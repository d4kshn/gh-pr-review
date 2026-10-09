"""Mock GitHub REST API + Azure OpenAI used by the end-to-end test.

Implements just the endpoints secrev calls, enforces auth the way GitHub does
(App JWT for access tokens, installation token elsewhere, no auth on artifact
blobs), and records every request so the test can assert on behaviour.
"""
import base64
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

INSTALL_TOKEN = "ghs_" + "e2eInstallationToken0000000000000000"
AZURE_KEY = "e2e-azure-key"


class State:
    def __init__(self, public_key_path, app_id, owner, repo, blob_host):
        self.public_key_path = public_key_path
        self.app_id = app_id
        self.owner, self.repo = owner, repo
        self.blob_host = blob_host
        self.prs = {}            # number -> PR object (labels kept separately)
        self.files = {}          # number -> list of file dicts
        self.contents = {}       # (path, ref) -> text
        self.runs = []           # workflow runs
        self.artifacts = {}      # run_id -> zip bytes
        self.comments = {}       # number -> list
        self.labels = {}         # number -> list of names
        self.repo_labels = set()
        self.requests = []
        self.azure_requests = []
        self.azure_fail_prs = set()
        self.next_id = 5000
        self.lock = threading.Lock()

    def new_id(self):
        with self.lock:
            self.next_id += 1
            return self.next_id

    def pr_view(self, number):
        pr = json.loads(json.dumps(self.prs[number]))
        pr["labels"] = [{"name": n} for n in self.labels.get(number, [])]
        return pr


def verify_jwt(state, token):
    try:
        head_b64, payload_b64, sig_b64 = token.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)
        header = json.loads(base64.urlsafe_b64decode(pad(head_b64)))
        payload = json.loads(base64.urlsafe_b64decode(pad(payload_b64)))
        sig = base64.urlsafe_b64decode(pad(sig_b64))
    except Exception:
        return False, "malformed JWT"
    if header.get("alg") != "RS256":
        return False, f"alg {header.get('alg')}"
    signed = f"{head_b64}.{payload_b64}".encode()
    with tempfile.TemporaryDirectory() as d:
        sp, dp = os.path.join(d, "sig"), os.path.join(d, "data")
        open(sp, "wb").write(sig)
        open(dp, "wb").write(signed)
        res = subprocess.run(["openssl", "dgst", "-sha256", "-verify", state.public_key_path, "-signature", sp, dp],
                             capture_output=True, text=True)
    if "Verified OK" not in res.stdout:
        return False, "bad signature"
    now = int(time.time())
    if str(payload.get("iss")) != str(state.app_id):
        return False, "wrong iss"
    if not (payload.get("iat", now + 999) <= now and now < payload.get("exp", 0) <= now + 600):
        return False, "bad iat/exp"
    return True, payload


def fake_review(user_message):
    """A schema-valid answer: confirm most automated findings, dismiss one, add one."""
    ids = re.findall(r"^- \[([RS]\d+)\] (\S+) (\S+)", user_message, re.M)
    triage = []
    for fid, source, rule in ids:
        if rule in ("CKV2_AWS_5", "zizmor/artipacked", "risky-shell-pipe"):
            triage.append({"id": fid, "verdict": "false_positive", "reason": "not relevant for this change"})
        else:
            triage.append({"id": fid, "verdict": "confirmed", "reason": "introduced by this PR"})
    files = re.findall(r"^- (\S+) \[", user_message, re.M)
    finding_file = next((f for f in files if f.endswith("chatbot.json")), files[0] if files else "README.md")
    return {
        "summary": "Opens SSH from anywhere, widens IAM and removes chatbot webhook auth; ping @security-team "
                   "![x](https://evil.example/pixel.png) <img src=x onerror=alert(1)>",
        "risk": "high",
        "risk_reason": "Several changes expose management access and credentials.",
        "look_first": [{"file": finding_file, "line": None, "why": "Webhook now unauthenticated"}],
        "findings": [{
            "severity": "high", "category": "n8n-workflow", "file": finding_file, "line": None,
            "title": "Chatbot workflow callable by anyone", "evidence": "authentication: none",
            "why_it_matters": "Anyone can drive the agent and its tools.", "fix": "Restore header auth.",
            "confidence": "high", "related_ids": [],
        }],
        "automated_findings_triage": triage,
        "injection_suspected": True,
    }


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def _send(self, code, body=None, headers=None, raw=None, ctype="application/json"):
            data = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            try:
                return json.loads(raw) if raw else {}
            except ValueError:
                return {"_raw": raw.decode(errors="replace")}

        def _record(self, body):
            url = urlsplit(self.path)
            state.requests.append({"method": self.command, "path": url.path, "query": parse_qs(url.query),
                                   "auth": self.headers.get("Authorization"), "accept": self.headers.get("Accept"),
                                   "api_key": self.headers.get("api-key"), "host": self.headers.get("Host"), "body": body})
            return url

        def do_GET(self):
            self._route()

        def do_POST(self):
            self._route()

        def do_PATCH(self):
            self._route()

        def do_DELETE(self):
            self._route()

        def _route(self):
            body = self._body() if self.command in ("POST", "PATCH", "DELETE") else None
            url = self._record(body)
            p, q = url.path, parse_qs(url.query)
            base = f"/repos/{state.owner}/{state.repo}"

            # ---- Azure OpenAI
            if p == "/openai/v1/chat/completions":
                if self.headers.get("api-key") != AZURE_KEY:
                    return self._send(401, {"error": {"message": "bad api key"}})
                state.azure_requests.append(body)
                user = body["messages"][1]["content"]
                m = re.search(r"number: #(\d+)", user)
                if m and int(m.group(1)) in state.azure_fail_prs:
                    return self._send(500, {"error": {"message": "simulated outage"}})
                review = fake_review(user)
                return self._send(200, {"id": "chatcmpl-e2e", "model": body.get("model"), "choices": [{
                    "index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(review)}}],
                    "usage": {"prompt_tokens": 12345, "completion_tokens": 2345,
                              "prompt_tokens_details": {"cached_tokens": 4000},
                              "completion_tokens_details": {"reasoning_tokens": 1500}}})

            # ---- artifact blob (different host, must not receive the GitHub token)
            if p.startswith("/blob/"):
                run_id = int(p.rsplit("/", 1)[1].split(".")[0])
                return self._send(200, raw=state.artifacts[run_id], ctype="application/zip")

            # ---- GitHub: token exchange uses the App JWT
            m = re.fullmatch(r"/app/installations/(\d+)/access_tokens", p)
            if m:
                auth = self.headers.get("Authorization") or ""
                ok, info = verify_jwt(state, auth.removeprefix("Bearer "))
                if not ok:
                    return self._send(401, {"message": f"JWT rejected: {info}"})
                return self._send(201, {"token": INSTALL_TOKEN, "expires_at": "2099-01-01T00:00:00Z",
                                        "permissions": body.get("permissions"), "repositories": body.get("repositories")})

            if self.headers.get("Authorization") != f"Bearer {INSTALL_TOKEN}":
                return self._send(401, {"message": "Bad credentials"})

            if p == "/rate_limit":
                return self._send(200, {"resources": {}})
            if p == "/installation/repositories":
                return self._send(200, {"total_count": 1, "repositories": [{
                    "name": state.repo, "full_name": f"{state.owner}/{state.repo}", "owner": {"login": state.owner},
                    "archived": False, "disabled": False}]})
            if p == f"{base}/pulls" and self.command == "GET":
                return self._send(200, [state.pr_view(n) for n in state.prs if state.prs[n]["state"] == "open"])
            m = re.fullmatch(rf"{base}/commits/([0-9a-f]{{40}})/pulls", p)
            if m:
                return self._send(200, [state.pr_view(n) for n, pr in state.prs.items() if pr["head"]["sha"] == m.group(1)])
            m = re.fullmatch(rf"{base}/pulls/(\d+)/files", p)
            if m:
                page = int(q.get("page", ["1"])[0])
                per = int(q.get("per_page", ["30"])[0])
                files = state.files.get(int(m.group(1)), [])
                return self._send(200, files[(page - 1) * per: page * per])
            m = re.fullmatch(rf"{base}/issues/(\d+)/comments", p)
            if m:
                n = int(m.group(1))
                if self.command == "GET":
                    page = int(q.get("page", ["1"])[0])
                    return self._send(200, state.comments.get(n, [])[(page - 1) * 100: page * 100])
                c = {"id": state.new_id(), "body": body["body"], "user": {"login": "gmn-secrev[bot]", "type": "Bot"},
                     "performed_via_github_app": {"slug": "gmn-secrev"}, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "issue_url": f"http://{self.headers.get('Host')}{base}/issues/{n}"}
                state.comments.setdefault(n, []).append(c)
                return self._send(201, c)
            m = re.fullmatch(rf"{base}/issues/comments/(\d+)", p)
            if m:
                cid = int(m.group(1))
                for n, lst in state.comments.items():
                    for c in lst:
                        if c["id"] == cid:
                            if self.command == "PATCH":
                                c["body"] = body["body"]
                                return self._send(200, c)
                            if self.command == "DELETE":
                                lst.remove(c)
                                return self._send(204)
                return self._send(404, {"message": "Not Found"})
            if p == f"{base}/labels" and self.command == "POST":
                if body["name"] in state.repo_labels:
                    return self._send(422, {"message": "Validation Failed", "errors": [{"code": "already_exists"}]})
                state.repo_labels.add(body["name"])
                return self._send(201, {"name": body["name"]})
            m = re.fullmatch(rf"{base}/issues/(\d+)/labels(?:/(.+))?", p)
            if m:
                n = int(m.group(1))
                current = state.labels.setdefault(n, [])
                if self.command == "POST":
                    for name in body["labels"]:
                        if name not in state.repo_labels:
                            return self._send(422, {"message": f"label {name} missing"})
                        if name not in current:
                            current.append(name)
                    return self._send(200, [{"name": x} for x in current])
                if self.command == "DELETE":
                    name = unquote(m.group(2))
                    if name in current:
                        current.remove(name)
                        return self._send(200, [{"name": x} for x in current])
                    return self._send(404, {"message": "Label does not exist"})
            if p == f"{base}/actions/runs":
                runs = [r for r in state.runs if r["head_sha"] == q.get("head_sha", [""])[0]]
                return self._send(200, {"total_count": len(runs), "workflow_runs": runs})
            m = re.fullmatch(rf"{base}/actions/runs/(\d+)/artifacts", p)
            if m:
                rid = int(m.group(1))
                arts = [{"id": rid * 10, "name": "secrev-scan", "expired": False,
                         "archive_download_url": f"http://{self.headers.get('Host')}{base}/actions/artifacts/{rid * 10}/zip"}] \
                    if rid in state.artifacts else []
                return self._send(200, {"total_count": len(arts), "artifacts": arts})
            m = re.fullmatch(rf"{base}/actions/artifacts/(\d+)/zip", p)
            if m:
                rid = int(m.group(1)) // 10
                return self._send(302, headers={"Location": f"http://{state.blob_host}/blob/{rid}.zip?sig=e2e"})
            m = re.fullmatch(rf"{base}/contents/(.+)", p)
            if m:
                key = (m.group(1), q.get("ref", [""])[0])
                if key in state.contents and "raw" in (self.headers.get("Accept") or ""):
                    return self._send(200, raw=state.contents[key].encode(), ctype="application/vnd.github.raw+json")
                return self._send(404, {"message": "Not Found"})
            return self._send(404, {"message": f"mock: no route for {self.command} {p}"})

    return Handler


class DualStackServer(ThreadingHTTPServer):
    # Node resolves "localhost" to ::1 first; listen on IPv6 and IPv4 alike.
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def serve(state, port):
    server = DualStackServer(("::", port), make_handler(state))
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server
