#!/usr/bin/env python3
"""End-to-end test: real n8n + mock GitHub/Azure OpenAI, driven by signed webhooks.

Requires an n8n install (N8N_BIN) and Node on PATH; everything else is local.

  NODE_BIN=~/.cache/gmn-secrev-dev/tools/node/bin \
  N8N_BIN=~/.cache/gmn-secrev-dev/n8n-runtime/node_modules/.bin/n8n \
  SECREV_E2E_WORK=~/.cache/gmn-secrev-dev/e2e python3 tests/e2e/run_e2e.py
"""
import hashlib
import hmac
import io
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import mock_services as mock  # noqa: E402

N8N_PORT, MOCK_PORT = 5688, 8765
OWNER, REPO, APP_ID, INSTALLATION = "dlr-gmn", "gmn-sample", 424242, 99
WEBHOOK_SECRET = "e2e-webhook-secret"
WORK = Path(os.environ.get("SECREV_E2E_WORK", HERE / ".work")).expanduser()
N8N_BIN = os.environ.get("N8N_BIN", "n8n")
FAKE_FRAGMENTS = ["R7xKq2Lm9TzW4vB8", "Z7Q3X5MBN2P4R6TQ", "rXUtnFEMI", "gmnRe4dOnly2026", "Sup3rS3cret", "Xq7Lm2Tz9Wv4", "9f8e7d6c5b4a3928"]

results = []


print = __import__("functools").partial(print, flush=True)  # noqa: A001 - live progress in logs


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("  PASS " if cond else "  FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""), flush=True)


def sh(*args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout


def wait_for(fn, timeout, what):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(1)
    print(f"  (timed out after {timeout}s waiting for {what})")
    return None


# --------------------------------------------------------------------------- setup
def prepare_repo():
    repo = WORK / "fixture-repo"
    sh("python3", str(ROOT / "tests/fixtures/make_fixture_repo.py"), str(repo))
    git = lambda *a: sh("git", *a, cwd=repo)
    env = {**os.environ, "GIT_AUTHOR_NAME": "e2e", "GIT_AUTHOR_EMAIL": "e2e@example.invalid",
           "GIT_COMMITTER_NAME": "e2e", "GIT_COMMITTER_EMAIL": "e2e@example.invalid"}
    git("checkout", "-q", "-b", "pr-fail", "pr-clean")
    (repo / "collector/util.py").write_text("def clamp(v, lo, hi):\n    return max(lo, min(hi, v))\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "Add clamp helper"], cwd=repo, check=True, env=env)
    git("checkout", "-q", "-b", "pr-docs", "main")
    (repo / "docs").mkdir(exist_ok=True)
    (repo / "docs/runbook.md").write_text("# Runbook\n\nRestart the collector with `systemctl restart monitoring-agent`.\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "Add runbook"], cwd=repo, check=True, env=env)
    git("checkout", "-q", "main")
    return repo, git


def setup_state(repo, git):
    state = mock.State(str(WORK / "app.pub.pem"), APP_ID, OWNER, REPO, blob_host=f"127.0.0.1:{MOCK_PORT}")
    base_sha = git("rev-parse", "main").strip()
    prs = {7: "pr-vuln", 8: "pr-clean", 10: "pr-fail", 11: "pr-docs"}
    for number, branch in prs.items():
        head = git("rev-parse", branch).strip()
        state.prs[number] = {
            "number": number, "state": "open", "draft": False, "title": f"{branch}: monitoring updates",
            "body": "Routine changes for the collectors.", "user": {"login": "dev1"},
            "html_url": f"https://github.com/{OWNER}/{REPO}/pull/{number}",
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "head": {"sha": head, "ref": branch}, "base": {"sha": base_sha, "ref": "main",
                     "repo": {"name": REPO, "full_name": f"{OWNER}/{REPO}", "owner": {"login": OWNER}}}}
        state.files[number] = json.loads(sh("python3", str(ROOT / "tests/fixtures/pr_files.py"), str(repo), "main", branch))
        for f in state.files[number]:
            if f["filename"].endswith(".json") and f["status"] != "removed":
                state.contents[(f["filename"], head)] = git("show", f"{branch}:{f['filename']}")
                if f["status"] != "added":
                    state.contents[(f["filename"], base_sha)] = git("show", f"main:{f['filename']}")
    # PR 7 has a completed scan with results; PR 10 and 11 have runs without artifacts.
    bundle = json.loads((ROOT / "tests/fixtures/scan-bundle-pr-vuln.json").read_text())
    bundle["meta"]["head_sha"] = state.prs[7]["head"]["sha"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("secrev.json", json.dumps(bundle))
    state.artifacts[1001] = buf.getvalue()
    for run_id, number in [(1001, 7), (1010, 10), (1011, 11)]:
        state.runs.append({"id": run_id, "path": ".github/workflows/secrev-scan.yml", "event": "pull_request",
                           "head_sha": state.prs[number]["head"]["sha"], "status": "completed", "conclusion": "success",
                           "updated_at": "2026-10-08T10:00:00Z"})
    state.azure_fail_prs.add(10)
    return state


def build(dry_run):
    cfg = json.loads((ROOT / "n8n/config.json").read_text())
    cfg.update({"github_api_url": f"http://localhost:{MOCK_PORT}", "github_app_id": str(APP_ID),
                "github_installation_id": str(INSTALLATION),
                "azure_chat_url": f"http://localhost:{MOCK_PORT}/openai/v1/chat/completions",
                "settle_seconds": 2, "dry_run": dry_run})
    (WORK / "config.json").write_text(json.dumps(cfg))
    out = WORK / "workflows"
    shutil.rmtree(out, ignore_errors=True)
    sh("python3", str(ROOT / "scripts/build.py"), "--workflows-only", "--config", str(WORK / "config.json"), "--out", str(out))
    for f in out.glob("*.json"):  # keep successful executions so failures are debuggable
        wf = json.loads(f.read_text())
        wf["settings"]["saveDataSuccessExecution"] = "all"
        if wf["id"] == "secrevSweeper001":  # test-only: trigger the sweeper by webhook instead of waiting 15 min
            trig = next(n for n in wf["nodes"] if n["name"] == "Every 15 minutes")
            trig.update({"type": "n8n-nodes-base.webhook", "typeVersion": 2.1, "webhookId": str(uuid.uuid4()),
                         "parameters": {"httpMethod": "POST", "path": "secrev-sweep-test", "responseMode": "onReceived", "options": {}}})
        f.write_text(json.dumps(wf))
    return out


def n8n_env():
    node_bin = os.environ.get("NODE_BIN", "")
    return {**os.environ, "PATH": f"{node_bin}:{os.environ['PATH']}" if node_bin else os.environ["PATH"],
            "N8N_USER_FOLDER": str(WORK / "n8n-home"), "N8N_ENCRYPTION_KEY": "e2e-encryption-key-0123456789abcdef",
            "N8N_PORT": str(N8N_PORT), "N8N_HOST": "localhost", "N8N_PROTOCOL": "http",
            "N8N_WEBHOOK_URL": f"http://localhost:{N8N_PORT}/", "N8N_DIAGNOSTICS_ENABLED": "false",
            "N8N_VERSION_NOTIFICATIONS_ENABLED": "false", "N8N_PERSONALIZATION_ENABLED": "false",
            "N8N_SECURE_COOKIE": "false", "N8N_RUNNERS_BROKER_PORT": "5689", "EXECUTIONS_DATA_PRUNE": "false",
            "N8N_LOG_LEVEL": "warn"}


def n8n(*args, env_extra=None, check_ok=True):
    env = {**n8n_env(), **(env_extra or {})}
    res = subprocess.run([N8N_BIN, *args], capture_output=True, text=True, env=env, timeout=600)
    if check_ok and res.returncode != 0:
        print(res.stdout[-3000:], res.stderr[-3000:])
        raise SystemExit(f"n8n {' '.join(args)} failed")
    return res


def import_all(workflows_dir):
    pem = (WORK / "app.key.pem").read_text()
    creds = [
        {"id": "secrevWebhookSec", "name": "secrev webhook secret", "type": "crypto", "data": {"hmacSecret": WEBHOOK_SECRET}},
        {"id": "secrevGhAppKey01", "name": "secrev GitHub App key", "type": "jwtAuth",
         "data": {"keyType": "pemKey", "privateKey": pem, "publicKey": "", "algorithm": "RS256"}},
        {"id": "secrevAzureAi001", "name": "secrev Azure OpenAI key", "type": "httpHeaderAuth",
         "data": {"name": "api-key", "value": mock.AZURE_KEY}},
    ]
    (WORK / "creds.json").write_text(json.dumps(creds))
    n8n("import:credentials", f"--input={WORK / 'creds.json'}")
    n8n("import:workflow", "--separate", f"--input={workflows_dir}")
    for wid in ["secrevGhToken001", "secrevReviewPr01", "secrevIntake0001", "secrevSweeper001"]:
        n8n("publish:workflow", f"--id={wid}")


def start_n8n():
    log = open(WORK / "n8n.log", "w")
    proc = subprocess.Popen([N8N_BIN, "start"], env=n8n_env(), stdout=log, stderr=subprocess.STDOUT, preexec_fn=os.setsid)

    def healthy():
        try:
            return urllib.request.urlopen(f"http://localhost:{N8N_PORT}/healthz", timeout=2).status == 200
        except Exception:
            return False
    if not wait_for(healthy, 180, "n8n to start"):
        raise SystemExit("n8n did not start; see " + str(WORK / "n8n.log"))

    # n8n 2.x activates published workflows after the editor is up. A GET to the POST-only
    # webhook answers "did you mean POST" once it is registered, without starting a run.
    def registered():
        try:
            urllib.request.urlopen(f"http://localhost:{N8N_PORT}/webhook/secrev-github", timeout=3)
        except urllib.error.HTTPError as e:
            return "POST" in e.read().decode(errors="replace")
        except Exception:
            return False
        return False
    if not wait_for(registered, 120, "webhook registration"):
        raise SystemExit("intake webhook never registered; see " + str(WORK / "n8n.log"))
    return proc


def stop_n8n(proc):
    os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(30)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)


def webhook(state, number, run_id, attempt=1, secret=WEBHOOK_SECRET, event="workflow_run"):
    payload = {"action": "completed", "workflow_run": {
        "id": run_id, "path": ".github/workflows/secrev-scan.yml", "head_sha": state.prs[number]["head"]["sha"],
        "event": "pull_request", "status": "completed", "conclusion": "success", "run_attempt": attempt,
        "pull_requests": [{"number": number}]},
        "repository": {"name": REPO, "full_name": f"{OWNER}/{REPO}", "owner": {"login": OWNER}},
        "installation": {"id": INSTALLATION}}
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(f"http://localhost:{N8N_PORT}/webhook/secrev-github", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "X-GitHub-Event": event,
                                          "X-Hub-Signature-256": sig, "X-GitHub-Delivery": str(uuid.uuid4())})
    return urllib.request.urlopen(req, timeout=10).status


def no_secrets(text):
    return [f for f in FAKE_FRAGMENTS if f in text]


def failed_executions():
    db = WORK / "n8n-home/.n8n/database.sqlite"
    with sqlite3.connect(db) as con:
        rows = con.execute("SELECT e.id, w.name, e.status FROM execution_entity e JOIN workflow_entity w ON w.id = e.workflowId "
                           "WHERE e.status IN ('error','crashed') ORDER BY e.id").fetchall()
    return rows


# --------------------------------------------------------------------------- scenarios
def scenario_dry_run(state):
    print("\n[dry run] review is stored in a Data Table, nothing posted to GitHub")
    check("webhook accepted", webhook(state, 7, 1001) == 200)
    db = WORK / "n8n-home/.n8n/database.sqlite"

    def rows():
        with sqlite3.connect(db) as con:
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'data_table_user_%'")]
            for t in tables:
                found = con.execute(f'SELECT repo, pr, risk, comment_md, input_tokens FROM "{t}"').fetchall()
                if found:
                    return found
        return None
    found = wait_for(rows, 120, "dry-run row")
    check("dry-run row written", found)
    if found:
        repo, pr, risk, body, tokens = found[0]
        check("row has repo, PR and risk", repo == f"{OWNER}/{REPO}" and pr == 7 and risk == "critical", f"{repo} {pr} {risk}")
        check("row stores rendered comment with token usage", body.startswith("<!-- secrev:v1") and tokens == 12345)
    check("no comment posted in dry run", not state.comments.get(7))
    check("no labels changed in dry run", not state.labels.get(7))


def scenario_live(state):
    print("\n[live] first review of PR 7 (scan results + model)")
    azure_before = len(state.azure_requests)
    req_before = len(state.requests)
    check("webhook accepted", webhook(state, 7, 1001) == 200)
    comment = wait_for(lambda: (state.comments.get(7) or [None])[0], 120, "PR 7 comment")
    check("comment posted", comment)
    if not comment:
        return
    body = comment["body"]
    marker = body.splitlines()[0]
    sha = state.prs[7]["head"]["sha"]
    check("marker records commit, scanners and model status", f"sha={sha}" in marker and "scanners=ok" in marker and "llm=ok" in marker, marker)
    check("risk badge is critical (secrets floor beats model's 'high')", "Security review · 🚨 Critical" in body)
    check("comment never contains secret values", not no_secrets(body), str(no_secrets(body)))
    check("model @mention is neutralized", "@security-team" not in body and "@​security-team" in body)
    check("model image/HTML is neutralized", "![x](" not in body and "<img" not in body)
    check("prompt-injection warning shown", "tries to instruct automated reviewers" in body)
    check("scanner table rendered", "| gitleaks | ✅ ran" in body and "| zizmor | ✅ ran" in body)
    check("dismissed findings listed", "Dismissed by the reviewer model" in body)
    check("env file not sent to model", "chatbot-ui/.env" in body and "environment file" in body)
    labels = wait_for(lambda: state.labels.get(7), 30, "labels")
    check("label secrev:critical applied", labels == ["secrev:critical"], str(labels))
    check("label created in repo", "secrev:critical" in state.repo_labels)

    req = state.azure_requests[azure_before] if len(state.azure_requests) > azure_before else None
    check("model called once", len(state.azure_requests) == azure_before + 1)
    if req:
        text = json.dumps(req)
        check("model request carries no secret values", not no_secrets(text), str(no_secrets(text)))
        check("strict JSON schema requested", req["response_format"]["json_schema"]["strict"] is True)
        check("deployment and reasoning effort set", req["model"] == "gpt-5.4" and req["reasoning_effort"] == "high")
        check("n8n workflow summarized for the model", "added node Lookup ticket" in req["messages"][1]["content"])

    token_reqs = [r for r in state.requests if r["path"].endswith("/access_tokens")]
    check("installation token scoped to the repo", token_reqs and token_reqs[-1]["body"].get("repositories") == [REPO])
    blob = [r for r in state.requests if r["path"].startswith("/blob/")]
    check("artifact downloaded via redirect", blob)
    check("GitHub token NOT forwarded to the artifact host", blob and all(r["auth"] is None for r in blob),
          str([r["auth"] for r in blob]))
    fetched = [r for r in state.requests[req_before:] if "/contents/" in r["path"]]
    check("n8n workflow JSON fetched at head and base", len(fetched) == 2, str(len(fetched)))

    print("\n[live] same event again is a no-op")
    calls = len(state.azure_requests)
    webhook(state, 7, 1001)
    time.sleep(20)
    check("no second model call for the same commit", len(state.azure_requests) == calls)
    check("still exactly one comment", len(state.comments[7]) == 1)

    print("\n[live] re-run of the scan check forces a fresh review that edits the same comment")
    first_body = state.comments[7][0]["body"]
    webhook(state, 7, 1001, attempt=2)
    wait_for(lambda: len(state.azure_requests) > calls, 120, "forced model call")
    wait_for(lambda: state.comments[7][0]["body"] != first_body, 60, "comment update")
    check("forced review called the model", len(state.azure_requests) == calls + 1)
    check("comment edited in place, not duplicated", len(state.comments[7]) == 1 and state.comments[7][0]["body"] != first_body)
    patch = [r for r in state.requests if r["method"] == "PATCH"]
    check("update used PATCH", patch)

    print("\n[live] forged webhook signature is rejected")
    calls = len(state.azure_requests)
    webhook(state, 7, 1001, attempt=3, secret="wrong-secret")
    time.sleep(10)
    check("forged event triggers nothing", len(state.azure_requests) == calls)
    fails = failed_executions()
    check("forged event visible as a failed intake execution", any(w == "secrev-intake" for _, w, _ in fails), str(fails))

    print("\n[live] model outage: review still posted with automated results and an error label")
    webhook(state, 10, 1010)
    comment = wait_for(lambda: (state.comments.get(10) or [None])[0], 180, "PR 10 comment")
    check("comment posted despite model failure", comment)
    if comment:
        check("comment explains the failure", "model review failed" in comment["body"] and "llm=error" in comment["body"])
        check("missing artifact reported", "could not be read" in comment["body"] or "were not available" in comment["body"])
    check("label secrev:error applied", wait_for(lambda: state.labels.get(10) == ["secrev:error"], 30, "error label"))

    print("\n[live] documentation-only PR skips the model")
    calls = len(state.azure_requests)
    webhook(state, 11, 1011)
    comment = wait_for(lambda: (state.comments.get(11) or [None])[0], 120, "PR 11 comment")
    check("docs PR commented", comment)
    if comment:
        check("docs PR marked clean without model call", "🟢 Clean" in comment["body"] and "llm=skipped" in comment["body"])
    check("no model call for docs PR", len(state.azure_requests) == calls)
    check("label secrev:clean applied", wait_for(lambda: state.labels.get(11) == ["secrev:clean"], 30, "clean label"))


def scenario_sweeper(state):
    print("\n[sweeper] catches an open PR that never got a review (no scan run, no webhook)")
    state.prs[8]["updated_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    urllib.request.urlopen(urllib.request.Request(f"http://localhost:{N8N_PORT}/webhook/secrev-sweep-test", data=b"{}",
                                                  method="POST", headers={"Content-Type": "application/json"}), timeout=10)
    comment = wait_for(lambda: (state.comments.get(8) or [None])[0], 120, "PR 8 comment")
    check("sweeper reviewed PR 8", comment)
    if comment:
        check("sweeper review notes missing scanner results", "scanners=missing" in comment["body"])
        check("clean PR rated clean or low", "🟢 Clean" in comment["body"] or "🟡 Low" in comment["body"] or "🔴 High" in comment["body"])
    others = [n for n in (7, 10, 11) if len(state.comments.get(n, [])) != 1]
    check("sweeper left already-reviewed PRs alone", not others, str(others))


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    sh("openssl", "genrsa", "-out", str(WORK / "app.key.pem"), "2048")
    sh("openssl", "rsa", "-in", str(WORK / "app.key.pem"), "-pubout", "-out", str(WORK / "app.pub.pem"))
    repo, git = prepare_repo()
    state = setup_state(repo, git)
    server = mock.serve(state, MOCK_PORT)
    proc = None
    try:
        import_all(build(dry_run=True))
        proc = start_n8n()
        scenario_dry_run(state)
        stop_n8n(proc)
        # Fresh n8n home: importing over an existing workflow can leave n8n running the
        # previously stored version of a sub-workflow (seen with 2.42.3).
        shutil.rmtree(WORK / "n8n-home")
        import_all(build(dry_run=False))
        proc = start_n8n()
        scenario_live(state)
        scenario_sweeper(state)
    finally:
        if proc:
            stop_n8n(proc)
        server.shutdown()
        (WORK / "mock-requests.json").write_text(json.dumps(state.requests, indent=1, default=str))
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("failed:", *failed, sep="\n  - ")
        print(f"logs: {WORK / 'n8n.log'}, {WORK / 'mock-requests.json'}")
        sys.exit(1)


if __name__ == "__main__":
    main()
