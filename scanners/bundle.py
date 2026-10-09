#!/usr/bin/env python3
"""Combine scanner SARIF output into one slim JSON bundle for n8n.

Usage: bundle.py OUT_DIR CHANGED_FILES_LIST > secrev.json

The bundle drops SARIF snippets and author details on purpose: snippets can contain
secrets, and n8n only needs rule, location, severity and a short message. n8n still
treats the bundle as untrusted, because a PR author can edit the caller workflow.
"""
import json
import os
import re
import sys
import time
from pathlib import Path

TOOLS = ["gitleaks", "checkov", "ansible-lint", "bandit", "semgrep", "zizmor"]
MAX_RESULTS_PER_TOOL = 300
MAX_MESSAGE = 400
VERSION_KEYS = ["GITLEAKS_VERSION", "CHECKOV_VERSION", "SEMGREP_VERSION", "BANDIT_VERSION",
                "ANSIBLE_LINT_VERSION", "ZIZMOR_VERSION"]


# Some tools quote the offending value in their message (bandit B105-B107 do).
QUOTED_SECRET = re.compile(r"(?i)(hardcoded (?:password|secret|token)[^:]*:\s*)(['\"]).*?\2")


def redact(text):
    return QUOTED_SECRET.sub(lambda m: m.group(1) + m.group(2) + "<redacted>" + m.group(2), text)


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def normalize_path(uri, prefix=""):
    path = (uri or "").strip()
    if path.startswith("file://"):
        path = path[len("file://"):]
    for root in filter(None, [os.environ.get("GITHUB_WORKSPACE"), os.getcwd()]):
        root = root.rstrip("/") + "/"
        if path.startswith(root):
            path = path[len(root):]
    while path.startswith("./"):
        path = path[2:]
    path = path.lstrip("/")
    if prefix and prefix != "." and not path.startswith(prefix.rstrip("/") + "/"):
        path = prefix.rstrip("/") + "/" + path
    return path


def severity_from_score(score):
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value >= 9:
        return "critical"
    if value >= 7:
        return "high"
    if value >= 4:
        return "medium"
    return "low" if value > 0 else None


def lower_or_none(value):
    return value.lower() if isinstance(value, str) and value else None


def slim_results(sarif, prefix=""):
    """Flatten SARIF runs into a list of small result dicts."""
    out = []
    if not isinstance(sarif, dict):
        return out
    for run in sarif.get("runs") or []:
        rules = {}
        driver = ((run.get("tool") or {}).get("driver") or {})
        for rule in driver.get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules[rule["id"]] = rule
        for res in run.get("results") or []:
            if not isinstance(res, dict):
                continue
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id") or "unknown"
            rule = rules.get(rule_id, {})
            props = res.get("properties") or {}
            rule_props = rule.get("properties") or {}
            level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
            loc = ((res.get("locations") or [{}])[0] or {}).get("physicalLocation") or {}
            region = loc.get("region") or {}
            message = ((res.get("message") or {}).get("text") or
                       (rule.get("shortDescription") or {}).get("text") or "")
            severity = (lower_or_none(props.get("issue_severity")) or
                        severity_from_score(props.get("security-severity")) or
                        severity_from_score(rule_props.get("security-severity")))
            fingerprints = res.get("partialFingerprints") or {}
            out.append({
                "rule_id": str(rule_id)[:200],
                "rule_name": str((rule.get("shortDescription") or {}).get("text") or rule.get("name") or "")[:200],
                "level": str(level)[:20],
                "message": redact(str(message))[:MAX_MESSAGE],
                "file": normalize_path((loc.get("artifactLocation") or {}).get("uri"), prefix),
                "start_line": region.get("startLine"),
                "end_line": region.get("endLine") or region.get("startLine"),
                "severity": severity,
                "confidence": lower_or_none(props.get("issue_confidence")) or lower_or_none(rule_props.get("precision")),
                "help_uri": str(rule.get("helpUri") or "")[:300],
                "commit": str(fingerprints.get("commitSha") or "")[:40] or None,
            })
    return out


def load_tool(out_dir, name):
    status = read_json(out_dir / f"{name}.status.json") or {"status": "skipped", "reason": "not run"}
    results = []
    if name == "checkov":
        dirs = {}
        dirs_file = out_dir / "checkov-dirs.txt"
        if dirs_file.exists():
            for line in dirs_file.read_text(encoding="utf-8").splitlines():
                idx, _, directory = line.partition("\t")
                dirs[idx] = directory
        for sarif_path in sorted(out_dir.glob("checkov-*.sarif")):
            idx = sarif_path.stem.split("-", 1)[1]
            results += slim_results(read_json(sarif_path), dirs.get(idx, ""))
    else:
        sarif_path = out_dir / f"{name}.sarif"
        if sarif_path.exists():
            sarif = read_json(sarif_path)
            if sarif is None and status.get("status") == "ran":
                status = {**status, "status": "error", "error": "invalid SARIF output"}
            results = slim_results(sarif)
    stderr = out_dir / f"{name}.stderr.txt"
    if status.get("status") in ("error", "timeout") and stderr.exists():
        status["error"] = (status.get("error") or "") + stderr.read_text(encoding="utf-8", errors="replace")[-600:]
    status["total"] = len(results)
    status["truncated"] = len(results) > MAX_RESULTS_PER_TOOL
    status["results"] = results[:MAX_RESULTS_PER_TOOL]
    return status


def main():
    out_dir = Path(sys.argv[1])
    changed = Path(sys.argv[2]).read_text(encoding="utf-8").splitlines() if len(sys.argv) > 2 else []
    bundle = {
        "schema": "secrev-scan/v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "meta": {
            "repo": os.environ.get("SECREV_REPO", ""),
            "pr_number": os.environ.get("SECREV_PR", ""),
            "base_sha": os.environ.get("BASE_SHA", ""),
            "head_sha": os.environ.get("HEAD_SHA", ""),
            "run_id": os.environ.get("SECREV_RUN_ID", ""),
            "run_attempt": os.environ.get("SECREV_RUN_ATTEMPT", ""),
            "domains": os.environ.get("SECREV_DOMAINS", "").split(),
            "changed_files": len([c for c in changed if c.strip()]),
            "versions": {k.lower(): os.environ.get(k, "") for k in VERSION_KEYS},
        },
        "tools": {name: load_tool(out_dir, name) for name in TOOLS},
    }
    json.dump(bundle, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    main()
