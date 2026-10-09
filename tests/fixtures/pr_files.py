#!/usr/bin/env python3
"""Emit GitHub "list pull request files" JSON for a git range, like the REST API does.

Usage: pr_files.py REPO_DIR BASE HEAD > files.json
"""
import json
import subprocess
import sys

STATUS = {"A": "added", "M": "modified", "D": "removed", "R": "renamed", "C": "copied", "T": "changed"}


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout


def main():
    repo, base, head = sys.argv[1:4]
    merge_base = git(repo, "merge-base", base, head).strip()
    numstat = {}
    for line in git(repo, "diff", "--numstat", "-M", merge_base, head).splitlines():
        adds, dels, path = line.split("\t", 2)
        numstat[path.split(" => ")[-1].rstrip("}")] = (adds, dels)
    files = []
    for line in git(repo, "diff", "--name-status", "-M", merge_base, head).splitlines():
        parts = line.split("\t")
        code = parts[0][0]
        path = parts[-1]
        entry = {"filename": path, "status": STATUS.get(code, "modified")}
        if code in "RC":
            entry["previous_filename"] = parts[1]
        adds, dels = numstat.get(path, ("-", "-"))
        binary = adds == "-"
        entry["additions"] = 0 if binary else int(adds)
        entry["deletions"] = 0 if binary else int(dels)
        entry["changes"] = entry["additions"] + entry["deletions"]
        if not binary:
            paths = [parts[1], path] if code in "RC" else [path]
            diff = git(repo, "diff", "-M", "--unified=3", merge_base, head, "--", *paths)
            hunk_start = diff.find("\n@@")
            if hunk_start >= 0:
                entry["patch"] = diff[hunk_start + 1:].rstrip("\n")
        files.append(entry)
    json.dump(files, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
