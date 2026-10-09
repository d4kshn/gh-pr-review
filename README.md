# gmn-secrev: advisory security review for GMN pull requests

secrev posts one security comment and one `secrev:*` risk label on each pull request in the Global Monitoring Network repos (Ansible, Terraform, Python, the chatbot frontend and its n8n workflows). It **never blocks merging**. It only gives reviewers an overview: what the PR does, how risky it is, and where to look first.

```
PR pushed ─► GitHub Actions "secrev-scan" (gitleaks · checkov · ansible-lint · bandit · semgrep · zizmor)
              │ always green, uploads a SARIF bundle
              ▼
        GitHub App webhook (workflow_run) ─► n8n secrev-intake ─► secrev-review-pr
                                                                 │ rules + n8n workflow checks + scan results
                                                                 │ + Azure OpenAI gpt-5.4 (strict JSON)
                                                                 ▼
                                                   sticky PR comment + secrev:<level> label
        n8n secrev-sweeper (every 15 min) catches PRs that slipped through
```

| Read | For |
|---|---|
| [PLAN.md](PLAN.md) | Design and decisions |
| [docs/SETUP.md](docs/SETUP.md) | Installing it: GitHub App, credentials, import, enrolling repos |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Operating it: labels, forcing reviews, troubleshooting, tuning |

## Repository layout

```
.github/workflows/scan.yml      GENERATED reusable scanner workflow (callers pin it by SHA)
templates/secrev-scan.yml       caller to copy into each enrolled repo
scanners/                       scanner runner, SARIF bundler, pinned versions, central configs
n8n/config.json                 settings baked into the workflows at build time
n8n/code/lib/                   Code-node library (rules, secrets, n8n workflow diff, prompt, rendering)
n8n/code/nodes/                 entry snippet for each Code node
n8n/workflows/                  GENERATED importable n8n workflows
prompts/                        system prompt, per-domain checklists, strict output schema
scripts/build.py                builds the two GENERATED outputs above
tests/js/                       unit and fixture tests (node --test)
tests/fixtures/                 planted-vulnerability repo generator, captured scan bundle
tests/e2e/                      real n8n + mock GitHub/Azure end-to-end test
```

## Development

Requires Python 3.10+ and Node 22+ (the end-to-end test needs Node 24 and n8n 2.42.x).

```bash
python3 scripts/build.py              # regenerate scan.yml and n8n/workflows/*.json
python3 scripts/build.py --check      # CI: fail when generated files are stale
node --test tests/js/*.test.mjs       # unit + fixture tests (builds a throwaway git repo)
```

Scanner check: run the scanners against the fixture repo. They must be on `PATH`; versions are in `scanners/versions.env`.

```bash
python3 tests/fixtures/make_fixture_repo.py /tmp/fx && cd /tmp/fx && git checkout -q pr-vuln
BASE_SHA=$(git rev-parse main) HEAD_SHA=$(git rev-parse pr-vuln) OUT_DIR=/tmp/fx-out \
  bash /path/to/gmn-secrev/scanners/run-scanners.sh
```

End-to-end test: imports the workflows into a real n8n, then drives it with signed webhooks against mock GitHub and Azure OpenAI endpoints.

```bash
NODE_BIN=/path/to/node/bin N8N_BIN=/path/to/n8n SECREV_E2E_WORK=/tmp/secrev-e2e \
  python3 tests/e2e/run_e2e.py
```

The test fixtures build fake credentials at runtime from fragments, so this repository doesn't trip secret scanners or GitHub push protection. Keep it that way when adding fixtures.
