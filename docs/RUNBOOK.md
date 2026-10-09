# secrev runbook

## How a review happens

1. A PR is opened, pushed to, reopened or marked ready. The repo's `secrev-scan` check runs the scanners. It always passes and uploads a `secrev-scan` artifact. A newer push cancels a running scan, so bursts of pushes collapse into one review.
2. When the scan finishes, GitHub sends a `workflow_run` event to `secrev-intake`.
3. `secrev-intake` checks the HMAC signature, keeps only completed `secrev-scan` runs, waits `settle_seconds`, then starts `secrev-review-pr`.
4. `secrev-review-pr` mints a token scoped to that one repo and re-reads the PR from the API (the webhook only provides IDs). It then:
   - skips the run if the PR is closed, a draft, has newer commits, or this commit was already reviewed
   - collects the diff, the scan bundle and the full JSON of any changed n8n workflows
   - runs the deterministic rules and asks gpt-5.4 for a review
   - edits its single comment and adjusts the `secrev:*` label
5. `secrev-sweeper` runs every 15 minutes. It reviews open PRs that have gone more than `sweeper_after_minutes` without a review: a missed webhook, a scan that never ran, or Actions minutes running out.

## Everyday use

| Want to… | Do this |
|---|---|
| See risky open PRs across repos | GitHub search `is:pr is:open org:<org> label:"secrev:critical","secrev:high"` (bookmark it) |
| Re-review a PR without pushing | Re-run the `secrev-scan` check. A re-run (`run_attempt > 1`) forces a fresh review. |
| Understand a rating | The comment's **Details and suggested fixes** and **Automated checks and coverage** sections show every source, including findings the model dismissed and files it did not see |
| Rate the review | 👍/👎 reactions on the comment. Read them when tuning. |

### Labels

| Label | Meaning |
|---|---|
| `secrev:critical` / `secrev:high` / `secrev:medium` / `secrev:low` | Highest severity shown in the comment |
| `secrev:clean` | Nothing security-relevant found, or a docs-only change |
| `secrev:error` | The model review failed. Automated results are still in the comment. Re-run the scan check to retry. |

### How the risk level is decided

- Deterministic rules and scanners run regardless of the model.
- Precise checks are marked **floor**: committed secrets, removed webhook auth, workflow script injection, and similar. The model cannot dismiss these, and their severity is the minimum risk.
- The model can dismiss other automated findings (shown under *Dismissed by the reviewer model*) and add its own findings.
- The badge and label show the highest remaining severity, and never less than the model's overall verdict.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| No comment, and GitHub's *Recent deliveries* show errors | n8n is unreachable, or `secrev-intake` isn't published. Check the URL `https://<n8n>/webhook/secrev-github`. After an n8n restart, production webhooks only register once n8n has finished indexing workflows (about 15 s after the editor is up in testing), so deliveries in that window get a 404. Use *Redeliver* in GitHub. |
| Failed `secrev-intake` executions: *signature mismatch* | The webhook secret in GitHub differs from the `secrev webhook secret` credential. If deliveries come from unknown sources, it may be noise or probing; consider the Webhook node's IP allowlist (GitHub `hooks` ranges from `api.github.com/meta`). |
| Failed `secrev-github-token` executions: *401 JWT* | Wrong App ID, wrong or expired private key, or the n8n server clock is off by more than about a minute |
| Comment says *scanner results were not available* | The repo has no `secrev-scan.yml` caller (or a different filename), Actions is disabled, or minutes ran out. The review still covers rules and model output. |
| Comment says *could not be read* | The artifact expired (3-day retention) or the scan job failed before uploading. Re-run the check. |
| `secrev:error` label | The Azure call failed: quota (429), timeout, content filter, or the answer was cut off. The comment shows the reason. Raise `max_completion_tokens` if the answer was cut off. |
| Comments duplicated | Two reviews raced for the same PR. The next review deletes the duplicates automatically. |
| Reviews feel slow | Expected: scan time + `settle_seconds` (90) + model time, roughly 3–6 minutes after the last push. |

To see what n8n received, find the failed execution under **Executions**. Successful runs are not stored, by design. To debug a specific PR, temporarily set the review workflow's *Save successful production executions* to *Save*, and set it back afterwards.

## Tuning noise

- **Paths the model should never see:** add globs to `llm_exclude_paths` (for example `"inventories/**"`). Rules and scanners still check them.
- **A rule that is too noisy:** edit or remove it in `n8n/code/lib/rules.js`, then run `node --test tests/js/*.test.mjs` and `python3 scripts/build.py`.
- **A scanner rule that is too noisy:**
  - checkov: severity mapping in `n8n/code/lib/sarif.js` (`CHECKOV_HIGH`, `CHECKOV_MEDIUM_HINT`)
  - ansible-lint: `ANSIBLE_LINT_SECURITY` in the same file
  - Low-severity scanner hits only appear under *Lower-severity notes*
- **Prompt:** edit `prompts/system.md` or the checklists in `prompts/checklists/`. Check the result on the fixture PRs before rolling out.
- **Cost:** lower `reasoning_effort` (and `reasoning_effort_sensitive`), or `diff_token_budget`. Each comment footer shows the tokens used, and the dry-run table records them per review.

## Changing things safely

| Change | Steps |
|---|---|
| Scanner versions | Edit `scanners/versions.env`. For gitleaks, also update the SHA-256 from the release's `checksums.txt`. Run `python3 scripts/build.py`, push, and move callers to the new commit SHA. |
| Actions used by `scan.yml` | Update the pinned SHAs in `scanners/scan.template.yml`, then rebuild |
| Settings | Edit the `CONFIG` block in the workflow's first Code node in the n8n editor, then publish. If you change `n8n/config.json` and rebuild instead, delete the old workflow in n8n before importing the new JSON. In testing, n8n 2.42.3 kept running the previous version of a sub-workflow after a CLI import over an existing workflow, even after publishing. After any change, check one execution to confirm the new settings took effect. |
| Code-node logic | Edit `n8n/code/`, run the tests, rebuild, re-import, publish. Keep the repo as the source of truth, so the n8n copy doesn't drift. |

`python3 scripts/build.py --check` fails if the generated files are out of date, which makes it a good CI step for this repo.

## Rotating secrets

| Secret | Steps |
|---|---|
| Webhook secret | Generate a new one, update the GitHub App webhook and the `secrev webhook secret` credential together. Deliveries fail in between. |
| App private key | Generate a new key in the App settings, update the `secrev GitHub App key` credential, then delete the old key in GitHub |
| Azure key | Switch the credential to Key 2, regenerate Key 1, switch back if you prefer |

## Turning it off

- **Pause everything:** unpublish `secrev-intake` and `secrev-sweeper`. The scan check keeps running harmlessly.
- **One repo:** remove it from the App installation, or delete its `secrev-scan.yml`.
- **Remove completely:** uninstall the App, delete the caller files, and delete the `secrev:*` labels if you want them gone.

## Known limits

- **The scan runs the PR's own caller workflow.** For PRs from branches in the same repo, the PR author can change what scans run. The rules and the model don't depend on the scan, and changes to secrev files are flagged, but treat scan results as advisory.
- **n8n workflow comparison uses the base branch tip, not the merge base,** so unrelated changes merged to the base branch in the meantime can show up as node differences.
- **Prompt injection.** The model sees PR text and the diff, which an attacker can write. It has no tools and its output only becomes text in a comment, so the worst case is a misleading review. That is why the floor rules exist.
