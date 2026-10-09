# secrev setup

Roughly an hour, most of it waiting on approvals. You need:

- someone who can create GitHub Apps in the org (org owner or app manager)
- n8n 2.42.x access that can create credentials and import/publish workflows
- an Azure OpenAI resource with a `gpt-5.4` deployment
- Python 3 (to run `scripts/build.py`)

## 1. Central repository

1. Create `<org>/gmn-secrev` (private or internal) and push this project to it.
2. **Settings → Actions → General → Access**: choose *Accessible from repositories in the organization*, so other repos can call `scan.yml`.
3. Note the commit SHA of the version you want callers to pin.

## 2. GitHub App

**Org settings → Developer settings → GitHub Apps → New GitHub App**

| Field | Value |
|---|---|
| Name | `gmn-secrev`. The app slug must match `github_app_slug` in `n8n/config.json`. |
| Homepage URL | URL of the central repo |
| Webhook | Active. URL `https://<n8n-host>/webhook/secrev-github`. Secret: `openssl rand -hex 32` (keep it for step 5). |
| Repository permissions | Actions: **Read**. Contents: **Read**. Metadata: **Read**. Pull requests: **Read and write**. |
| Subscribe to events | **Workflow run** only |
| Installable on | Only this account |

After creating the app:

1. Note the **App ID** shown on the General page.
2. Generate a **private key**. A `.pem` file downloads; treat it like a password.
3. **Install App → Only select repositories**, then pick the repos. The installation URL ends in `/installations/<id>`; note that **installation ID**.

The App never needs Issues, Checks or administration permissions, and it has no access to code beyond reading it.

## 3. Azure OpenAI

- Deploy `gpt-5.4`. Use a Standard (regional) or Data Zone deployment if data residency matters, rather than Global.
- Endpoint for `azure_chat_url`:
  - v1 API (preferred): `https://<resource>.openai.azure.com/openai/v1/chat/completions`. The deployment name goes in `azure_deployment`.
  - Older API: `https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=<version>`
- Copy **Key 1** from *Keys and Endpoint* for step 5.
- Quota: a review uses up to ~50k tokens including reasoning. Any normal tokens-per-minute quota is fine at ~10 PRs/day.

## 4. Configure and build

Edit `n8n/config.json`:

| Key | Set to |
|---|---|
| `github_app_id`, `github_app_slug`, `github_installation_id` | From step 2 |
| `azure_chat_url`, `azure_deployment` | From step 3 |
| `dry_run` | Leave `true` for the first week (see step 8) |
| `allowed_repos` | Optional extra allowlist, for example `["<org>/ansible-monitoring"]`. Empty means every repo the App is installed on. |

Then rebuild:

```bash
python3 scripts/build.py
```

Settings are baked into each workflow's first Code node (the `CONFIG` block at the top), because n8n 2.x blocks `$env` in Code nodes. You can also edit them there after import. Remember that `github_api_url` and `caller_workflow_path` appear in more than one workflow.

## 5. n8n credentials

Create these under **Credentials → Add credential**. Restrict sharing to the people who maintain secrev.

| Name | Type | Fields |
|---|---|---|
| `secrev webhook secret` | Crypto | **Hmac Secret** = webhook secret from step 2 |
| `secrev GitHub App key` | JWT Auth | Key Type **PEM Key**. Private Key = contents of the `.pem`. Algorithm **RS256**. |
| `secrev Azure OpenAI key` | Header Auth | Name `api-key`. Value = Azure key. |

## 6. Import and publish the workflows

**With the n8n CLI (recommended).** This keeps the workflow IDs, so the sub-workflow links work as-is:

```bash
n8n import:workflow --separate --input=n8n/workflows/
```

**With the UI.** Create each workflow and use *Import from File*. Then re-link the Execute Workflow nodes, because UI imports get new IDs:

- `secrev-intake` › **Start review** → `secrev-review-pr`
- `secrev-review-pr` › **Get GitHub token** → `secrev-github-token`
- `secrev-sweeper` › **Get GitHub token** → `secrev-github-token`
- `secrev-sweeper` › **Run review** → `secrev-review-pr`

With either method, open these nodes and select the credentials from step 5:

- `secrev-intake` › **Compute signature**
- `secrev-github-token` › **Sign app JWT**
- `secrev-review-pr` › **Ask Azure OpenAI**

Publish in this order: `secrev-github-token`, `secrev-review-pr`, `secrev-intake`, `secrev-sweeper`. Production webhooks and sub-workflow calls only work once a workflow is published.

These settings are already in the JSON. Keep them:

- **Save successful production executions: Do not save.** Diffs can contain secrets, so only failures are stored.
- **This workflow can be called by:** workflows from the same owner.

## 7. Enroll a repository

1. Copy `templates/secrev-scan.yml` to `.github/workflows/secrev-scan.yml` in the repo.
2. Replace `<org>` and `<commit-sha>`, and keep the filename: n8n only reacts to that path.
3. Open the change as a normal PR. That PR gets the first review.
4. Make sure the repo is selected in the App installation.

Optional: add a `CODEOWNERS` entry for `.github/workflows/` so changes to the scan caller need a second pair of eyes.

## 8. Dry run, then go live

With `dry_run: true`, nothing is posted to GitHub. Each review is stored as a row in the n8n Data table **`secrev_dry_run`** (n8n → *Data tables*), with the rendered comment, risk level and token usage.

1. Run for a week on one or two repos.
2. Read the `comment_md` column and look for noise.
3. Tune `llm_exclude_paths`, the prompt (`prompts/`) or the rules (`n8n/code/lib/rules.js`) as needed.
4. Set `dry_run` to `false`, rebuild, re-import `secrev-review-pr` and publish it.

## 9. Check that it works

- **GitHub App → Advanced → Recent deliveries:** `workflow_run` deliveries return **200**.
- **n8n Executions:** a failed `secrev-intake` execution saying *webhook signature mismatch* means the webhook secret differs between GitHub and the n8n credential.
- **A test PR:** the scan check passes, and the secrev comment and label appear a couple of minutes later. In dry run, a new row appears in the data table instead.
