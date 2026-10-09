// secrev-intake › Route event
// Verifies the GitHub signature, then keeps only completed secrev-scan runs for PRs.
// The payload is used for IDs only; secrev-review-pr re-fetches everything from the API.
const CONFIG = __CONFIG__;
const item = $input.first().json || {};
const headers = item.headers || {};
const expected = 'sha256=' + String(item.secrev_signature || '');
if (!Util.timingSafeEqual(String(headers['x-hub-signature-256'] || ''), expected)) {
  throw new Error('secrev: webhook signature mismatch. Check that the "secrev webhook secret" credential matches the GitHub App webhook secret.');
}
const body = item.body || {};
if (headers['x-github-event'] !== 'workflow_run' || body.action !== 'completed') return [];
const run = body.workflow_run || {};
if (String(run.path || '').split('@')[0] !== CONFIG.caller_workflow_path) return [];
if (run.event !== 'pull_request' || ['cancelled', 'skipped', 'stale'].includes(run.conclusion)) return [];
const repo = body.repository || {};
if (CONFIG.allowed_repos.length && !CONFIG.allowed_repos.includes(repo.full_name)) return [];
return [{
  json: {
    owner: (repo.owner || {}).login, repo: repo.name, installation_id: (body.installation || {}).id,
    head_sha: run.head_sha, run_id: run.id, run_attempt: run.run_attempt || 1,
    pr_number: ((run.pull_requests || [])[0] || {}).number || null,
    force: (run.run_attempt || 1) > 1, source: 'webhook', delivery_id: headers['x-github-delivery'] || null,
  },
}];
