// secrev-review-pr › Config
// Settings live here because n8n 2.x blocks $env in Code nodes. scripts/build.py fills
// them from n8n/config.json; you can also edit this object directly in n8n.
const CONFIG = __CONFIG__;
const input = $input.first().json || {};
const num = (v) => (v === null || v === undefined || v === '' ? null : Number(v));
const i = {
  owner: String(input.owner || ''), repo: String(input.repo || ''),
  installation_id: num(input.installation_id), head_sha: String(input.head_sha || '').toLowerCase(),
  run_id: num(input.run_id), run_attempt: num(input.run_attempt) || 1, pr_number: num(input.pr_number),
  force: input.force === true || input.force === 'true', source: String(input.source || 'manual'),
};
if (!/^[A-Za-z0-9_.-]+$/.test(i.owner) || !/^[A-Za-z0-9_.-]+$/.test(i.repo)) throw new Error('secrev: owner/repo input is missing or invalid');
if (!/^[0-9a-f]{40}$/.test(i.head_sha)) throw new Error('secrev: head_sha must be a 40-character commit SHA');
if (!i.installation_id) throw new Error('secrev: installation_id is required');
return [{
  json: {
    kind: 'secrev-ctx', config: CONFIG, input: i, started_at: new Date().toISOString(),
    // Read by secrev-github-token: a token limited to this repo and these permissions.
    installation_id: i.installation_id, repositories: [i.repo],
    permissions: { pull_requests: 'write', contents: 'read', actions: 'read', metadata: 'read' },
  },
}];
