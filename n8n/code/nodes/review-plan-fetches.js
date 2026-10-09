// secrev-review-pr › Plan file fetches
// Fetches head and base versions of JSON files that may be n8n workflows. When there is
// nothing to fetch, one request to /rate_limit (which costs no API quota) keeps the
// flow linear.
const ctx = $('Checkpoint').first().json;
const api = ctx.config.github_api_url;
const { owner, repo } = ctx.input;
const enc = (p) => p.split('/').map(encodeURIComponent).join('/');
const fetches = [];
for (const f of ctx.files) {
  if (!Classify.isWorkflowCandidate(f)) continue;
  if (fetches.length >= 2 * ctx.config.max_workflow_files) break;
  fetches.push({ key: `${f.filename}@head`, url: `${api}/repos/${owner}/${repo}/contents/${enc(f.filename)}?ref=${ctx.pr.head_sha}` });
  if (f.status !== 'added') {
    // Base branch tip, not the merge base: close enough for a node-level comparison.
    const basePath = f.previous_filename || f.filename;
    fetches.push({ key: `${basePath}@base`, url: `${api}/repos/${owner}/${repo}/contents/${enc(basePath)}?ref=${ctx.pr.base_sha}` });
  }
}
if (!fetches.length) fetches.push({ key: null, url: `${api}/rate_limit` });
return fetches.map((f) => ({ json: f }));
