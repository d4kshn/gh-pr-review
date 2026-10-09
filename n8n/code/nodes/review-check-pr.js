// secrev-review-pr › Check PR
// Stops quietly when the PR is closed, still a draft, or has newer commits (their own
// scan run will trigger a fresh review).
const ctx = $('Config').first().json;
const items = $input.all().map((it) => it.json);
const prs = items.filter((p) => p && typeof p.number === 'number' && p.head);
if (!prs.length) {
  const err = items.find((x) => x && x.error);
  if (err) throw new Error('secrev: could not look up the PR for this commit: ' + JSON.stringify(err.error).slice(0, 200));
  return [];
}
const want = ctx.input.pr_number;
const pr = (want && prs.find((p) => p.number === want)) || prs.find((p) => p.head.sha === ctx.input.head_sha) || prs[0];
if (pr.state !== 'open' || pr.head.sha !== ctx.input.head_sha) return [];
if (pr.draft && ctx.config.skip_drafts && !ctx.input.force) return [];
ctx.pr = {
  number: pr.number, title: pr.title || '', body: pr.body || '', user: (pr.user || {}).login || 'unknown',
  draft: !!pr.draft, head_sha: pr.head.sha, base_sha: (pr.base || {}).sha, head_ref: pr.head.ref,
  base_ref: (pr.base || {}).ref, html_url: pr.html_url, labels: (pr.labels || []).map((l) => l.name),
};
return [{ json: ctx }];
