// secrev-review-pr › Plan follow-up requests
// Label bookkeeping (only when the level changes) and cleanup of duplicate comments.
const ctx = $('Finalize').first().json;
const posted = $input.first().json || {};
if (posted.error || !posted.id) throw new Error('secrev: could not post the PR comment: ' + JSON.stringify(posted.error || posted).slice(0, 200));
const api = ctx.config.github_api_url;
const base = `${api}/repos/${ctx.input.owner}/${ctx.input.repo}`;
const n = ctx.pr.number;
const plan = GH.labelPlan(ctx.pr.labels, ctx.final.level, ctx.config.label_prefix);
const reqs = [];
if (plan.add) {
  const meta = GH.LABELS[ctx.final.level];
  reqs.push({ method: 'POST', url: `${base}/labels`, body: { name: plan.add, color: meta.color, description: meta.description } });
  reqs.push({ method: 'POST', url: `${base}/issues/${n}/labels`, body: { labels: [plan.add] } });
}
for (const name of plan.remove) reqs.push({ method: 'DELETE', url: `${base}/issues/${n}/labels/${encodeURIComponent(name)}`, body: {} });
for (const id of ((ctx.previous || {}).duplicates || [])) reqs.push({ method: 'DELETE', url: `${base}/issues/comments/${id}`, body: {} });
return reqs.map((r) => ({ json: r }));
