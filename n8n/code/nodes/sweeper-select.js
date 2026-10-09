// secrev-sweeper › Select PRs to review
const cfg = $('Config').first().json.config;
const installationId = $('Config').first().json.installation_id;
const appSlug = $('Get GitHub token').first().json.app_slug;
const byPr = {};
for (const it of $input.all()) {
  const c = it.json || {};
  const m = /\/repos\/([^/]+)\/([^/]+)\/issues\/(\d+)$/.exec(String(c.issue_url || ''));
  if (m) (byPr[`${m[1]}/${m[2]}#${m[3]}`] ||= []).push(c);
}
const picks = [];
for (const cand of $('Pick candidates').all().map((it) => it.json)) {
  const own = GH.findOwnComment(byPr[`${cand.owner}/${cand.repo}#${cand.pr_number}`] || [], appSlug);
  if (own && own.marker && own.marker.sha === cand.head_sha) continue;
  picks.push({ ...cand, installation_id: installationId, run_id: null, run_attempt: 1, force: false, source: 'sweeper' });
  if (picks.length >= cfg.sweeper_max_reviews) break;
}
return picks.map((p) => ({ json: p }));
