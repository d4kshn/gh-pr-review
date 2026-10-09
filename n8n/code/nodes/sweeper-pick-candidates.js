// secrev-sweeper › Pick candidates
// Open PRs quiet for at least sweeper_after_minutes (normal reviews arrive well before
// that) and active within sweeper_max_age_hours (so enabling secrev does not review
// every old PR at once).
const cfg = $('Config').first().json.config;
const now = Date.now();
const out = [];
for (const it of $input.all()) {
  const pr = it.json || {};
  if (typeof pr.number !== 'number' || pr.state !== 'open' || !pr.head || !pr.base) continue;
  if (pr.draft && cfg.skip_drafts) continue;
  const age = now - Date.parse(pr.updated_at);
  if (age < cfg.sweeper_after_minutes * 60000 || age > cfg.sweeper_max_age_hours * 3600000) continue;
  out.push({ owner: pr.base.repo.owner.login, repo: pr.base.repo.name, pr_number: pr.number, head_sha: pr.head.sha });
}
return out.map((c) => ({ json: c }));
