// secrev-sweeper › Expand repos
const cfg = $('Config').first().json.config;
const repos = [];
for (const it of $input.all()) {
  for (const r of ((it.json || {}).repositories || [])) {
    if (r.archived || r.disabled) continue;
    if (cfg.allowed_repos.length && !cfg.allowed_repos.includes(r.full_name)) continue;
    repos.push({ owner: r.owner.login, repo: r.name });
  }
}
return repos.map((r) => ({ json: r }));
