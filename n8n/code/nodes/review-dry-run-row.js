// secrev-review-pr › Dry-run row
const ctx = $('Finalize').first().json;
const u = ctx.final.usage || {};
return [{
  json: {
    repo: `${ctx.input.owner}/${ctx.input.repo}`, pr: ctx.pr.number, sha: ctx.input.head_sha.slice(0, 12),
    risk: ctx.final.risk, level: ctx.final.level, llm: ctx.final.llmStatus, scanners: ctx.final.scanStatus,
    findings: ctx.final.findings, input_tokens: u.input_tokens || 0, output_tokens: u.output_tokens || 0,
    duration_s: ctx.final.duration_s, pr_url: ctx.pr.html_url, comment_md: ctx.final.body,
    reviewed_at: new Date().toISOString(),
  },
}];
