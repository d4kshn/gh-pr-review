// secrev-review-pr › Finalize
const ctx = $('Analyze').first().json;
const resp = $input.first().json || {};
let llm;
if (!ctx.llm.needed) {
  llm = { ok: false };
} else {
  const parsed = Review.parseLlmResponse(resp.choices || resp.error ? resp : { error: 'the model step did not run' });
  llm = parsed.ok
    ? { ok: true, review: Review.validate(parsed.raw, ctx.analysis.files), usage: parsed.usage, model: parsed.model }
    : { ok: false, error: parsed.error, usage: parsed.usage || null };
}
const final = Review.combine(ctx.analysis, llm);
const llmStatus = !ctx.llm.needed ? 'skipped' : (llm.ok ? 'ok' : 'error');
const reviewedAt = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
const body = Render.comment(final, {
  marker: { sha: ctx.input.head_sha, scanners: ctx.scan.status, llm: llmStatus, run: ctx.scan.run_id || 'none', at: reviewedAt },
  llmStatus, llmError: llm.error, llmSkipReason: ctx.llm.skip_reason,
  scanStatus: ctx.scan.status, scanError: ctx.scan.error,
  partial: ctx.analysis.diff.partial, scanTools: ctx.analysis.scanTools,
  sensitiveFiles: ctx.analysis.sensitiveFiles, omitted: ctx.analysis.diff.omitted,
  usage: llm.usage, model: llm.ok ? (llm.model || ctx.config.azure_deployment) : null,
  headSha: ctx.input.head_sha, reviewedAt, maxRows: ctx.config.max_rows_in_table,
});
ctx.final = {
  risk: final.risk, level: llmStatus === 'error' ? 'error' : final.risk, body, llmStatus,
  scanStatus: ctx.scan.status, findings: final.rows.length, minor: final.minor.length, dismissed: final.dismissed.length,
  injection_suspected: final.injection_suspected, usage: llm.usage || null,
  duration_s: Math.round((Date.now() - Date.parse(ctx.started_at)) / 1000),
};
delete ctx.analysis;
delete ctx.llm;
return [{ json: ctx }];
