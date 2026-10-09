// secrev-review-pr › Pick scan run
// Uses the run from the webhook when it belongs to this commit and the secrev caller
// workflow; otherwise the latest completed one (sweeper and forced reviews).
const ctx = $('Collect files').first().json;
const runs = ($input.first().json || {}).workflow_runs || [];
const ours = runs.filter((r) => String(r.path || '').split('@')[0] === ctx.config.caller_workflow_path &&
  r.head_sha === ctx.input.head_sha && r.event === 'pull_request');
let run = ctx.input.run_id ? ours.find((r) => r.id === ctx.input.run_id) : null;
if (!run) {
  run = ours.filter((r) => r.status === 'completed' && !['cancelled', 'skipped'].includes(r.conclusion))
    .sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)))[0];
}
ctx.scan = run ? { status: 'pending', run_id: run.id } : { status: 'missing', run_id: null };
return [{ json: ctx }];
