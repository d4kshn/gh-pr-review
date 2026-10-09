// secrev-review-pr › Collect files
const ctx = $('Check previous review').first().json;
const items = $input.all().map((it) => it.json);
const files = items.filter((f) => f && typeof f.filename === 'string').map((f) => ({
  filename: f.filename, status: f.status, additions: f.additions || 0, deletions: f.deletions || 0,
  patch: typeof f.patch === 'string' ? f.patch : null, previous_filename: f.previous_filename || null,
}));
if (!files.length && items.some((x) => x && x.error)) throw new Error('secrev: could not list the PR files');
ctx.files = files;
return [{ json: ctx }];
