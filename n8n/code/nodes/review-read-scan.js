// secrev-review-pr › Read scan results
const ctx = $('Pick scan run').first().json;
const item = $input.first();
const keys = Object.keys(item.binary || {});
let bundle = null;
let error = null;
if (!keys.length) {
  error = 'the secrev-scan artifact was missing or could not be downloaded';
} else {
  const key = keys.find((k) => /secrev\.json$/.test(item.binary[k].fileName || '')) || keys[0];
  try {
    const buf = await this.helpers.getBinaryDataBuffer(0, key);
    if (buf.length > 5000000) throw new Error('bundle larger than 5 MB');
    bundle = JSON.parse(buf.toString('utf8'));
    const v = Sarif.validateBundle(bundle);
    if (!v.ok) { error = v.error; bundle = null; }
  } catch (e) {
    error = 'could not read the scan bundle: ' + e.message;
    bundle = null;
  }
}
if (bundle && bundle.meta && bundle.meta.head_sha && bundle.meta.head_sha !== ctx.input.head_sha) {
  error = 'the scan bundle belongs to a different commit';
  bundle = null;
}
ctx.scan = bundle ? { status: 'ok', run_id: ctx.scan.run_id, bundle } : { status: 'error', run_id: ctx.scan.run_id, error };
return [{ json: ctx }];
