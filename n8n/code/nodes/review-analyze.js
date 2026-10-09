// secrev-review-pr › Analyze
const ctx = $('Checkpoint').first().json;
const plan = $('Plan file fetches').all().map((it) => it.json);
// Contents arrive as binary so line numbers match the file exactly (text mode would
// parse JSON and re-serialize it onto one line).
ctx.contents = {};
const items = $input.all();
for (let idx = 0; idx < items.length; idx++) {
  const p = plan[idx];
  if (!p || !p.key || !items[idx].binary || !items[idx].binary.data) continue;
  try {
    const buf = await this.helpers.getBinaryDataBuffer(idx, 'data');
    if (buf.length <= 2000000) ctx.contents[p.key] = buf.toString('utf8');
  } catch (e) {
    // unreadable file: analysed from the diff alone
  }
}
const { analysis, llm } = Analyze.run(ctx);
delete ctx.contents;
delete ctx.files;
if (ctx.scan) delete ctx.scan.bundle;
ctx.analysis = analysis;
ctx.llm = llm;
return [{ json: ctx }];
