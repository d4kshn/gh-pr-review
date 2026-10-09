// secrev-review-pr › No scan results
const ctx = $input.first().json;
ctx.scan = { status: 'missing', run_id: null };
return [{ json: ctx }];
