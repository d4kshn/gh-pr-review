// secrev-review-pr › Check previous review
const ctx = $('Check PR').first().json;
const comments = $input.all().map((it) => it.json).filter((c) => c && typeof c.id === 'number');
const appSlug = $('Get GitHub token').first().json.app_slug;
const previous = GH.findOwnComment(comments, appSlug);
const decision = GH.decideReview(previous, ctx.input);
if (!decision.proceed) return [];
ctx.previous = previous;
ctx.reason = decision.reason;
return [{ json: ctx }];
