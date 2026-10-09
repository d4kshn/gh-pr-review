// End-to-end analysis on the planted-vulnerability fixture repo (no n8n, no network).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { CONFIG, FAKE, ROOT, fixtureRepo, loadLib } from './harness.mjs';

const L = loadLib();
const fx = fixtureRepo();
const bundle = JSON.parse(readFileSync(path.join(ROOT, 'tests/fixtures/scan-bundle-pr-vuln.json'), 'utf8'));

function ctxFor(branch, scan) {
  const files = fx.files(branch);
  const contents = {};
  for (const f of files) {
    if (!L.Classify.isWorkflowCandidate(f)) continue;
    contents[`${f.filename}@head`] = fx.show(branch, f.filename);
    if (f.status !== 'added') contents[`${f.filename}@base`] = fx.show('main', f.filename);
  }
  return {
    config: CONFIG,
    input: { owner: 'dlr-gmn', repo: 'gmn-sample', head_sha: fx.sha(branch), installation_id: 1 },
    pr: { number: 7, title: 'Monitoring updates', body: 'Routine changes.', user: 'dev1', base_ref: 'main', head_ref: branch,
      head_sha: fx.sha(branch), base_sha: fx.sha('main'), labels: [] },
    files, contents, scan,
  };
}

test('n8n workflow analysis flags the chatbot regressions', () => {
  const a = L.N8nWf.analyzeFile('n8n-workflows/chatbot.json', fx.show('pr-vuln', 'n8n-workflows/chatbot.json'), fx.show('main', 'n8n-workflows/chatbot.json'));
  const rules = a.workflows[0].findings.map((f) => f.rule);
  for (const want of ['n8n-trigger-auth-removed', 'n8n-hardcoded-credential', 'n8n-tls-verify-off', 'n8n-sql-injection',
    'n8n-code-exec', 'n8n-agent-risky-tool', 'n8n-pindata']) assert.ok(rules.includes(want), want);
  const authRemoved = a.workflows[0].findings.find((f) => f.rule === 'n8n-trigger-auth-removed');
  assert.equal(authRemoved.severity, 'high');
  assert.ok(authRemoved.floor);
  assert.ok(authRemoved.line > 1, 'points at the node in the JSON file');
  const text = L.N8nWf.describe('n8n-workflows/chatbot.json', a);
  assert.match(text, /added node Lookup ticket/);
  assert.match(text, /authentication = "none"/);
  assert.ok(!text.includes(FAKE.crmToken), 'parameter values are masked');
});

test('Analyze.run on the vulnerable PR: findings, masking and fencing', () => {
  const { analysis, llm } = L.Analyze.run(ctxFor('pr-vuln', { status: 'ok', run_id: 1, bundle }));
  const rules = new Set(analysis.automated.filter((a) => a.source !== 'rules' || true).map((a) => a.rule));
  for (const want of ['tf-open-ingress', 'tf-iam-wildcard-action', 'tf-tls-verify-off', 'ans-validate-certs-off',
    'ans-templated-shell', 'world-writable-mode', 'py-shell-true', 'py-sql-string', 'py-eval', 'py-tls-verify-off',
    'fe-raw-html', 'fe-public-secret-env', 'n8n-test-webhook-url', 'env-file-committed', 'ci-script-injection',
    'ci-checkout-pr-head', 'prompt-injection-text', 'secret:snmp-community', 'secret:ansible-plaintext-password',
    'n8n-trigger-auth-removed', 'n8n-sql-injection']) assert.ok(rules.has(want), want);
  const scannerTools = new Set(analysis.automated.filter((a) => a.id.startsWith('S')).map((a) => a.source));
  for (const t of ['gitleaks', 'checkov', 'bandit', 'semgrep', 'zizmor']) assert.ok(scannerTools.has(t), t);
  assert.ok(!analysis.automated.some((a) => a.source === 'ansible-lint' && a.rule === 'no-changed-when'), 'style rules filtered');
  assert.equal(llm.needed, true);
  const req = JSON.stringify(llm.request);
  for (const secret of Object.values(FAKE)) assert.ok(!req.includes(secret), 'no raw secret reaches the model');
  assert.ok(!req.includes('gmnRe4dOnly2026') && !req.includes('Sup3rS3cret!'));
  const user = llm.request.messages[1].content;
  assert.match(user, /snmp_community: "gmnR…\[15 chars\]"/, 'masking is stable when applied twice');
  const fence = /The data fence marker for this request is (SECREV_DATA_[A-Z0-9]+)/.exec(user)[1];
  assert.ok(user.includes(`<${fence}>`));
  assert.match(user, /\+\s+14 \|\s+return subprocess\.run\(f"ping -c1 \{host\}", shell=True/, 'diff lines carry head line numbers');
  assert.match(user, /chatbot-ui\/\.env: environment file/, 'env file is not sent');
  assert.equal(llm.request.response_format.json_schema.strict, true);
  assert.equal(llm.request.reasoning_effort, 'high', 'CI changes and floor findings raise the effort');
  assert.match(llm.request.messages[0].content, /### n8n workflows/);
});

test('Analyze.run on the clean PR stays quiet', () => {
  const { analysis, llm } = L.Analyze.run(ctxFor('pr-clean', { status: 'missing', run_id: null }));
  const notable = analysis.automated.filter((a) => L.Util.sevRank(a.severity) >= L.Util.sevRank('medium'));
  assert.deepEqual(notable.map((a) => a.rule), []);
  assert.equal(llm.needed, true);
  assert.equal(llm.request.reasoning_effort, 'medium');
});

test('Finalize path: model output plus automated findings render a safe comment', () => {
  const ctx = ctxFor('pr-vuln', { status: 'ok', run_id: 1, bundle });
  const { analysis } = L.Analyze.run(ctx);
  const raw = {
    summary: 'Opens SSH to the world, widens IAM and @security-team should look. ![x](https://evil.example/a.png)',
    risk: 'low', risk_reason: 'Several high-risk changes.',
    look_first: [{ file: 'terraform/network/main.tf', line: 18, why: 'SSH from 0.0.0.0/0' }],
    findings: [{ severity: 'high', category: 'auth', file: 'n8n-workflows/chatbot.json', line: null, title: 'Chat webhook is now public',
      evidence: 'authentication: none', why_it_matters: 'Anyone can spend LLM tokens.', fix: 'Restore header auth.', confidence: 'high', related_ids: [] }],
    automated_findings_triage: [], injection_suspected: true,
  };
  const review = L.Review.validate(raw, analysis.files);
  const final = L.Review.combine(analysis, { ok: true, review });
  assert.equal(final.risk, 'critical', 'committed secrets keep the floor at critical');
  const body = L.Render.comment(final, {
    marker: { sha: ctx.input.head_sha, scanners: 'ok', llm: 'ok', run: 1, at: '2026-10-08T10:00:00Z' },
    llmStatus: 'ok', scanStatus: 'ok', partial: false, scanTools: analysis.scanTools, sensitiveFiles: analysis.sensitiveFiles,
    omitted: analysis.diff.omitted, usage: { input_tokens: 12000, output_tokens: 3000 }, model: 'gpt-5.4',
    headSha: ctx.input.head_sha, reviewedAt: '2026-10-08T10:00:00Z', maxRows: 12,
  });
  assert.ok(body.startsWith('<!-- secrev:v1 sha=' + ctx.input.head_sha));
  assert.ok(body.length < 60000);
  for (const secret of Object.values(FAKE)) assert.ok(!body.includes(secret));
  assert.ok(!body.includes('gmnRe4dOnly2026') && !body.includes('Sup3rS3cret!'));
  assert.ok(!/(^|[\s(])@security-team/.test(body), 'mentions are neutralized');
  assert.ok(!body.includes('![x]'), 'images are neutralized');
  assert.match(body, /tries to instruct automated reviewers/);
  assert.match(body, /\| gitleaks \| ✅ ran/);
  assert.equal((body.match(/<!-- secrev:v1/g) || []).length, 1, 'exactly one marker');
});
