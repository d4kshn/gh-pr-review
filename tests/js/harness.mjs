// Loads the Code-node library the same way scripts/build.py inlines it: concatenated
// into one function scope, with SECREV_ASSETS defined.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ORDER = ['util', 'diff', 'classify', 'secrets', 'rules', 'n8nwf', 'sarif', 'prompt', 'analyze', 'review', 'github', 'render'];

export function loadAssets() {
  const dir = path.join(ROOT, 'prompts/checklists');
  const checklists = Object.fromEntries(readdirSync(dir).filter((f) => f.endsWith('.md'))
    .map((f) => [f.replace(/\.md$/, ''), readFileSync(path.join(dir, f), 'utf8').trim()]));
  return {
    system: readFileSync(path.join(ROOT, 'prompts/system.md'), 'utf8').trim(),
    checklists,
    schema: JSON.parse(readFileSync(path.join(ROOT, 'prompts/review.schema.json'), 'utf8')),
  };
}

export function loadLib() {
  const src = ORDER.map((n) => readFileSync(path.join(ROOT, 'n8n/code/lib', `${n}.js`), 'utf8')).join('\n\n');
  // eslint-disable-next-line no-new-func
  const fn = new Function('SECREV_ASSETS', `${src}\nreturn { Util, Diff, Classify, Secrets, Rules, N8nWf, Sarif, Prompt, Analyze, Review, GH, Render };`);
  return fn(loadAssets());
}

// Builds the planted-vulnerability repo once per test process.
let fixture = null;
export function fixtureRepo() {
  if (fixture) return fixture;
  const dir = path.join(mkdtempSync(path.join(tmpdir(), 'secrev-fixture-')), 'repo');
  execFileSync('python3', [path.join(ROOT, 'tests/fixtures/make_fixture_repo.py'), dir]);
  const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' });
  const files = (head) => JSON.parse(execFileSync('python3', [path.join(ROOT, 'tests/fixtures/pr_files.py'), dir, 'main', head], { encoding: 'utf8' }));
  fixture = { dir, git, files, sha: (ref) => git('rev-parse', ref).trim(), show: (ref, p) => git('show', `${ref}:${p}`) };
  return fixture;
}

export const CONFIG = JSON.parse(readFileSync(path.join(ROOT, 'n8n/config.json'), 'utf8'));

// Fake secrets assembled at runtime so this file contains none.
export const FAKE = {
  githubToken: 'gh' + 'p_' + 'R7xKq2Lm9TzW4vB8nC1dF6hJ3sY5aE0gU2iO',
  awsKeyId: 'AK' + 'IA' + 'Z7Q3X5MBN2P4R6TQ',
  openaiKey: 'sk-' + 'proj-' + 'Xq7Lm2Tz9Wv4Bn8Cd1Fh6Js3Ya5Ee0Gu',
  crmToken: 'crm_' + 'live_' + '9f8e7d6c5b4a39281706f5e4d3c2b1a0',
};
