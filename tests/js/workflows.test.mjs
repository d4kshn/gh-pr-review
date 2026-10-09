// Structural checks on the generated n8n workflows and the model schema.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { ROOT } from './harness.mjs';

const dir = path.join(ROOT, 'n8n/workflows');
const workflows = readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => JSON.parse(readFileSync(path.join(dir, f), 'utf8')));
const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;

test('all four workflows are present with stable ids', () => {
  assert.deepEqual(workflows.map((w) => w.id).sort(), ['secrevGhToken001', 'secrevIntake0001', 'secrevReviewPr01', 'secrevSweeper001']);
});

for (const wf of workflows) {
  test(`${wf.name}: connections point at real nodes and every node is reachable`, () => {
    const names = new Set(wf.nodes.map((n) => n.name));
    assert.equal(names.size, wf.nodes.length, 'node names are unique');
    const reached = new Set();
    for (const [from, outs] of Object.entries(wf.connections)) {
      assert.ok(names.has(from), from);
      for (const conn of outs.main.flat()) { assert.ok(names.has(conn.node), conn.node); reached.add(conn.node); }
    }
    const triggers = wf.nodes.filter((n) => /trigger|webhook/i.test(n.type)).map((n) => n.name);
    for (const n of names) if (!triggers.includes(n)) assert.ok(reached.has(n), `${n} is connected`);
  });

  test(`${wf.name}: Code nodes compile and keep secrets out`, () => {
    for (const node of wf.nodes.filter((n) => n.type === 'n8n-nodes-base.code')) {
      assert.doesNotThrow(() => new AsyncFunction('$input', '$', node.parameters.jsCode), node.name);
      assert.ok(!/__CONFIG__/.test(node.parameters.jsCode), `${node.name}: config placeholder replaced`);
    }
    const text = JSON.stringify(wf);
    assert.ok(!/gh[pousr]_[A-Za-z0-9]{36}|sk-proj-[A-Za-z0-9]{20}/.test(text), 'no tokens embedded');
  });
}

test('review workflow does not save successful executions (diffs can hold secrets)', () => {
  for (const wf of workflows) assert.equal(wf.settings.saveDataSuccessExecution, 'none', wf.name);
});

test('credentials are only referenced, never inlined', () => {
  const creds = workflows.flatMap((w) => w.nodes.filter((n) => n.credentials).map((n) => Object.keys(n.credentials)[0]));
  assert.deepEqual(creds.sort(), ['crypto', 'httpHeaderAuth', 'jwtAuth']);
});

test('review schema is valid for strict structured outputs', () => {
  const schema = JSON.parse(readFileSync(path.join(ROOT, 'prompts/review.schema.json'), 'utf8'));
  const walk = (s, where) => {
    if (s.type === 'object') {
      assert.equal(s.additionalProperties, false, `${where}: additionalProperties false`);
      assert.deepEqual([...s.required].sort(), Object.keys(s.properties).sort(), `${where}: every property required`);
      for (const [k, v] of Object.entries(s.properties)) walk(v, `${where}.${k}`);
    }
    if (s.type === 'array') walk(s.items, `${where}[]`);
  };
  walk(schema, 'root');
});
