// n8n workflow JSON analysis: node-level diff between base and head, plus checks for
// the risks that matter in chatbot workflows (open webhooks, pasted keys, SQL built
// from user input, agent tools with too much power, committed pinData).
const N8nWf = (() => {
  const T = {
    webhook: 'n8n-nodes-base.webhook',
    formTrigger: 'n8n-nodes-base.formTrigger',
    chatTrigger: '@n8n/n8n-nodes-langchain.chatTrigger',
    executeCommand: 'n8n-nodes-base.executeCommand',
    ssh: 'n8n-nodes-base.ssh',
  };
  const HTTP_TYPES = /^(n8n-nodes-base\.httpRequest(Tool)?|@n8n\/n8n-nodes-langchain\.toolHttpRequest)$/;
  const CODE_TYPES = /^(n8n-nodes-base\.(code|function|functionItem)(Tool)?|@n8n\/n8n-nodes-langchain\.(toolCode|code))$/;
  const DB_TYPES = /^n8n-nodes-base\.(postgres|mySql|microsoftSql|oracleDb|snowflake|crateDb|questDb|timescaleDb|mongoDb)(Tool)?$/;
  const AGENT_TYPES = /^@n8n\/n8n-nodes-langchain\.(agent|agentTool)$/;
  const RISKY_TOOL_TYPES = /(toolCode|toolHttpRequest|toolWorkflow|httpRequestTool|executeCommand|sshTool|(postgres|mySql|microsoftSql|oracleDb|snowflake|mongoDb|redis)Tool|codeTool)$/i;
  const AUTH_HEADER_NAMES = /^(authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|token|cookie|x-functions-key|ocp-apim-subscription-key)$/i;

  function parseWorkflows(text) {
    let obj;
    try { obj = JSON.parse(text); } catch (e) { return { workflows: [], error: 'invalid JSON' }; }
    const list = Array.isArray(obj) ? obj : [obj];
    const workflows = list.filter(Classify.looksLikeWorkflow);
    return { workflows, error: null };
  }

  const isExpression = (v) => typeof v === 'string' && (v.startsWith('=') || v.includes('{{'));

  function nodeKey(node) { return node.id || node.name; }

  // Flattened "path=value" view of node parameters, for change detection and summaries.
  function flatten(obj, prefix = '', out = {}) {
    if (obj === null || typeof obj !== 'object') { out[prefix] = obj; return out; }
    if (Array.isArray(obj)) { obj.forEach((v, i) => flatten(v, `${prefix}[${i}]`, out)); return out; }
    for (const [k, v] of Object.entries(obj)) flatten(v, prefix ? `${prefix}.${k}` : k, out);
    return out;
  }

  function changedParams(baseNode, headNode) {
    const a = flatten({ parameters: baseNode.parameters || {}, credentials: baseNode.credentials || {}, disabled: !!baseNode.disabled });
    const b = flatten({ parameters: headNode.parameters || {}, credentials: headNode.credentials || {}, disabled: !!headNode.disabled });
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    return [...keys].filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k])).sort();
  }

  // Which nodes are connected to an agent as tools: { toolName: agentName }.
  function agentTools(wf) {
    const tools = {};
    for (const [from, outputs] of Object.entries(wf.connections || {})) {
      for (const conn of (outputs.ai_tool || []).flat()) {
        if (conn && conn.node) tools[from] = conn.node;
      }
    }
    return tools;
  }

  function lineOf(text, node) {
    if (!text) return null;
    const needles = [node.id && `"id": "${node.id}"`, node.id && `"id":"${node.id}"`, `"name": "${node.name}"`, `"name":"${node.name}"`].filter(Boolean);
    for (const needle of needles) {
      const idx = text.indexOf(needle);
      if (idx >= 0) return text.slice(0, idx).split('\n').length;
    }
    return null;
  }

  function webhookAuth(node) {
    const p = node.parameters || {};
    if (node.type === T.chatTrigger) return p.public ? (p.authentication || 'none') : 'n8n-user';
    return p.authentication || 'none';
  }

  // Checks for one head node. `base` is the matching base node or null (new node).
  function checkNode(node, base, ctx) {
    const p = node.parameters || {};
    const out = [];
    const add = (rule, severity, category, title, why, fix, extra = {}) =>
      out.push({ rule, severity, category, title, why, fix, node: node.name, ...extra });
    const isNew = !base;
    const changed = !isNew && changedParams(base, node).length > 0;
    if (!isNew && !changed) return out; // pre-existing and untouched

    if ([T.webhook, T.formTrigger, T.chatTrigger].includes(node.type) && !node.disabled) {
      const auth = webhookAuth(node);
      const baseAuth = base ? webhookAuth(base) : null;
      if (auth === 'none') {
        if (baseAuth && baseAuth !== 'none') {
          add('n8n-trigger-auth-removed', 'high', 'auth', `Authentication removed from "${node.name}"`,
            `The ${node.type.split('.').pop()} was protected (${baseAuth}) and is now open to anyone who knows the URL.`,
            'Restore authentication (header auth, JWT or basic) or put the endpoint behind the gateway.', { floor: true });
        } else if (isNew) {
          add('n8n-trigger-no-auth', node.type === T.formTrigger ? 'low' : 'medium', 'auth', `"${node.name}" accepts unauthenticated requests`,
            'Anyone who finds the URL can trigger the workflow and spend its credentials (LLM tokens, APIs).',
            'Enable authentication on the trigger, or validate a shared secret before doing work.');
        }
      }
      const origins = (p.options || {}).allowedOrigins;
      if (origins === '*' && (isNew || (base && ((base.parameters || {}).options || {}).allowedOrigins !== '*'))) {
        add('n8n-cors-any', 'low', 'misconfiguration', `"${node.name}" allows any browser origin`,
          'Any website can call this endpoint from a visitor\'s browser.', 'Set allowedOrigins to the chatbot\'s own origin.');
      }
    }

    if (HTTP_TYPES.test(node.type)) {
      if ((p.options || {}).allowUnauthorizedCerts === true) {
        add('n8n-tls-verify-off', 'medium', 'tls-crypto', `"${node.name}" ignores TLS certificate errors`,
          'Requests (and any credentials in them) can be intercepted.', 'Turn off "Ignore SSL Issues" and trust the internal CA instead.');
      }
      const params = [
        ...(((p.headerParameters || {}).parameters) || []),
        ...(((p.queryParameters || {}).parameters) || []),
      ];
      for (const h of params) {
        if (h && AUTH_HEADER_NAMES.test(String(h.name || '')) && h.value && !isExpression(h.value)) {
          add('n8n-hardcoded-credential', 'high', 'secrets', `Credential pasted into "${node.name}" (${h.name})`,
            'The value is stored in the workflow JSON, so it lands in git, exports and execution logs.',
            'Use an n8n credential (Header Auth or a predefined type) instead of a literal value.',
            { floor: true, evidence: `${h.name}: ${Secrets.mask(h.value)}` });
        }
      }
    }

    if (CODE_TYPES.test(node.type)) {
      const code = String(p.jsCode || p.pythonCode || p.functionCode || p.code || '');
      if (/child_process|\bexecSync\b|\bspawn\(|subprocess|os\.system/.test(code)) {
        add('n8n-code-exec', 'high', 'injection', `"${node.name}" runs shell commands`,
          'Shell access from a workflow (especially one an AI agent can call) lets crafted input execute commands on the n8n host.',
          'Remove the shell call or move it to a tightly scoped, separately authenticated service.', { floor: true });
      }
      if (/\$env\b|process\.env/.test(code)) {
        add('n8n-code-env', 'medium', 'secrets', `"${node.name}" reads environment variables`,
          'Environment variables on n8n hosts include secrets such as the encryption key (blocked by default in n8n 2.x).',
          'Pass needed values through credentials or workflow inputs.');
      }
      if (/(?<![\w.])eval\s*\(|new\s+Function\s*\(/.test(code)) {
        add('n8n-code-eval', 'high', 'injection', `"${node.name}" evaluates dynamic code`,
          'Workflow data becomes executable code.', 'Remove eval/new Function.');
      }
    }

    if (node.type === T.executeCommand) {
      add('n8n-execute-command', 'high', 'injection', `Execute Command node "${node.name}"`,
        'Runs shell commands on the n8n host; disabled by default in n8n 2.x for that reason.',
        'Use a dedicated integration instead.', { floor: true });
    }

    if (DB_TYPES.test(node.type) && p.operation === 'executeQuery') {
      const query = String(p.query || '');
      const usesReplacement = !!((p.options || {}).queryReplacement) && /\$\d/.test(query);
      if (query.includes('{{') && !usesReplacement) {
        add('n8n-sql-injection', 'high', 'injection', `SQL built from workflow data in "${node.name}"`,
          'Values interpolated into the query (chat input, webhook body, AI tool arguments) allow SQL injection.',
          'Use query parameters ($1, $2 with "Query Parameters") instead of {{ }} in the SQL text.',
          { floor: true, evidence: Util.truncate(query, 140) });
      }
    }

    if (ctx.toolOf[node.name] && RISKY_TOOL_TYPES.test(node.type) && (isNew || !ctx.baseToolOf[node.name])) {
      add('n8n-agent-risky-tool', 'medium', 'auth', `AI agent "${ctx.toolOf[node.name]}" can now use "${node.name}"`,
        'Agent tools act on model output, which users can steer with crafted prompts (prompt injection, excessive agency).',
        'Scope the tool narrowly (read-only credentials, fixed queries/hosts) and validate its inputs.');
    }

    // Any other literal secret in parameters.
    for (const [path, value] of Object.entries(flatten(p))) {
      if (typeof value !== 'string' || isExpression(value)) continue;
      for (const hit of Secrets.scanText(value)) {
        if (out.some((f) => f.rule === 'n8n-hardcoded-credential')) break;
        add('n8n-secret-in-parameters', hit.severity, 'secrets', `${hit.title} in "${node.name}" parameters`,
          'The value is stored in the workflow JSON, so it lands in git, exports and execution logs.',
          'Move it into an n8n credential.', { floor: Util.sevRank(hit.severity) >= 3, evidence: `${path}: ${Secrets.mask(hit.value)}` });
      }
    }
    return out;
  }

  function summarizeNode(node) {
    const p = node.parameters || {};
    const bits = [node.type.replace(/^n8n-nodes-base\.|^@n8n\/n8n-nodes-langchain\./, '')];
    if (p.httpMethod || p.path) bits.push(`${p.httpMethod || ''} /${p.path || ''}`.trim());
    if (p.authentication) bits.push(`auth=${p.authentication}`);
    if (p.url && !isExpression(p.url)) bits.push(`url=${Util.truncate(p.url, 80)}`);
    if (p.operation) bits.push(`op=${p.operation}`);
    return bits.join(' ');
  }

  // Analyse one file. Returns { workflows: [{ name, added, removed, changed, findings }], error }.
  function analyzeFile(path, headText, baseText) {
    const head = parseWorkflows(headText || '');
    const base = baseText ? parseWorkflows(baseText) : { workflows: [] };
    if (!head.workflows.length) return { workflows: [], error: head.error || 'not an n8n workflow' };
    const results = [];
    head.workflows.forEach((wf, wi) => {
      const baseWf = base.workflows.find((b) => (b.id && b.id === wf.id) || b.name === wf.name) || base.workflows[wi] || null;
      const baseNodes = new Map((baseWf ? baseWf.nodes : []).map((n) => [nodeKey(n), n]));
      const baseByName = new Map((baseWf ? baseWf.nodes : []).map((n) => [n.name, n]));
      const headKeys = new Set();
      const ctx = { toolOf: agentTools(wf), baseToolOf: baseWf ? agentTools(baseWf) : {} };
      const added = []; const changed = []; const findings = [];
      for (const node of wf.nodes) {
        const b = baseNodes.get(nodeKey(node)) || baseByName.get(node.name) || null;
        headKeys.add(b ? nodeKey(b) : nodeKey(node));
        if (!b) {
          added.push({ label: `${node.name} (${summarizeNode(node)})`, params: paramPreview(node.parameters) });
        } else {
          const diffs = changedParams(b, node);
          if (diffs.length) {
            const now = flatten({ parameters: node.parameters || {}, credentials: node.credentials || {}, disabled: !!node.disabled });
            changed.push({ label: `${node.name} (${summarizeNode(node)})`,
              diffs: diffs.slice(0, 12).map((k) => `${k} = ${Util.truncate(JSON.stringify(now[k] ?? null), 160)}`),
              more: Math.max(0, diffs.length - 12) });
          }
        }
        for (const f of checkNode(node, b, ctx)) findings.push({ ...f, file: path, line: lineOf(headText, node) });
      }
      const removed = (baseWf ? baseWf.nodes : []).filter((n) => !headKeys.has(nodeKey(n))).map((n) => `${n.name} (${summarizeNode(n)})`);
      const pin = wf.pinData && Object.keys(wf.pinData).length ? wf.pinData : null;
      if (pin) {
        const pinText = JSON.stringify(pin);
        const emails = (pinText.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || []).length;
        findings.push({ rule: 'n8n-pindata', severity: 'medium', category: 'data-exposure', file: path, line: null,
          title: `Pinned test data committed in "${wf.name}"`,
          why: `pinData stores real execution data in the workflow file${emails ? ` (it contains ${emails} email address${emails > 1 ? 'es' : ''})` : ''}.`,
          fix: 'Unpin the data before exporting, or strip pinData in the export step.' });
        for (const hit of Secrets.scanText(pinText)) {
          findings.push({ rule: 'n8n-secret-in-pindata', severity: hit.severity, category: 'secrets', file: path, line: null, floor: true,
            title: `${hit.title} inside pinned data`, why: 'Pinned data is stored in the workflow file.',
            fix: 'Remove the pinned data and rotate the credential.', evidence: Secrets.mask(hit.value) });
          break;
        }
      }
      if ((wf.settings || {}).callerPolicy === 'any') {
        findings.push({ rule: 'n8n-caller-policy-any', severity: 'low', category: 'auth', file: path, line: null,
          title: `"${wf.name}" can be called by any workflow`, why: 'Any workflow on the instance can invoke it with arbitrary input.',
          fix: 'Restrict "This workflow can be called by" to the workflows that need it.' });
      }
      results.push({ name: wf.name || '(unnamed)', added, removed, changed, findings, isNewWorkflow: !baseWf });
    });
    return { workflows: results, error: null };
  }

  const paramPreview = (params) => Util.truncate(JSON.stringify(params || {}), 700);

  // Text for the LLM prompt. It replaces the raw JSON patch, which is mostly noise
  // (ids, positions) and wastes tokens. Values are masked by the caller's maskText.
  function describe(path, analysis) {
    const lines = [`n8n workflow file ${path}:`];
    for (const wf of analysis.workflows) {
      lines.push(`- Workflow "${wf.name}"${wf.isNewWorkflow ? ' (new)' : ''}`);
      for (const a of wf.added) lines.push(`  + added node ${a.label}\n    parameters: ${a.params}`);
      for (const r of wf.removed) lines.push(`  - removed node ${r}`);
      for (const c of wf.changed) {
        lines.push(`  ~ changed node ${c.label}`);
        for (const d of c.diffs) lines.push(`    ${d}`);
        if (c.more) lines.push(`    … ${c.more} more changed fields`);
      }
      if (!wf.added.length && !wf.removed.length && !wf.changed.length) lines.push('  (layout or metadata changes only)');
    }
    return Secrets.maskText(lines.join('\n'));
  }

  return { parseWorkflows, analyzeFile, describe };
})();
