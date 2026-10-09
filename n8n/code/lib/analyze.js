// Turns the collected PR data into automated findings, a size-budgeted diff, and the
// LLM request. Input ctx fields: config, input, pr, files (GitHub "list PR files"
// objects), scan ({ status, bundle }), contents ({ "path@head" | "path@base": text }).
const Analyze = (() => {
  const MAX_AUTOMATED_FOR_LLM = 100;

  function prepareFiles(ctx) {
    const cfg = ctx.config;
    return ctx.files.map((f) => {
      const parsed = Diff.parsePatch(f.patch);
      let domain = Classify.domainOf(f.filename);
      let wf = null;
      const headText = ctx.contents[`${f.filename}@head`];
      if (domain === 'json' && typeof headText === 'string') {
        const baseText = ctx.contents[`${f.previous_filename || f.filename}@base`];
        const a = N8nWf.analyzeFile(f.filename, headText, typeof baseText === 'string' ? baseText : null);
        if (a.workflows.length) { wf = a; domain = 'n8n'; }
      }
      const neverSend = Classify.neverSendReason(f.filename, cfg.llm_exclude_paths) ||
        (Classify.isVaultEncrypted(f.patch) ? 'Ansible Vault encrypted' : null);
      return {
        filename: f.filename, previous_filename: f.previous_filename || null, status: f.status,
        additions: f.additions || 0, deletions: f.deletions || 0, patch: f.patch || null,
        domain, kind: domain, added: parsed.added, addedLines: parsed.addedLines, wf, neverSend,
        sensitive: Classify.sensitiveReason(f.filename),
      };
    });
  }

  function automatedFindings(files, scan) {
    const automated = [];
    let r = 0;
    let s = 0;
    for (const f of files) {
      if (f.status === 'removed') continue;
      // n8n JSON gets structured checks; line rules would mostly fire on JSON noise.
      const lineFindings = f.domain === 'n8n'
        ? Rules.checkFile({ ...f, domain: 'json' }, f.added).filter((x) => x.category === 'prompt-injection' || x.rule === 'n8n-test-webhook-url')
        : Rules.checkFile(f, f.added);
      for (const x of lineFindings) automated.push({ id: `R${++r}`, source: 'rules', ...x });
      if (f.wf) {
        for (const wf of f.wf.workflows) {
          for (const x of wf.findings) automated.push({ id: `R${++r}`, source: 'n8n-check', ...x });
        }
      }
    }
    let tools = null;
    if (scan && scan.status === 'ok' && scan.bundle) {
      const norm = Sarif.normalize(scan.bundle, files);
      tools = norm.tools;
      for (const x of norm.findings.filter(Sarif.isNew)) {
        automated.push({
          id: `S${++s}`, source: x.tool, rule: x.rule, severity: x.severity, floor: false, category: x.category,
          file: x.file, line: x.line, end_line: x.end_line, title: x.title, evidence: '',
          why: x.message && !x.message.startsWith(x.title) ? x.message : '', help_uri: x.help_uri,
          commit: x.commit, scope: x.scope,
        });
      }
    }
    return { automated, tools };
  }

  function buildDiff(files, budget) {
    const ordered = [...files].sort((a, b) => Classify.priorityOf(b) - Classify.priorityOf(a) || a.filename.localeCompare(b.filename));
    const blocks = [];
    const omitted = [];
    let used = 0;
    let partial = false;
    const omit = (f, reason) => { f.omitReason = reason; omitted.push({ file: f.filename, reason }); };
    for (const f of ordered) {
      if (f.status === 'removed') { omit(f, 'file deleted'); continue; }
      if (f.neverSend) { omit(f, f.neverSend); continue; }
      let body;
      if (f.domain === 'n8n') body = N8nWf.describe(f.filename, f.wf);
      else if (!f.patch) { omit(f, 'no diff available (binary, or too large for the GitHub API)'); continue; }
      else body = Prompt.formatPatch(f.patch);
      let cost = Util.estimateTokens(body);
      if (used + cost > budget) {
        const remaining = budget - used;
        if (remaining < 800 || f.domain === 'n8n') { omit(f, 'over the review size budget'); partial = true; continue; }
        body = Prompt.formatPatch(f.patch, Math.max(20, Math.floor((remaining * 3.5) / 70)));
        cost = Util.estimateTokens(body);
        f.truncated = true;
        partial = true;
      }
      used += cost;
      blocks.push({ header: `${f.filename} (${f.status}, ${f.domain})${f.truncated ? ' [truncated]' : ''}`, body });
    }
    return { blocks, omitted, partial, tokens: used };
  }

  function run(ctx) {
    const cfg = ctx.config;
    const files = prepareFiles(ctx);
    const { automated, tools } = automatedFindings(files, ctx.scan);
    const diff = buildDiff(files, cfg.diff_token_budget);
    const domains = [...new Set(files.map((f) => f.domain))];
    const sensitiveFiles = files.filter((f) => f.sensitive).map((f) => ({ file: f.filename, why: f.sensitive }));
    const sensitive = sensitiveFiles.length > 0 || domains.includes('ci') ||
      automated.some((a) => a.floor && Util.sevRank(a.severity) >= Util.sevRank('high'));
    const docsOnly = files.length > 0 && files.every((f) => f.domain === 'docs');

    // The LLM sees the most severe automated findings first.
    const forLlm = [...automated].sort((a, b) => Util.sevRank(b.severity) - Util.sevRank(a.severity)).slice(0, MAX_AUTOMATED_FOR_LLM);
    const analysis = {
      files: files.map((f) => ({ filename: f.filename, status: f.status, additions: f.additions, deletions: f.deletions,
        kind: f.kind, omitReason: f.omitReason || null, addedLines: f.addedLines })),
      automated, diff, domains, sensitive, sensitiveFiles, docsOnly, scanTools: tools,
    };
    let llm;
    if (docsOnly) llm = { needed: false, skip_reason: 'documentation-only change' };
    else if (!diff.blocks.length) llm = { needed: false, skip_reason: 'nothing reviewable was left after exclusions' };
    else llm = { needed: true, request: Prompt.buildRequest(ctx, { ...analysis, automated: forLlm }) };
    // Drop bulky per-file data the later steps no longer need.
    return { analysis: { ...analysis, diff: { omitted: diff.omitted, partial: diff.partial, tokens: diff.tokens, blocks: diff.blocks.length } }, llm };
  }

  return { run, buildDiff, prepareFiles };
})();
