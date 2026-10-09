// Parses the model's answer, validates it against what the PR actually contains, and
// merges it with the automated findings into the final review.
const Review = (() => {
  const CATEGORIES = ['secrets', 'iam-access', 'network-exposure', 'injection', 'tls-crypto', 'supply-chain', 'data-exposure',
    'auth', 'misconfiguration', 'logging', 'ci-cd', 'n8n-workflow', 'prompt-injection', 'other'];
  const VERDICTS = ['confirmed', 'false_positive', 'not_introduced_by_pr', 'needs_human'];
  const MAX_LLM_FINDINGS = 8;

  const str = (v, max) => Util.truncate(Secrets.maskText(typeof v === 'string' ? v : ''), max);
  const oneOf = (v, allowed, fallback) => (allowed.includes(v) ? v : fallback);
  const intOrNull = (v) => (Number.isInteger(v) && v > 0 ? v : null);

  function errorText(err) {
    if (!err) return 'unknown error';
    if (typeof err === 'string') return err;
    return err.message || err.description || JSON.stringify(err).slice(0, 300);
  }

  // resp: the HTTP node output (chat completion JSON, or an item carrying `error`).
  function parseLlmResponse(resp) {
    if (!resp || typeof resp !== 'object') return { ok: false, error: 'no response' };
    if (resp.error) return { ok: false, error: Util.truncate(errorText(resp.error), 300) };
    const choice = Array.isArray(resp.choices) ? resp.choices[0] : null;
    const u = resp.usage || {};
    const usage = {
      input_tokens: u.prompt_tokens || 0,
      cached_tokens: (u.prompt_tokens_details || {}).cached_tokens || 0,
      output_tokens: u.completion_tokens || 0,
      reasoning_tokens: (u.completion_tokens_details || {}).reasoning_tokens || 0,
    };
    if (!choice) return { ok: false, error: 'response had no choices', usage };
    const msg = choice.message || {};
    if (msg.refusal) return { ok: false, error: 'model refused: ' + Util.truncate(String(msg.refusal), 200), usage };
    if (choice.finish_reason === 'length') return { ok: false, error: 'answer cut off (raise max_completion_tokens)', usage };
    if (choice.finish_reason === 'content_filter') return { ok: false, error: 'blocked by the Azure content filter', usage };
    let raw;
    try { raw = JSON.parse(msg.content); } catch (e) { return { ok: false, error: 'model did not return valid JSON', usage }; }
    return { ok: true, raw, usage, model: resp.model || null };
  }

  // Keep only well-formed content that refers to files in this PR.
  function validate(raw, files) {
    const byFile = new Map(files.map((f) => [f.filename, f]));
    const fixLine = (file, line) => {
      const f = byFile.get(file);
      const l = intOrNull(line);
      return { line: l, inDiff: !!(f && l && f.addedLines.includes(l)) };
    };
    const out = {
      summary: str(raw.summary, 700),
      risk: oneOf(raw.risk, Util.RISKS, 'medium'),
      risk_reason: str(raw.risk_reason, 500),
      look_first: [],
      findings: [],
      triage: {},
      injection_suspected: raw.injection_suspected === true,
      dropped: 0,
    };
    for (const lf of (Array.isArray(raw.look_first) ? raw.look_first : []).slice(0, 3)) {
      if (!lf || !byFile.has(lf.file)) { out.dropped++; continue; }
      out.look_first.push({ file: lf.file, line: fixLine(lf.file, lf.line).line, why: str(lf.why, 200) });
    }
    for (const f of (Array.isArray(raw.findings) ? raw.findings : [])) {
      if (!f || !byFile.has(f.file) || out.findings.length >= MAX_LLM_FINDINGS) { out.dropped++; continue; }
      const { line } = fixLine(f.file, f.line);
      out.findings.push({
        severity: oneOf(f.severity, Util.SEVERITIES, 'low'),
        category: oneOf(f.category, CATEGORIES, 'other'),
        file: f.file, line,
        title: str(f.title, 140), evidence: str(f.evidence, 160),
        why: str(f.why_it_matters, 400), fix: str(f.fix, 400),
        confidence: oneOf(f.confidence, ['high', 'medium', 'low'], 'medium'),
        related: (Array.isArray(f.related_ids) ? f.related_ids : []).filter((x) => /^[RS]\d+$/.test(x)).slice(0, 10),
      });
    }
    for (const t of (Array.isArray(raw.automated_findings_triage) ? raw.automated_findings_triage : [])) {
      if (t && /^[RS]\d+$/.test(t.id) && VERDICTS.includes(t.verdict)) {
        out.triage[t.id] = { verdict: t.verdict, reason: str(t.reason, 240) };
      }
    }
    return out;
  }

  const sourceLabel = (s) => ({ rules: 'rules', 'n8n-check': 'n8n check', LLM: 'LLM' }[s] || s);

  // Combine automated findings, LLM output and gating into the final review object.
  function combine(analysis, llm) {
    const triage = llm.ok ? llm.review.triage : {};
    const entries = [];
    for (const a of analysis.automated) {
      const t = triage[a.id];
      entries.push({
        ids: [a.id], severity: a.severity, floor: !!a.floor, category: a.category, file: a.file, line: a.line || null,
        end_line: a.end_line || null,
        title: a.title, evidence: a.evidence || '', why: a.why || '', fix: a.fix || '', sources: [sourceLabel(a.source)],
        help_uri: a.help_uri || '', commit: a.commit || null, note: a.note || null, verdict: t ? t.verdict : null,
        verdictReason: t ? t.reason : null, verdicts: t ? [t.verdict] : [],
      });
    }
    // Merge duplicates: several tools on the same line and category, and block-level
    // scanner hits (checkov reports whole resources) that contain a rule's line.
    const preferred = (r) => (r.sources.some((s) => s === 'rules' || s === 'n8n check' || s === 'LLM') ? 1 : 0);
    const absorb = (target, r) => {
      const takeText = preferred(r) > preferred(target) ||
        (preferred(r) === preferred(target) && Util.sevRank(r.severity) > Util.sevRank(target.severity));
      target.ids.push(...r.ids);
      target.sources = [...new Set([...target.sources, ...r.sources])];
      target.severity = Util.maxSeverity(target.severity, r.severity);
      if (takeText) Object.assign(target, { title: r.title, why: r.why || target.why, fix: r.fix || target.fix, help_uri: r.help_uri || target.help_uri });
      target.floor = target.floor || r.floor;
      if (!target.evidence && r.evidence) target.evidence = r.evidence;
      if (!target.commit && r.commit) target.commit = r.commit;
      target.verdicts = [...target.verdicts, ...r.verdicts];
      if (r.verdictReason && !target.verdictReason) target.verdictReason = r.verdictReason;
    };
    const merged = [];
    for (const r of entries) {
      const key = r.line ? `${r.file}:${r.line}:${r.category}` : `${r.file}:${r.title}`;
      const existing = merged.find((m) => m._key === key);
      if (existing) absorb(existing, r);
      else merged.push({ ...r, _key: key });
    }
    for (const r of [...merged]) {
      if (preferred(r) || !r.line || !r.end_line || r.end_line <= r.line) continue;
      const host = merged.find((m) => m !== r && preferred(m) && m.file === r.file && m.category === r.category &&
        m.line && m.line >= r.line && m.line <= r.end_line);
      if (host) { absorb(host, r); merged.splice(merged.indexOf(r), 1); }
    }
    // Split after merging, so one issue never shows up in two sections.
    const rows = [];
    const dismissed = [];
    const minor = [];
    const DISMISS = ['false_positive', 'not_introduced_by_pr'];
    for (const g of merged) {
      g.verdict = g.verdicts.includes('confirmed') ? 'confirmed' : (g.verdicts.includes('needs_human') ? 'needs_human' : (g.verdicts[0] || null));
      if (!g.floor && g.verdicts.length && g.verdicts.every((v) => DISMISS.includes(v))) dismissed.push(g);
      else if (!g.floor && Util.sevRank(g.severity) <= Util.sevRank('low') && g.verdict !== 'confirmed') minor.push(g);
      else rows.push(g);
    }
    if (llm.ok) {
      for (const f of llm.review.findings) {
        const target = rows.find((r) => r.ids.some((id) => f.related.includes(id))) ||
          rows.find((r) => r.file === f.file && f.line && r.line === f.line && r.category === f.category);
        if (target) {
          target.sources = [...new Set([...target.sources, 'LLM'])];
          target.severity = Util.maxSeverity(target.severity, f.severity);
          if (f.why) target.why = f.why;
          if (f.fix) target.fix = f.fix;
          continue;
        }
        rows.push({ ids: [], severity: f.severity, floor: false, category: f.category, file: f.file, line: f.line,
          title: f.title, evidence: f.evidence, why: f.why, fix: f.fix, sources: ['LLM'], confidence: f.confidence,
          verdict: null, verdicts: [], help_uri: '', commit: null, note: null });
      }
    }
    rows.sort((a, b) => Util.sevRank(b.severity) - Util.sevRank(a.severity) || Number(b.floor) - Number(a.floor) ||
      preferred(b) - preferred(a) || a.file.localeCompare(b.file) || (a.line || 0) - (b.line || 0));
    for (const g of [...rows, ...minor, ...dismissed]) delete g._key;

    // The badge matches the table: the highest displayed severity, and never below the
    // model's overall verdict. The model lowers risk only by dismissing non-floor findings.
    const risk = Util.maxRisk(llm.ok ? llm.review.risk : 'clean', ...rows.map((r) => Util.severityToRisk(r.severity)));
    return {
      risk, rows, dismissed, minor,
      summary: llm.ok ? llm.review.summary : '',
      risk_reason: llm.ok ? llm.review.risk_reason : '',
      look_first: llm.ok ? llm.review.look_first : [],
      injection_suspected: (llm.ok && llm.review.injection_suspected) || analysis.automated.some((a) => a.category === 'prompt-injection'),
      llm_dropped: llm.ok ? llm.review.dropped : 0,
    };
  }

  return { parseLlmResponse, validate, combine };
})();
