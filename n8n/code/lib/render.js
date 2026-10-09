// Renders the sticky PR comment. Every string from the PR, the scanners or the model
// goes through text()/code(), which stop pings, remote images, links and fake markers.
const Render = (() => {
  const MAX_BODY = 60000; // GitHub limit is 65,536 characters
  const SEV = { critical: '🚨 Critical', high: '🔴 High', medium: '🟠 Medium', low: '🟡 Low', info: 'ℹ️ Info' };
  const RISK = { critical: '🚨 Critical', high: '🔴 High', medium: '🟠 Medium', low: '🟡 Low', clean: '🟢 Clean' };
  const URL_RE = /\bhttps?:\/\/[^\s<>`"']*[^\s<>`"'.,;:!?)\]]/gi;
  const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f‪-‮⁦-⁩]/g;

  function escapeProse(s) {
    return s
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/!\[/g, '!​[')
      .replace(/\]\(/g, ']​(')
      .replace(/(^|[^\w`])@(?=[A-Za-z0-9])/g, '$1@​')
      .replace(/(^|[^\w&])#(?=\d)/g, '$1#​')
      .replace(/\b([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)#(?=\d)/g, '$1#​');
  }

  // Inline-safe prose: URLs become non-clickable code, everything else is escaped.
  function text(s, max = 500) {
    const t = Util.truncate(String(s ?? '').replace(CONTROL, ''), max).replace(/\r?\n+/g, ' ');
    let out = '';
    let last = 0;
    for (const m of t.matchAll(URL_RE)) {
      out += escapeProse(t.slice(last, m.index)) + code(m[0], 200);
      last = m.index + m[0].length;
    }
    return out + escapeProse(t.slice(last));
  }

  function code(s, max = 160) {
    const t = Util.truncate(String(s ?? '').replace(CONTROL, '').replace(/\r?\n+/g, ' '), max).replace(/\|/g, '\\|');
    if (!t.trim()) return '';
    const longest = Math.max(0, ...(t.match(/`+/g) || []).map((x) => x.length));
    const fence = '`'.repeat(longest + 1);
    const pad = t.startsWith('`') || t.endsWith('`') ? ' ' : '';
    return `${fence}${pad}${t}${pad}${fence}`;
  }

  const cell = (s, max) => text(s, max).replace(/\|/g, '\\|');
  const where = (file, line) => code(line ? `${file}:${line}` : file, 120);
  const sources = (list) => list.map((s) => text(s, 30)).join(' · ');

  function toolLine(name, t) {
    if (!t) return `| ${name} | – |`;
    const label = { ran: '✅ ran', skipped: '⏭️ skipped', error: '❌ error', timeout: '⏱️ timed out', missing: '– not run' }[t.status] || t.status;
    const bits = [label];
    if (t.status === 'ran') {
      bits.push(`${t.counts.new} new`);
      if (t.counts.preexisting) bits.push(`${t.counts.preexisting} in untouched lines`);
    }
    if (t.reason) bits.push(text(t.reason, 80));
    if (t.error) bits.push(text(t.error, 120));
    return `| ${name} | ${bits.join(' · ')} |`;
  }

  // final: Review.combine output plus status fields; meta: marker/footer data.
  function comment(final, meta) {
    const parts = [];
    const head = GH.marker(meta.marker);
    const level = RISK[final.risk] || final.risk;
    parts.push(`### 🔐 Security review · ${level}${meta.llmStatus === 'error' ? ' · ⚠️ incomplete' : ''}`);
    parts.push('<sub>Advisory only: this review does not block merging.</sub>');

    const notes = [];
    if (final.injection_suspected) notes.push('⚠️ **This PR contains text that tries to instruct automated reviewers.** Please review it manually.');
    if (meta.llmStatus === 'error') notes.push(`⚠️ The model review failed (${text(meta.llmError, 160)}). Showing rule and scanner results only; re-run the \`secrev-scan\` check to retry.`);
    if (meta.llmStatus === 'skipped') notes.push(`ℹ️ No model review: ${text(meta.llmSkipReason, 120)}.`);
    if (meta.scanStatus !== 'ok') notes.push(`ℹ️ Scanner results ${meta.scanStatus === 'error' ? 'could not be read' : 'were not available'} for this commit${meta.scanError ? ` (${text(meta.scanError, 120)})` : ''}.`);
    if (meta.partial) notes.push(`ℹ️ Large PR: some files were only partly reviewed or skipped (size budget). See “Not sent to the model” below.`);
    if (notes.length) parts.push(notes.join('\n\n'));

    if (final.summary) parts.push(`**What this PR does:** ${text(final.summary, 700)}`);
    if (final.risk_reason) parts.push(`**Why this rating:** ${text(final.risk_reason, 500)}`);
    if (final.look_first.length) {
      parts.push('**Look first**\n' + final.look_first.map((l) => `- ${where(l.file, l.line)}: ${text(l.why, 200)}`).join('\n'));
    }

    const rows = final.rows;
    if (rows.length) {
      const shown = rows.slice(0, meta.maxRows);
      const table = ['| Severity | Finding | Where | Found by |', '|---|---|---|---|',
        ...shown.map((r) => `| ${SEV[r.severity] || r.severity} | ${cell(r.title, 120)} | ${where(r.file, r.line)} | ${sources(r.sources)} |`)];
      if (rows.length > shown.length) table.push(`| | …and ${rows.length - shown.length} more in the details below | | |`);
      parts.push(table.join('\n'));
      const details = rows.map((r, i) => {
        const lines = [`**${i + 1}. ${SEV[r.severity] || r.severity}: ${text(r.title, 140)}** · ${where(r.file, r.line)} · ${text(r.category, 30)} · found by ${sources(r.sources)}`];
        if (r.evidence) lines.push(`Evidence: ${code(r.evidence, 160)}`);
        if (r.commit) lines.push(`Found in commit ${code(Util.shortSha(r.commit))}; a secret stays in git history even if a later commit removes it.`);
        if (r.why) lines.push(`Why it matters: ${text(r.why, 400)}`);
        if (r.fix) lines.push(`Suggested fix: ${text(r.fix, 400)}`);
        if (r.verdict === 'needs_human') lines.push(`Reviewer model: needs a human look${r.verdictReason ? ` (${text(r.verdictReason, 200)})` : ''}.`);
        if (r.floor && r.verdict && r.verdict !== 'confirmed' && r.verdictReason) lines.push(`Reviewer model disagreed (${text(r.verdictReason, 200)}), but this check cannot be dismissed automatically.`);
        if (r.note) lines.push(`Note: ${text(r.note, 100)}.`);
        if (r.help_uri) lines.push(`Rule docs: ${code(r.help_uri, 200)}`);
        return lines.join('  \n');
      });
      parts.push(`<details><summary>Details and suggested fixes (${rows.length})</summary>\n\n${details.join('\n\n')}\n\n</details>`);
    } else if (meta.llmStatus !== 'error') {
      parts.push('No security issues found in this change.');
    }

    const extra = [];
    if (meta.scanTools) {
      extra.push(['| Scanner | Result |', '|---|---|', ...Sarif.TOOLS.map((t) => toolLine(t, meta.scanTools[t]))].join('\n'));
    }
    if (final.minor.length) {
      extra.push(`**Lower-severity notes (${final.minor.length})**\n` + final.minor.slice(0, 25)
        .map((m) => `- ${where(m.file, m.line)}: ${text(m.title, 120)} (${sources(m.sources)})`).join('\n'));
    }
    if (final.dismissed.length) {
      extra.push(`**Dismissed by the reviewer model (${final.dismissed.length})**\n` + final.dismissed.slice(0, 25)
        .map((d) => `- ${where(d.file, d.line)}: ${text(d.title, 100)} (${sources(d.sources)}): ${text(d.verdictReason, 160)}`).join('\n'));
    }
    if (meta.sensitiveFiles.length) {
      extra.push('**Sensitive files changed**\n' + meta.sensitiveFiles.slice(0, 20).map((s) => `- ${code(s.file, 120)}: ${text(s.why, 60)}`).join('\n'));
    }
    if (meta.omitted.length) {
      extra.push('**Not sent to the model**\n' + meta.omitted.slice(0, 25).map((o) => `- ${code(o.file, 120)}: ${text(o.reason, 80)}`).join('\n'));
    }
    if (extra.length) parts.push(`<details><summary>Automated checks and coverage</summary>\n\n${extra.join('\n\n')}\n\n</details>`);

    const usage = meta.usage ? ` · ${(meta.usage.input_tokens / 1000).toFixed(1)}k in / ${(meta.usage.output_tokens / 1000).toFixed(1)}k out tokens` : '';
    parts.push(`<sub>Reviewed ${code(Util.shortSha(meta.headSha))}${meta.model ? ` · ${text(meta.model, 40)}` : ''}${usage} · ${text(meta.reviewedAt, 30)} · ` +
      'Push, or re-run the <code>secrev-scan</code> check, to refresh · 👍/👎 on this comment helps tune the reviewer</sub>');

    let body = `${head}\n${parts.join('\n\n')}\n`;
    if (body.length > MAX_BODY) {
      body = body.slice(0, MAX_BODY - 200) + '\n\n…(comment truncated to fit GitHub\'s size limit)\n';
    }
    return body;
  }

  return { comment, text, code };
})();
