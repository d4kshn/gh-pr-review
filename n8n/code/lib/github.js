// GitHub-facing helpers: the hidden comment marker, finding our own comment,
// deciding whether a review is needed, and label bookkeeping.
const GH = (() => {
  const MARKER_RE = /<!--\s*secrev:v1\s+([^>]*?)\s*-->/;
  const LABELS = {
    critical: { color: 'b60205', description: 'secrev: critical security risk (advisory)' },
    high: { color: 'd93f0b', description: 'secrev: high security risk (advisory)' },
    medium: { color: 'fbca04', description: 'secrev: medium security risk (advisory)' },
    low: { color: 'c2e0c6', description: 'secrev: low security risk (advisory)' },
    clean: { color: '0e8a16', description: 'secrev: no security concerns found (advisory)' },
    error: { color: 'bfdadc', description: 'secrev: review incomplete, re-run the secrev-scan check' },
  };

  function marker(fields) {
    const parts = Object.entries(fields).map(([k, v]) => `${k}=${String(v ?? '').replace(/[\s>]/g, '_').replace(/--/g, '_')}`);
    return `<!-- secrev:v1 ${parts.join(' ')} -->`;
  }

  function parseMarker(body) {
    const m = MARKER_RE.exec(String(body || ''));
    if (!m) return null;
    const out = {};
    for (const kv of m[1].split(/\s+/)) {
      const i = kv.indexOf('=');
      if (i > 0) out[kv.slice(0, i)] = kv.slice(i + 1);
    }
    return out;
  }

  // Only comments written by our GitHub App count; anyone can paste a marker.
  function findOwnComment(comments, appSlug) {
    const bot = `${appSlug}[bot]`;
    const mine = (comments || []).filter((c) => c && typeof c.body === 'string' && MARKER_RE.test(c.body) &&
      ((c.performed_via_github_app && c.performed_via_github_app.slug === appSlug) || (c.user && c.user.login === bot)));
    if (!mine.length) return null;
    mine.sort((a, b) => String(a.created_at || '').localeCompare(String(b.created_at || '')) || a.id - b.id);
    return { id: mine[0].id, marker: parseMarker(mine[0].body), duplicates: mine.slice(1).map((c) => c.id) };
  }

  function decideReview(previous, input) {
    if (!previous || !previous.marker) return { proceed: true, reason: 'first review' };
    const m = previous.marker;
    if (m.sha !== input.head_sha) return { proceed: true, reason: 'new commits' };
    if (input.force) return { proceed: true, reason: 'forced by a scan re-run' };
    if (m.llm === 'error') return { proceed: true, reason: 'previous review was incomplete' };
    if (m.scanners !== 'ok' && input.run_id) return { proceed: true, reason: 'scan results are now available' };
    return { proceed: false, reason: 'already reviewed at this commit' };
  }

  function labelPlan(currentNames, level, prefix) {
    const ours = (currentNames || []).filter((n) => n.startsWith(prefix));
    const want = prefix + level;
    return { add: ours.includes(want) ? null : want, remove: ours.filter((n) => n !== want) };
  }

  return { marker, parseMarker, findOwnComment, decideReview, labelPlan, LABELS, MARKER_RE };
})();
