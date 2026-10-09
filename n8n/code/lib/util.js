// Shared helpers.
// Each lib file defines exactly one namespace constant, so scripts/build.py can concatenate
// several of them into a single n8n Code node (Code nodes cannot import local files).
const Util = (() => {
  const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
  const RISKS = ['clean', 'low', 'medium', 'high', 'critical'];

  const sevRank = (s) => Math.max(0, SEVERITIES.indexOf(s));
  const riskRank = (r) => Math.max(0, RISKS.indexOf(r));

  // "info" findings never raise the risk level.
  const severityToRisk = (s) => (s === 'info' || !SEVERITIES.includes(s) ? 'clean' : s);

  function maxRisk(...risks) {
    return risks.reduce((best, r) => (riskRank(r) > riskRank(best) ? r : best), 'clean');
  }

  function maxSeverity(...sevs) {
    return sevs.filter(Boolean).reduce((best, s) => (sevRank(s) > sevRank(best) ? s : best), 'info');
  }

  function lowerSeverity(s) {
    return SEVERITIES[Math.max(0, sevRank(s) - 1)];
  }

  function truncate(text, max) {
    const s = String(text ?? '');
    return s.length <= max ? s : s.slice(0, Math.max(0, max - 1)) + '…';
  }

  // Constant-time string comparison (for webhook signatures).
  function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    let diff = a.length ^ b.length;
    const n = Math.max(a.length, b.length);
    for (let i = 0; i < n; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    return diff === 0;
  }

  // Minimal glob support: ** (any path), * (within a segment), ? (one char).
  function globToRegExp(glob) {
    let re = '';
    for (let i = 0; i < glob.length; i++) {
      const c = glob[i];
      if (c === '*' && glob[i + 1] === '*') {
        re += glob[i + 2] === '/' ? '(?:.*/)?' : '.*';
        i += glob[i + 2] === '/' ? 2 : 1;
      } else if (c === '*') re += '[^/]*';
      else if (c === '?') re += '[^/]';
      else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
    return new RegExp('^' + re + '$');
  }

  const matchesAny = (path, globs) => (globs || []).some((g) => globToRegExp(g).test(path));

  const shortSha = (sha) => String(sha || '').slice(0, 7);

  // Rough token estimate; code averages about 3.5 characters per token.
  const estimateTokens = (text) => Math.ceil(String(text || '').length / 3.5);

  function entropy(s) {
    const str = String(s || '');
    if (!str) return 0;
    const counts = {};
    for (const ch of str) counts[ch] = (counts[ch] || 0) + 1;
    let h = 0;
    for (const k in counts) {
      const p = counts[k] / str.length;
      h -= p * Math.log2(p);
    }
    return h;
  }

  function randomToken(n = 12) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let out = '';
    for (let i = 0; i < n; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
    return out;
  }

  function uniqueBy(arr, keyFn) {
    const seen = new Set();
    return arr.filter((x) => {
      const k = keyFn(x);
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }

  const isTestPath = (p) =>
    /(^|\/)(tests?|spec|__tests__|fixtures?|examples?|samples?|mocks?|testdata)\//i.test(p) ||
    /(^|\/)(test_[^/]*|[^/]*_test\.[a-z]+|[^/]*\.(test|spec)\.[a-z]+)$/i.test(p);

  return {
    SEVERITIES, RISKS, sevRank, riskRank, severityToRisk, maxRisk, maxSeverity, lowerSeverity,
    truncate, timingSafeEqual, globToRegExp, matchesAny, shortSha, estimateTokens, entropy,
    randomToken, uniqueBy, isTestPath,
  };
})();
