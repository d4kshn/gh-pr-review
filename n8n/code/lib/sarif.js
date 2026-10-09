// Normalizes the scan bundle produced by scanners/bundle.py. The bundle comes from a
// workflow the PR author can edit, so everything is validated and treated as data.
const Sarif = (() => {
  const TOOLS = ['gitleaks', 'checkov', 'ansible-lint', 'bandit', 'semgrep', 'zizmor'];
  // ansible-lint is mostly style; keep only rules with a security angle.
  const ANSIBLE_LINT_SECURITY = {
    'risky-file-permissions': 'medium', 'no-log-password': 'medium', 'risky-shell-pipe': 'low',
    'risky-octal': 'low', 'partial-become': 'low', 'latest': 'low', 'package-latest': 'low',
  };
  // checkov reports every failed check as "error"; these carry real exposure.
  const CHECKOV_HIGH = new Set([
    'CKV_AWS_24', 'CKV_AWS_25', 'CKV_AWS_260', 'CKV_AWS_1', 'CKV_AWS_49', 'CKV_AWS_62', 'CKV_AWS_63',
    'CKV_AWS_286', 'CKV_AWS_287', 'CKV_AWS_288', 'CKV_AWS_289', 'CKV_AWS_290', 'CKV_AWS_355', 'CKV_AWS_20', 'CKV_AWS_57',
    'CKV_AZURE_9', 'CKV_AZURE_10', 'CKV_AZURE_160', 'CKV_GCP_2', 'CKV_GCP_3', 'CKV_GCP_106',
  ]);
  // zizmor marks most audits "error"; these are the levels that fit an advisory review.
  const ZIZMOR_SEVERITY = {
    'template-injection': 'high', 'dangerous-triggers': 'medium', 'cache-poisoning': 'high', 'github-env': 'high',
    'insecure-commands': 'high', 'known-vulnerable-actions': 'high', 'impostor-commit': 'critical',
    'hardcoded-container-credentials': 'high', 'excessive-permissions': 'medium', 'secrets-inherit': 'medium',
    'overprovisioned-secrets': 'medium', 'unredacted-secrets': 'medium', 'bot-conditions': 'medium',
    'self-hosted-runner': 'medium', 'ref-confusion': 'medium', 'unsound-contains': 'medium',
    'unpinned-uses': 'low', 'artipacked': 'low', 'unpinned-images': 'low', 'stale-action-refs': 'low',
    'use-trusted-publishing': 'low', 'undocumented-permissions': 'low', 'obfuscation': 'low',
  };
  const CHECKOV_MEDIUM_HINT = /0\.0\.0\.0|ingress|public|administrative|privilege escalation|credentials exposure|certificate validation|https url|encrypt|wildcard|"\*"|exfiltration|unrestricted|without constraints/i;

  const VALID_SCOPES = ['changed-lines', 'history'];
  // Tools whose rule names are internal ids; their message reads better as a title.
  const TITLE_FROM_MESSAGE = new Set(['bandit', 'semgrep', 'zizmor', 'ansible-lint']);

  function firstSentence(text) {
    const s = String(text || '').split(/(?<=\.)\s|\n/)[0].replace(/\.$/, '');
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  function levelSeverity(level) {
    return { error: 'high', warning: 'medium', note: 'low' }[String(level).toLowerCase()] || 'low';
  }

  function toolSeverity(tool, r) {
    switch (tool) {
      case 'gitleaks': return 'high';
      case 'checkov':
        if (CHECKOV_HIGH.has(r.rule_id)) return 'high';
        return CHECKOV_MEDIUM_HINT.test(r.message) ? 'medium' : 'low';
      case 'ansible-lint': return ANSIBLE_LINT_SECURITY[r.rule_id] || null;
      case 'zizmor': return ZIZMOR_SEVERITY[r.rule_id.replace(/^zizmor\//, '')] || levelSeverity(r.level);
      case 'bandit': {
        let s = ['low', 'medium', 'high'].includes(r.severity) ? r.severity : levelSeverity(r.level);
        if (r.confidence === 'low') s = Util.lowerSeverity(s);
        return s;
      }
      default: {
        const s = ['critical', 'high', 'medium', 'low'].includes(r.severity) ? r.severity : levelSeverity(r.level);
        return s;
      }
    }
  }

  const CATEGORY_TESTS = [
    ['injection', /inject|shell|eval|exec|sql|deserial|yaml[._ -]?load|pickle|template/],
    ['supply-chain', /unpinned|mutable|pinned|supply|dependency|artipacked/],
    ['ci-cd', /trigger|pull_request_target|pull-request-target|workflow/],
    ['iam-access', /\biam\b|privilege|permission|admin|\bpolicy|\brole\b/],
    ['network-exposure', /ingress|0\.0\.0\.0|security group|\bport\b|public/],
    ['tls-crypto', /tls|ssl|cert|verif|https|encrypt|crypto|md5|sha1/],
    ['secrets', /secret|password|credential|token|private key|api key|access[_-]?key|aws/],
  ];

  // Rule ids and names are short and precise; the long message is only a fallback.
  function categoryOf(tool, r) {
    if (tool === 'gitleaks') return 'secrets';
    for (const text of [`${r.rule_id} ${r.rule_name}`, r.message]) {
      const t = String(text).toLowerCase();
      const hit = CATEGORY_TESTS.find(([, re]) => re.test(t));
      if (hit) return hit[0];
    }
    return 'misconfiguration';
  }

  function validateBundle(bundle) {
    if (!bundle || typeof bundle !== 'object' || bundle.schema !== 'secrev-scan/v1' || typeof bundle.tools !== 'object') {
      return { ok: false, error: 'not a secrev-scan/v1 bundle' };
    }
    return { ok: true };
  }

  // files: [{ filename, addedLines }] for the PR. Returns { findings, tools, counts }.
  function normalize(bundle, files) {
    const byFile = new Map(files.map((f) => [f.filename, f]));
    const findings = [];
    const tools = {};
    for (const tool of TOOLS) {
      const t = (bundle.tools || {})[tool] || {};
      const status = ['ran', 'skipped', 'error', 'timeout'].includes(t.status) ? t.status : 'missing';
      const counts = { new: 0, preexisting: 0, ignored: 0 };
      const results = Array.isArray(t.results) ? t.results.slice(0, 300) : [];
      for (const raw of results) {
        if (!raw || typeof raw !== 'object') continue;
        const r = {
          rule_id: Util.truncate(String(raw.rule_id || 'unknown'), 120),
          rule_name: Util.truncate(String(raw.rule_name || ''), 160),
          level: String(raw.level || ''),
          message: Util.truncate(Secrets.maskText(String(raw.message || '')), 300),
          file: String(raw.file || ''),
          start_line: Number.isInteger(raw.start_line) ? raw.start_line : null,
          end_line: Number.isInteger(raw.end_line) ? raw.end_line : null,
          severity: raw.severity ? String(raw.severity).toLowerCase() : null,
          confidence: raw.confidence ? String(raw.confidence).toLowerCase() : null,
          help_uri: /^https:\/\//.test(String(raw.help_uri || '')) ? String(raw.help_uri) : '',
          commit: /^[0-9a-f]{7,40}$/.test(String(raw.commit || '')) ? raw.commit : null,
        };
        const severity = toolSeverity(tool, r);
        if (!severity) { counts.ignored++; continue; }
        const file = byFile.get(r.file);
        let scope;
        if (tool === 'gitleaks') scope = file || r.commit ? 'history' : 'outside-pr';
        else if (!file) scope = 'outside-pr';
        else if (tool === 'semgrep') scope = 'changed-lines'; // already diff-aware via --baseline-commit
        else if (r.start_line && Diff.touchesAdded(file.addedLines, r.start_line, r.end_line || r.start_line)) scope = 'changed-lines';
        else scope = 'touched-file';
        if (VALID_SCOPES.includes(scope)) counts.new++; else counts.preexisting++;
        findings.push({
          tool, scope, severity, category: categoryOf(tool, r), rule: r.rule_id,
          title: Util.truncate(TITLE_FROM_MESSAGE.has(tool) || !r.rule_name ? firstSentence(r.message) : firstSentence(r.rule_name), 140),
          message: r.message,
          file: r.file, line: r.start_line, end_line: r.end_line, help_uri: r.help_uri, commit: r.commit,
        });
      }
      tools[tool] = { status, counts, total: results.length, truncated: !!t.truncated,
        error: status === 'error' || status === 'timeout' ? Util.truncate(String(t.error || ''), 200) : null,
        reason: status === 'skipped' ? Util.truncate(String(t.reason || ''), 120) : null };
    }
    return { findings, tools };
  }

  const isNew = (f) => VALID_SCOPES.includes(f.scope);

  return { validateBundle, normalize, isNew, TOOLS };
})();
