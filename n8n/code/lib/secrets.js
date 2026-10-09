// Secret detection and masking. Runs on added lines before anything reaches the LLM
// or the PR comment, so found values are never repeated in full.
const Secrets = (() => {
  // `group` is the capture group holding the secret value (0 = whole match).
  // `checkValue` applies the placeholder and entropy filters below.
  const PATTERNS = [
    { id: 'private-key', title: 'Private key', severity: 'critical', group: 0,
      re: /-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----/g },
    { id: 'aws-access-key-id', title: 'AWS access key ID', severity: 'high', group: 1,
      re: /\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b/g },
    { id: 'aws-secret-access-key', title: 'AWS secret access key', severity: 'critical', group: 1,
      re: /(?:aws_?secret_?access_?key|aws_?secret_?key|secret_?access_?key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi },
    { id: 'github-token', title: 'GitHub token', severity: 'critical', group: 1,
      re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g },
    { id: 'slack-token', title: 'Slack token', severity: 'high', group: 1,
      re: /\b(xox[abposr]-[A-Za-z0-9-]{10,})\b/g },
    { id: 'chat-webhook-url', title: 'Slack/Teams/Power Automate webhook URL', severity: 'high', group: 1,
      re: /(https:\/\/(?:hooks\.slack\.com\/services\/[A-Za-z0-9/]+|[a-z0-9.-]+\.webhook\.office\.com\/webhookb2\/[^\s"'<>]+|[a-z0-9.-]+\.logic\.azure\.com(?::443)?\/workflows\/[^\s"'<>]*sig=[^\s"'<>&]+))/gi },
    { id: 'azure-storage-key', title: 'Azure storage account key', severity: 'critical', group: 1,
      re: /AccountKey=([A-Za-z0-9+/=]{60,})/g },
    { id: 'azure-sas-token', title: 'Azure SAS token', severity: 'high', group: 1,
      re: /[?&]sig=([A-Za-z0-9%+/=]{30,})/g },
    { id: 'google-api-key', title: 'Google API key', severity: 'high', group: 1,
      re: /\b(AIza[0-9A-Za-z_-]{35})\b/g },
    { id: 'openai-api-key', title: 'OpenAI API key', severity: 'critical', group: 1,
      re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})\b/g },
    { id: 'anthropic-api-key', title: 'Anthropic API key', severity: 'critical', group: 1,
      re: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g },
    { id: 'grafana-token', title: 'Grafana token', severity: 'high', group: 1,
      re: /\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}|glc_[A-Za-z0-9+/=]{32,}|eyJrIjoi[A-Za-z0-9+/=]{20,})/g },
    { id: 'npm-token', title: 'npm token', severity: 'high', group: 1,
      re: /\b(npm_[A-Za-z0-9]{36})\b/g },
    { id: 'jwt', title: 'JSON Web Token', severity: 'medium', group: 1,
      re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g },
    { id: 'url-credentials', title: 'Password in URL', severity: 'high', group: 1, checkValue: true,
      re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@"']+:([^\s/@"']{3,})@[^\s"']+/gi },
    { id: 'network-device-password', title: 'Plaintext network device password', severity: 'high', group: 1, checkValue: true,
      re: /\b(?:enable\s+(?:secret|password)|username\s+\S+\s+(?:secret|password))\s+(?:[07]\s+)?(\S{4,})/gi },
    { id: 'snmp-community', title: 'SNMP community string', severity: 'high', group: 1, checkValue: true,
      re: /\b(?:snmp[_-]?)?(?:ro[_-]|rw[_-])?community(?:[_-]?string)?\b["']?\s*[:=]\s*["']?([^\s"'#,}]{3,})/gi },
    { id: 'snmp-community', title: 'SNMP community string', severity: 'high', group: 1, checkValue: true,
      re: /\bsnmp-server\s+community\s+(\S+)/gi },
    { id: 'ansible-plaintext-password', title: 'Plaintext Ansible password', severity: 'high', group: 1, checkValue: true,
      re: /\bansible_(?:ssh_|become_)?pass(?:word)?\s*[:=]\s*["']?([^\s"'{}$!][^\s"']{2,})/g },
    { id: 'bearer-token', title: 'Hard-coded bearer token', severity: 'high', group: 1, checkValue: true,
      re: /\bBearer\s+([A-Za-z0-9._~+/-]{16,}=*)/g },
    // Generic name = "value" (code, JSON, quoted YAML).
    { id: 'generic-secret', title: 'Hard-coded secret', severity: 'medium', group: 2, checkValue: true, minEntropy: 2.5,
      re: /\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']([^"'\s]{6,})["']/gi },
    // Unquoted YAML: name: value
    { id: 'generic-secret', title: 'Hard-coded secret', severity: 'medium', group: 2, checkValue: true, minEntropy: 2.5,
      re: /^\s*-?\s*([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token)[A-Za-z0-9_.-]*)\s*:\s*([^\s"'#{|>&*!][^\s#]{5,})\s*$/gim },
    // Unquoted env files and shell: NAME=value
    { id: 'generic-secret', title: 'Hard-coded secret', severity: 'medium', group: 2, checkValue: true, minEntropy: 2.5,
      re: /^\s*(?:export\s+)?([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CLIENT_?SECRET)[A-Z0-9_]*)\s*=\s*([^\s"'$#][^\s#]{5,})\s*$/gm },
  ];

  // Values that are references, templates or obvious placeholders, not secrets.
  const PLACEHOLDER = /^(?:\{\{|\$\{|\$[A-Za-z_(]|%[A-Za-z_]|<[^>]*>?$|\*{3,}|x{3,}|\.{3}|!vault|vault_|ENC\[|lookup\(|var\.|local\.|data\.|module\.|os\.environ|getenv|process\.env|env\(|secrets\.|\(|https?:\/\/|\/|\.\/|~\/)|^(?:changeme|change_me|change-me|replace_?me|example|dummy|sample|placeholder|password|passw0rd|secret|token|null|none|nil|true|false|undefined|todo|tbd|redacted|test|testing|fake|foobar|admin|public|private|string|value|your[_-].*|my[_-].*)$/i;
  const NAME_NOT_SECRET = /(_file|_path|_dir|_url|_uri|_name|_id|_type|_length|_size|_count|_policy|_expiry|_expires|_ttl|_header|_field|_key_name|_mode|_format)$/i;

  function isPlaceholder(value) {
    const v = String(value || '').trim();
    // '…[' marks a value this module already masked, so masking twice is a no-op.
    return !v || PLACEHOLDER.test(v) || v.includes('{{') || v.includes('${') || v.includes('…[');
  }

  // Scan one line (or any text). Returns [{id, title, severity, value, index}].
  function scanText(text) {
    const s = String(text || '');
    const hits = [];
    for (const p of PATTERNS) {
      p.re.lastIndex = 0;
      let m;
      while ((m = p.re.exec(s)) !== null) {
        if (m[0] === '') { p.re.lastIndex++; continue; }
        const value = p.group === 0 ? m[0] : (m[p.group] ?? m[0]);
        if (p.checkValue && isPlaceholder(value)) continue;
        if (p.id === 'generic-secret' && NAME_NOT_SECRET.test(m[1] || '')) continue;
        if (p.minEntropy && Util.entropy(value) < p.minEntropy) continue;
        hits.push({ id: p.id, title: p.title, severity: p.severity, value, index: m.index + m[0].indexOf(value) });
      }
    }
    // Keep the most specific hit when several patterns overlap the same value.
    hits.sort((a, b) => a.index - b.index || Util.sevRank(b.severity) - Util.sevRank(a.severity));
    const kept = [];
    for (const h of hits) {
      const overlap = kept.find((k) => h.index < k.index + k.value.length && k.index < h.index + h.value.length);
      if (!overlap) kept.push(h);
    }
    return kept;
  }

  function mask(value) {
    const v = String(value || '');
    if (v.startsWith('-----BEGIN')) return '[private key]';
    if (v.length <= 8) return '*'.repeat(v.length);
    return v.slice(0, 4) + '…[' + v.length + ' chars]';
  }

  // Replace every detected secret value in text with its masked form.
  function maskText(text) {
    let out = String(text || '');
    const hits = scanText(out).sort((a, b) => b.index - a.index);
    for (const h of hits) {
      out = out.slice(0, h.index) + mask(h.value) + out.slice(h.index + h.value.length);
    }
    return out;
  }

  return { scanText, mask, maskText, isPlaceholder, PATTERNS };
})();
