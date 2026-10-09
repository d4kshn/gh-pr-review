// Deterministic checks on added lines. They are cheap, consistent, and independent of
// both the LLM and the PR-controlled scan workflow. `floor: true` marks precise rules
// whose severity sets a minimum risk the LLM cannot talk down.
const Rules = (() => {
  const LINE_RULES = [
    // ---- Terraform
    { id: 'tf-open-ingress', domains: ['terraform'], severity: 'medium', category: 'network-exposure',
      re: /\b(cidr_blocks|ipv6_cidr_blocks|source_ranges|source_address_prefix(?:es)?|cidr_ipv4|cidr_ipv6)\s*=\s*\[?[^\n]*"(0\.0\.0\.0\/0|::\/0|\*|Internet|Any)"/i,
      title: 'Network rule open to the whole internet',
      why: 'Any service behind this rule becomes reachable from every address on the internet.',
      fix: 'Limit the source to known management, VPN or partner ranges.' },
    { id: 'tf-iam-wildcard-action', domains: ['terraform', 'json'], severity: 'high', floor: true, category: 'iam-access',
      re: /\bactions\s*=\s*\[\s*"\*(?::\*)?"\s*\]|"Action"\s*:\s*\[?\s*"\*"/,
      title: 'IAM policy allows every action',
      why: 'A wildcard action grants full administrative rights, including privilege escalation.',
      fix: 'List only the actions this principal needs.' },
    { id: 'tf-public-acl', domains: ['terraform'], severity: 'high', category: 'data-exposure',
      re: /\bacl\s*=\s*"public-read(?:-write)?"/,
      title: 'Storage made publicly readable',
      why: 'Anyone on the internet can list and read the objects.',
      fix: 'Keep the bucket private and grant access through IAM or signed URLs.' },
    { id: 'tf-public-access-setting', domains: ['terraform'], severity: 'medium', category: 'data-exposure',
      re: /\b(block_public_(?:acls|policy)|restrict_public_buckets|ignore_public_acls)\s*=\s*false\b|\b(allow_nested_items_to_be_public|public_network_access_enabled|publicly_accessible|associate_public_ip_address)\s*=\s*true\b/,
      title: 'Public access protection relaxed',
      why: 'The resource can be exposed to the internet.',
      fix: 'Keep public access blocked unless there is a documented need.' },
    { id: 'tf-tls-verify-off', domains: ['terraform'], severity: 'medium', category: 'tls-crypto',
      re: /\b(allow_unverified_ssl|insecure|skip_tls_verify|insecure_skip_verify|tls_insecure_skip_verify)\s*=\s*true\b|\b(ssl_verify|verify_ssl|tls_verify)\s*=\s*false\b/,
      title: 'TLS certificate verification disabled',
      why: 'Credentials sent to this endpoint can be intercepted by anyone able to impersonate it.',
      fix: 'Trust the internal CA (for example via a CA bundle) instead of disabling verification.' },
    { id: 'tf-encryption-off', domains: ['terraform'], severity: 'medium', category: 'tls-crypto',
      re: /\b(encrypted|storage_encrypted|encryption_enabled|enable_https_traffic_only|https_traffic_only_enabled|ssl_enforcement_enabled|kms_encrypted)\s*=\s*false\b|\bmin_tls_version\s*=\s*"(TLS1_0|TLS1_1|1\.0|1\.1)"/,
      title: 'Encryption or modern TLS turned off',
      why: 'Data at rest or in transit is no longer protected.',
      fix: 'Keep encryption enabled and require TLS 1.2 or newer.' },
    { id: 'tf-protection-off', domains: ['terraform'], severity: 'low', category: 'misconfiguration',
      re: /\b(deletion_protection|prevent_destroy)\s*=\s*false\b|\bskip_final_snapshot\s*=\s*true\b/,
      title: 'Deletion protection removed',
      why: 'An accidental apply or destroy can now remove the resource or its data.',
      fix: 'Keep deletion protection on for stateful resources.' },
    { id: 'tf-exec-provisioner', domains: ['terraform'], severity: 'low', category: 'injection',
      re: /\bprovisioner\s+"(local|remote)-exec"/,
      title: 'Exec provisioner added',
      why: 'Commands built from variables can be injected and run with the apply credentials.',
      fix: 'Prefer native resources; if needed, avoid interpolating untrusted values into the command.' },
    { id: 'tf-module-unpinned', domains: ['terraform'], severity: 'low', category: 'supply-chain',
      re: /\bsource\s*=\s*"(?:git::|github\.com\/|git@)(?![^"]*[?&]ref=)[^"]*"/,
      title: 'Terraform module source not pinned',
      why: 'The module can change underneath you on the next init.',
      fix: 'Pin the module with ?ref=<tag or commit>.' },
    { id: 'tf-logging-off', domains: ['terraform'], severity: 'low', category: 'logging',
      re: /\b(enable_logging|logging_enabled|enable_log_file_validation|flow_logs?_enabled)\s*=\s*false\b/,
      title: 'Logging disabled',
      why: 'Incidents become hard to detect and investigate.',
      fix: 'Keep logging on.' },

    // ---- Ansible
    { id: 'ans-validate-certs-off', domains: ['ansible'], severity: 'medium', category: 'tls-crypto',
      re: /\bvalidate_certs\s*[:=]\s*["']?(false|no|0)\b/i,
      title: 'Certificate validation disabled',
      why: 'Anyone who can intercept the connection can read or alter the traffic, including credentials.',
      fix: 'Point the task at the internal CA bundle (ca_path/ca_cert) instead of disabling validation.' },
    { id: 'ans-host-key-checking-off', domains: ['ansible', 'config', 'shell', 'ci'], severity: 'medium', category: 'tls-crypto',
      re: /\bhost_key_checking\s*[:=]\s*(false|no|0)\b|StrictHostKeyChecking[=\s]+no\b|ANSIBLE_HOST_KEY_CHECKING\s*[:=]\s*["']?(false|0)\b/i,
      title: 'SSH host key checking disabled',
      why: 'Connections can be silently redirected to an impersonating host.',
      fix: 'Distribute known_hosts entries and keep host key checking on.' },
    { id: 'ans-templated-shell', domains: ['ansible'], severity: 'medium', category: 'injection',
      re: /\b(?:ansible\.builtin\.|ansible\.legacy\.)?(shell|command|raw)\s*:.*\{\{(?![^}]*\|\s*quote)/,
      title: 'Shell command built from variables',
      why: 'Variable values are interpreted by the shell, so crafted inventory or fact values can inject commands.',
      fix: 'Use a dedicated module, or pass values through the | quote filter.' },
    { id: 'curl-pipe-shell', domains: ['ansible', 'shell', 'docker', 'ci', 'python'], severity: 'medium', category: 'supply-chain',
      re: /\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|k)?sh\b/,
      title: 'Remote script piped into a shell',
      why: 'Whatever the server returns runs with full privileges, with no integrity check.',
      fix: 'Download, verify a checksum or signature, then run.' },
    { id: 'world-writable-mode', domains: ['ansible'], severity: 'medium', category: 'misconfiguration',
      re: /\bmode\s*[:=]\s*["']?0?[0-7]{2}[2367]["']?\s*$|\bmode\s*[:=]\s*["']?[ugoa]*[ao][+=]r?w/,
      title: 'World-writable file permissions',
      why: 'Any local user can modify the file, which often leads to privilege escalation.',
      fix: 'Use the narrowest mode that works, such as 0640 or 0644.' },
    { id: 'ans-security-disabled', domains: ['ansible'], severity: 'medium', category: 'misconfiguration',
      re: /\b(selinux|firewalld|ufw|apparmor|auditd|iptables)\b.*\b(state\s*[:=]\s*["']?(disabled|stopped|absent)|enabled\s*[:=]\s*["']?(false|no))\b/i,
      title: 'Host security control disabled',
      why: 'Disabling SELinux, the firewall or auditing removes a layer of defence on every targeted host.',
      fix: 'Adjust the policy or rules instead of turning the control off.' },
    { id: 'insecure-download', domains: ['ansible'], severity: 'low', category: 'supply-chain',
      re: /\b(url|src)\s*:\s*["']?http:\/\/(?!localhost|127\.0\.0\.1)/,
      title: 'Download over plain HTTP',
      why: 'The content can be tampered with in transit.',
      fix: 'Use HTTPS and verify a checksum.' },
    { id: 'snmp-v1-v2c', domains: ['ansible', 'config'], severity: 'low', category: 'tls-crypto',
      re: /\bsnmp[_-]?(version|ver)\s*[:=]\s*["']?(1|2c|v1|v2c)["']?\s*$/i,
      title: 'SNMP v1/v2c in use',
      why: 'Community strings travel in clear text and give read (or write) access to devices.',
      fix: 'Prefer SNMPv3 with authPriv.' },
    { id: 'snmp-default-community', domains: ['ansible', 'config', 'terraform', 'python'], severity: 'medium', floor: true, category: 'secrets',
      re: /\bcommunity(?:[_-]?string)?\b["']?\s*[:=]\s*["']?(public|private)["']?\s*,?\s*$/i,
      title: 'Default SNMP community string',
      why: '"public" and "private" are the first values anyone tries.',
      fix: 'Use a unique community stored in Ansible Vault, or move to SNMPv3.' },

    // ---- Python
    { id: 'py-shell-true', domains: ['python'], severity: 'medium', category: 'injection',
      re: /\bshell\s*=\s*True\b/,
      title: 'Subprocess with shell=True',
      why: 'Values in the command string are interpreted by the shell and can inject commands.',
      fix: 'Pass an argument list and leave shell=False.' },
    { id: 'py-os-system', domains: ['python'], severity: 'medium', category: 'injection',
      re: /\bos\.(system|popen)\s*\(/,
      title: 'os.system / os.popen',
      why: 'The command runs through the shell.',
      fix: 'Use subprocess with an argument list.' },
    { id: 'py-eval', domains: ['python'], severity: 'high', category: 'injection',
      re: /(?<![\w.])(eval|exec)\s*\(/,
      title: 'eval/exec on dynamic input',
      why: 'Arbitrary code runs if the input is attacker-influenced.',
      fix: 'Parse the value explicitly (for example ast.literal_eval or a small expression parser).' },
    { id: 'py-unsafe-deserialization', domains: ['python'], severity: 'medium', category: 'injection',
      re: /\b(pickle|cPickle|dill|shelve|marshal)\.loads?\s*\(|\byaml\.unsafe_load\s*\(|\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?C?SafeLoader)/,
      title: 'Unsafe deserialization',
      why: 'Loading untrusted data can execute code.',
      fix: 'Use yaml.safe_load or a data-only format such as JSON.' },
    { id: 'py-tls-verify-off', domains: ['python'], severity: 'medium', category: 'tls-crypto',
      re: /\bverify\s*=\s*False\b|_create_unverified_context|\bCERT_NONE\b|\bcheck_hostname\s*=\s*False\b/,
      title: 'TLS verification disabled',
      why: 'Traffic, including tokens, can be intercepted.',
      fix: 'Pass the internal CA bundle via verify="/path/ca.pem".' },
    { id: 'py-sql-string', domains: ['python'], severity: 'high', category: 'injection',
      re: /\.(execute|executemany|raw|exec_driver_sql)\s*\(\s*(f["']|["'][^"']*["']\s*(%|\.format\s*\()|[A-Za-z_][A-Za-z0-9_]*\s*\+)/,
      title: 'SQL built from strings',
      why: 'Values concatenated into SQL allow injection.',
      fix: 'Use parameterized queries.' },
    { id: 'py-ssh-autoadd', domains: ['python'], severity: 'medium', category: 'tls-crypto',
      re: /\b(AutoAddPolicy|WarningPolicy)\s*\(/,
      title: 'SSH host keys accepted blindly',
      why: 'The client will talk to any host that answers, including an impostor.',
      fix: 'Load known hosts and use RejectPolicy.' },
    { id: 'py-debug-mode', domains: ['python'], severity: 'medium', category: 'misconfiguration',
      re: /\.run\([^)]*\bdebug\s*=\s*True|^\s*DEBUG\s*=\s*True\b/,
      title: 'Debug mode enabled',
      why: 'Debug servers can expose an interactive console or stack traces.',
      fix: 'Drive debug mode from configuration and keep it off in deployments.' },
    { id: 'py-jwt-no-verify', domains: ['python'], severity: 'high', category: 'auth',
      re: /["']verify_signature["']\s*:\s*False|algorithms\s*=\s*\[\s*["']none["']/i,
      title: 'JWT signature not verified',
      why: 'Anyone can forge tokens.',
      fix: 'Verify signatures with an explicit algorithm list.' },
    { id: 'py-weak-hash', domains: ['python'], severity: 'low', category: 'tls-crypto',
      re: /\bhashlib\.(md5|sha1)\s*\((?![^)]*usedforsecurity\s*=\s*False)/,
      title: 'MD5/SHA-1 hash',
      why: 'Unsafe if used for passwords, signatures or integrity.',
      fix: 'Use SHA-256 or a password hash such as bcrypt/argon2.' },

    // ---- Frontend (chatbot UI)
    { id: 'fe-raw-html', domains: ['frontend'], severity: 'medium', category: 'injection',
      re: /dangerouslySetInnerHTML|\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(|\bv-html\s*=|\{@html\s/,
      title: 'Raw HTML rendering',
      why: 'If the content comes from users or an LLM answer, injected HTML/JS runs in the user\'s session (XSS).',
      fix: 'Render text, or sanitize with DOMPurify before inserting HTML.' },
    { id: 'fe-eval', domains: ['frontend'], severity: 'high', category: 'injection',
      re: /(?<![\w.])eval\s*\(|new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*["'`]/,
      title: 'Dynamic code execution in the browser',
      why: 'Attacker-influenced strings become code.',
      fix: 'Avoid eval/new Function.' },
    { id: 'fe-public-secret-env', domains: ['frontend'], severity: 'high', floor: true, category: 'secrets',
      re: /\b(VITE|NEXT_PUBLIC|REACT_APP|NUXT_PUBLIC|PUBLIC|EXPO_PUBLIC|GATSBY)_[A-Z0-9_]*(SECRET|TOKEN|API_?KEY|PASSWORD|PASS|PRIVATE|CLIENT_SECRET)[A-Z0-9_]*\b/,
      title: 'Secret exposed through a public build variable',
      why: 'Variables with this prefix are compiled into the JavaScript bundle that every visitor downloads.',
      fix: 'Keep the key server-side (for example in n8n) and call it through an authenticated backend endpoint.' },
    { id: 'fe-token-in-storage', domains: ['frontend'], severity: 'low', category: 'auth',
      re: /(localStorage|sessionStorage)\.setItem\(\s*["'`][^"'`]*(token|jwt|auth|secret|password)/i,
      title: 'Token kept in web storage',
      why: 'Any XSS can read it.',
      fix: 'Prefer HttpOnly, Secure cookies for session tokens.' },
    { id: 'fe-postmessage-wildcard', domains: ['frontend'], severity: 'medium', category: 'data-exposure',
      re: /postMessage\([^)]*,\s*["'`]\*["'`]\s*\)/,
      title: 'postMessage to any origin',
      why: 'Any embedding page can receive the message.',
      fix: 'Pass the exact target origin.' },
    { id: 'cors-wildcard', domains: ['frontend', 'python', 'config', 'terraform'], severity: 'medium', category: 'misconfiguration',
      re: /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|allow_origins\s*=\s*\[\s*["']\*["']\s*\]|\borigin\s*:\s*["']\*["']|CORS_ALLOW_ALL_ORIGINS\s*=\s*True/,
      title: 'CORS allows any origin',
      why: 'Any website can call this endpoint from a visitor\'s browser.',
      fix: 'List the allowed origins explicitly.' },
    { id: 'n8n-test-webhook-url', domains: ['frontend', 'python', 'config', 'shell', 'json', 'other'], severity: 'medium', category: 'misconfiguration',
      re: /\/webhook-test\/[A-Za-z0-9_-]+/,
      title: 'n8n test webhook URL in code',
      why: 'Test URLs only work while someone has the editor open, and point at unpublished workflow drafts.',
      fix: 'Use the production /webhook/ URL with authentication.' },
    { id: 'fe-markdown-raw-html', domains: ['frontend'], severity: 'medium', category: 'injection',
      re: /\b(rehype-raw|rehypeRaw)\b|\bsanitize\s*:\s*false\b|\bdisableSanitizer\b/,
      title: 'Markdown rendered with raw HTML allowed',
      why: 'LLM answers or user text can carry HTML/JS into the page.',
      fix: 'Keep raw HTML disabled or sanitize the output.' },
    { id: 'fe-install-script', domains: ['frontend'], severity: 'low', category: 'supply-chain',
      re: /"(pre|post)?install"\s*:/,
      title: 'npm install script added',
      why: 'Install scripts run on every developer machine and CI runner that installs the package.',
      fix: 'Make sure the script is necessary and reviewed.' },

    // ---- CI/CD
    { id: 'ci-pull-request-target', domains: ['ci'], severity: 'medium', category: 'ci-cd',
      re: /\bpull_request_target\b/,
      title: 'pull_request_target trigger',
      why: 'The workflow runs with repository secrets and a write token for PRs, including from forks.',
      fix: 'Use pull_request unless you need write access, and never check out PR code in this context.' },
    { id: 'ci-script-injection', domains: ['ci'], severity: 'high', floor: true, category: 'injection', skipLine: /^\s*(-\s*)?if\s*:/,
      re: /\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|review_comment|discussion|discussion_comment|pages|commits|head_commit|workflow_run)\.[A-Za-z0-9_.[\]*]*(?:title|body|label|message|name|ref|email|head_branch|default_branch|page_name)|head_ref)\b[^}]*\}\}/,
      title: 'Untrusted event data interpolated into a workflow',
      why: 'PR titles, branch names and comments are attacker-controlled; interpolated into run: they execute as shell code.',
      fix: 'Pass the value through an env: variable and quote it in the script.' },
    { id: 'ci-unpinned-action', domains: ['ci'], severity: 'low', category: 'supply-chain',
      re: /\buses\s*:\s*["']?(?!\.\/|docker:\/\/)[^@\s"']+@(?![0-9a-f]{40}\b)[^\s"'#]+/,
      title: 'Action not pinned to a commit SHA',
      why: 'A moved tag can swap in different code with access to the job\'s token and secrets.',
      fix: 'Pin to a full commit SHA and note the version in a comment.' },
    { id: 'ci-write-all', domains: ['ci'], severity: 'medium', category: 'ci-cd',
      re: /\bpermissions\s*:\s*write-all\b/,
      title: 'Workflow token has write-all permissions',
      why: 'Any compromised step can push code or tamper with releases.',
      fix: 'Grant only the scopes the job needs.' },
    { id: 'ci-secret-echo', domains: ['ci'], severity: 'medium', category: 'secrets',
      re: /\b(echo|printf|cat)\b[^\n]*\$\{\{\s*secrets\./,
      title: 'Secret written to the log or a file',
      why: 'Masking is best effort; transformed values leak.',
      fix: 'Pass secrets through env: and avoid printing them.' },
    { id: 'ci-checkout-pr-head', domains: ['ci'], severity: 'high', floor: true, category: 'ci-cd', fileRequires: /pull_request_target/,
      re: /\bref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}/,
      title: 'PR code checked out in a privileged workflow',
      why: 'With pull_request_target, PR code runs with secrets and a write token (a "pwn request").',
      fix: 'Do not check out PR code under pull_request_target; split into an unprivileged pull_request workflow.' },

    // ---- Containers and shell
    { id: 'privileged-container', domains: ['docker', 'ci', 'ansible', 'terraform'], severity: 'medium', category: 'misconfiguration',
      re: /\bprivileged\s*[:=]\s*true\b|--privileged\b/,
      title: 'Privileged container',
      why: 'A privileged container can take over its host.',
      fix: 'Grant only the capabilities required.' },
    { id: 'docker-secret-arg', domains: ['docker'], severity: 'medium', category: 'secrets',
      re: /^\s*(ARG|ENV)\s+[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)[A-Z0-9_]*(\s*=|\s+)\S+/i,
      title: 'Secret baked into the image',
      why: 'ARG/ENV values are stored in image layers and history.',
      fix: 'Use build secrets (--mount=type=secret) or runtime injection.' },
    { id: 'chmod-777', domains: ['shell', 'docker', 'ansible', 'ci'], severity: 'medium', category: 'misconfiguration',
      re: /\bchmod\s+(-R\s+)?(0?777|a\+w|o\+w)\b/,
      title: 'chmod 777',
      why: 'Everyone can modify the target.',
      fix: 'Use the narrowest permissions that work.' },

    // ---- Any file
    { id: 'scanner-suppression', domains: ['*'], severity: 'info', category: 'other',
      re: /#\s*nosec\b|nosemgrep|checkov:skip=|gitleaks:allow|#\s*noqa:\s*S\d+|tfsec:ignore|trivy:ignore|zizmor:\s*ignore/i,
      title: 'Scanner finding suppressed inline',
      why: 'A suppression hides an issue from scanners; make sure it is justified.',
      fix: 'Keep a short justification next to the suppression.' },
    { id: 'prompt-injection-text', domains: ['*'], severity: 'medium', floor: true, category: 'prompt-injection',
      re: /\b(ignore|disregard|forget|override)\b[^\n]{0,40}\b(previous|prior|above|earlier|all)\b[^\n]{0,40}\b(instructions?|prompts?|rules|guidelines)\b|\b(AI|LLM|automated|bot)\s+(code\s+)?review(er|ers)?\b[^\n]{0,80}\b(approve|clean|no\s+findings|safe|skip)\b/i,
      title: 'Text addressed to AI reviewers',
      why: 'Instructions aimed at automated reviewers are a prompt-injection attempt; the change deserves a human look.',
      fix: 'Remove the text and review the change manually.' },
  ];

  function checkFileLevel(file) {
    const out = [];
    const added = file.status !== 'removed';
    if (!added) return out;
    const path = file.filename;
    if (/\.tfstate(\.backup)?$/i.test(path)) {
      out.push({ rule: 'tf-state-committed', severity: 'critical', floor: true, category: 'secrets', line: null,
        title: 'Terraform state committed',
        why: 'State files contain resource attributes in clear text, often including passwords and keys.',
        fix: 'Remove the file, rewrite history if it was pushed, rotate any secrets it contains, and use a remote backend.' });
    }
    if (/\.(pem|key|p12|pfx|jks|keystore|ppk)$|(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/i.test(path)) {
      const patch = String(file.patch || '');
      const certOnly = patch && /BEGIN CERTIFICATE/.test(patch) && !/PRIVATE KEY/.test(patch);
      if (!certOnly) {
        out.push({ rule: 'private-key-file', severity: patch ? 'critical' : 'high', floor: true, category: 'secrets', line: null,
          title: patch ? 'Private key file committed' : 'Possible private key or keystore committed',
          why: 'Anyone with repository access can use the key.',
          fix: 'Remove it, revoke and replace the key, and keep keys in a vault.' });
      }
    }
    if (/(^|\/)\.env(\.[^/]+)?$/.test(path) && !/\.(example|sample|template|dist|defaults)$/.test(path)) {
      out.push({ rule: 'env-file-committed', severity: 'medium', floor: true, category: 'secrets', line: null,
        title: '.env file committed',
        why: 'Environment files usually hold real credentials.',
        fix: 'Commit a .env.example with placeholders and add .env to .gitignore.' });
    }
    return out;
  }

  // Apply rules and secret patterns to one file's added lines.
  function checkFile(file, addedLines) {
    const findings = [];
    const testPath = Util.isTestPath(file.filename);
    const fileText = String(file.patch || '');
    for (const f of checkFileLevel(file)) findings.push({ ...f, file: file.filename, evidence: '' });

    for (const { line, text } of addedLines) {
      for (const hit of Secrets.scanText(text)) {
        findings.push({
          rule: 'secret:' + hit.id, severity: hit.severity, floor: Util.sevRank(hit.severity) >= Util.sevRank('high'),
          category: 'secrets', file: file.filename, line,
          title: hit.title + ' in plain text',
          evidence: Util.truncate(Secrets.maskText(text).trim(), 160),
          why: 'Anyone with read access to the repository (and its history) can use it.',
          fix: 'Remove it, rotate the credential (it stays in git history), and load it from a vault or CI secret instead.',
        });
      }
      for (const r of LINE_RULES) {
        if (!r.domains.includes('*') && !r.domains.includes(file.domain)) continue;
        if (r.fileRequires && !r.fileRequires.test(fileText)) continue;
        if (r.skipLine && r.skipLine.test(text)) continue;
        if (!r.re.test(text)) continue;
        findings.push({
          rule: r.id, severity: r.severity, floor: !!r.floor, category: r.category, file: file.filename, line,
          title: r.title, evidence: Util.truncate(Secrets.maskText(text).trim(), 160), why: r.why, fix: r.fix,
        });
      }
    }
    if (testPath) {
      for (const f of findings) {
        f.severity = Util.lowerSeverity(f.severity);
        f.floor = f.floor && Util.sevRank(f.severity) >= Util.sevRank('high');
        f.note = 'in a test/example path';
      }
    }
    return findings;
  }

  return { checkFile, LINE_RULES };
})();
