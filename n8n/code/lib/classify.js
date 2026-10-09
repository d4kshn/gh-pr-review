// File classification: domain, priority, and what must never be sent to the LLM.
const Classify = (() => {
  const LOCKFILE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|uv\.lock|\.terraform\.lock\.hcl|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock)$/;
  const BINARY = /\.(png|jpe?g|gif|ico|webp|bmp|tiff?|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|ear|class|exe|dll|so|dylib|bin|o|a|woff2?|ttf|otf|eot|mp[34]|wav|mov|avi|mkv|db|sqlite3?|pyc|whl)$/i;
  const PRIVATE_KEY_FILE = /\.(pem|key|p12|pfx|jks|keystore|ppk)$|(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/i;
  const TFSTATE = /\.tfstate(\.backup)?$/i;
  const ENV_FILE = /(^|\/)\.env(\.[^/]+)?$/;
  const ENV_TEMPLATE = /(^|\/)\.env\.(example|sample|template|dist|defaults)$/;
  const NON_WORKFLOW_JSON = /(^|\/)(package(-lock)?\.json|tsconfig[^/]*\.json|jsconfig\.json|composer\.json|\.?eslintrc[^/]*\.json|\.prettierrc[^/]*\.json|renovate\.json|launch\.json|settings\.json|extensions\.json|[^/]*\.schema\.json|manifest\.json|turbo\.json|nx\.json|lerna\.json|vercel\.json|firebase\.json|app\.json|\.babelrc(\.json)?)$/;

  // Files whose change deserves a mention even when nothing looks wrong.
  const SENSITIVE = [
    { re: /^\.github\/workflows\/secrev-scan\.ya?ml$/, why: 'secrev scan workflow' },
    { re: /(^|\/)\.secrev\.ya?ml$/, why: 'secrev configuration' },
    { re: /(^|\/)(\.gitleaks\.toml|\.gitleaksignore|\.semgrepignore|\.semgrep\.ya?ml|\.checkov\.ya?ml|\.bandit|\.ansible-lint|\.config\/ansible-lint\.ya?ml|zizmor\.ya?ml)$/, why: 'scanner configuration or suppression' },
    { re: /^\.github\/(workflows|actions)\//, why: 'CI/CD pipeline' },
    { re: /(^|\/)CODEOWNERS$/, why: 'code ownership rules' },
    { re: /(^|\/)ansible\.cfg$/, why: 'Ansible defaults' },
    { re: /(^|\/)(backend|providers?|versions)\.tf$/, why: 'Terraform backend/providers' },
    { re: /(^|\/)\.npmrc$|(^|\/)pip\.conf$|(^|\/)\.pypirc$/, why: 'package registry configuration' },
    { re: /(^|\/)Dockerfile[^/]*$/, why: 'container build' },
  ];

  const PRIORITY = {
    ci: 100, terraform: 90, ansible: 90, n8n: 88, docker: 80, shell: 75, python: 70,
    frontend: 65, config: 55, json: 50, other: 40, docs: 10, lockfile: 5, binary: 0,
  };

  function domainOf(path) {
    if (LOCKFILE.test(path)) return 'lockfile';
    if (BINARY.test(path)) return 'binary';
    if (/^\.github\/(workflows|actions)\/.+\.ya?ml$/.test(path) || /(^|\/)(\.gitlab-ci\.yml|Jenkinsfile|azure-pipelines\.ya?ml)$/.test(path)) return 'ci';
    if (/\.(tf|tfvars|hcl)$|\.tf\.json$/.test(path)) return 'terraform';
    if (/(^|\/)(roles|playbooks|group_vars|host_vars|inventory|inventories|tasks|handlers|vars|defaults)\/.+\.ya?ml$/.test(path) ||
        /(^|\/)(site|playbook[^/]*)\.ya?ml$|(^|\/)ansible\.cfg$|(^|\/)(requirements|galaxy)\.ya?ml$/.test(path) ||
        /(^|\/)inventor(y|ies)\/[^/]+\.(ini|cfg)$|(^|\/)hosts(\.ini)?$/.test(path)) return 'ansible';
    if (/\.py$|(^|\/)(requirements[^/]*\.txt|pyproject\.toml|setup\.(py|cfg)|Pipfile)$/.test(path)) return 'python';
    if (/\.(jsx?|mjs|cjs|tsx?|vue|svelte|html?|svg)$|(^|\/)(package\.json|vite\.config\.[cm]?[jt]s|next\.config\.[cm]?[jt]s|\.npmrc)$/.test(path) || ENV_FILE.test(path)) return 'frontend';
    if (/(^|\/)Dockerfile[^/]*$|\.dockerfile$|(^|\/)(docker-)?compose[^/]*\.ya?ml$/.test(path)) return 'docker';
    if (/\.(sh|bash|zsh|ps1)$/.test(path)) return 'shell';
    if (/\.json$/.test(path)) return 'json';
    if (/\.(md|rst|adoc|txt)$|(^|\/)(LICENSE|CHANGELOG|AUTHORS|NOTICE)(\.[a-z]+)?$|(^|\/)docs?\//i.test(path)) return 'docs';
    if (/\.(ya?ml|toml|ini|cfg|conf|properties|j2|xml)$/.test(path)) return 'config';
    return 'other';
  }

  // Never sent to the LLM; rules flag them instead. Returns a reason or null.
  function neverSendReason(path, extraGlobs) {
    if (PRIVATE_KEY_FILE.test(path)) return 'private key or certificate store';
    if (TFSTATE.test(path)) return 'Terraform state';
    if (ENV_FILE.test(path) && !ENV_TEMPLATE.test(path)) return 'environment file';
    if (LOCKFILE.test(path)) return 'lockfile';
    if (BINARY.test(path)) return 'binary file';
    if (Util.matchesAny(path, extraGlobs)) return 'excluded by llm_exclude_paths';
    return null;
  }

  const isVaultEncrypted = (patch) => /^\+?\$ANSIBLE_VAULT;\d/m.test(String(patch || ''));

  function sensitiveReason(path) {
    const hit = SENSITIVE.find((s) => s.re.test(path));
    return hit ? hit.why : null;
  }

  // JSON files worth fetching to check whether they are n8n workflows.
  function isWorkflowCandidate(file) {
    if (!/\.json$/i.test(file.filename) || NON_WORKFLOW_JSON.test(file.filename)) return false;
    if (file.status === 'removed') return false;
    if (file.patch && !/"(nodes|connections|type)"\s*:/.test(file.patch)) return /workflow/i.test(file.filename);
    return true;
  }

  const looksLikeWorkflow = (obj) =>
    !!obj && typeof obj === 'object' && Array.isArray(obj.nodes) &&
    obj.connections && typeof obj.connections === 'object' &&
    obj.nodes.every((n) => n && typeof n.type === 'string');

  function priorityOf(file) {
    let p = PRIORITY[file.domain] ?? 40;
    if (Util.isTestPath(file.filename)) p -= 30;
    if (file.sensitive) p += 5;
    return p;
  }

  return {
    domainOf, neverSendReason, isVaultEncrypted, sensitiveReason, isWorkflowCandidate,
    looksLikeWorkflow, priorityOf, PRIORITY,
  };
})();
