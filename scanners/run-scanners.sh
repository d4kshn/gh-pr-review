#!/usr/bin/env bash
# secrev scanner runner.
#
# Runs inside the reusable GitHub Actions workflow (embedded by scripts/build.py) and
# locally in tests. It never fails the job: every tool runs report-only, and problems
# are recorded per tool in the bundle that n8n reads.
#
# Required env: BASE_SHA, HEAD_SHA, OUT_DIR
# Optional env: SECREV_DIR (configs; default: this script's dir), SECREV_INSTALL=1 (CI),
#               SECREV_TMP, TOOL_TIMEOUT (seconds), GH_TOKEN (zizmor online audits),
#               SECREV_REPO, SECREV_PR, SECREV_RUN_ID, SECREV_RUN_ATTEMPT (bundle metadata)
set -uo pipefail

: "${BASE_SHA:?BASE_SHA is required}" "${HEAD_SHA:?HEAD_SHA is required}" "${OUT_DIR:?OUT_DIR is required}"
SECREV_DIR="${SECREV_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
SECREV_TMP="${SECREV_TMP:-${RUNNER_TEMP:-/tmp}/secrev-work}"
SECREV_INSTALL="${SECREV_INSTALL:-0}"
TOOL_TIMEOUT="${TOOL_TIMEOUT:-300}"
MAX_DIRS=10
MAX_FILES=200

set -a
# shellcheck disable=SC1091  # sourced at runtime from SECREV_DIR
. "$SECREV_DIR/versions.env"
set +a
mkdir -p "$OUT_DIR" "$SECREV_TMP"
log() { printf '[secrev] %s\n' "$*" >&2; }

# ---------------------------------------------------------------- changed files
CHANGED="$SECREV_TMP/changed.txt"
if ! git diff --name-only --diff-filter=ACMR "$BASE_SHA...$HEAD_SHA" > "$CHANGED" 2> "$SECREV_TMP/git-diff.log"; then
  log "git diff failed (is the history fetched?): $(head -c 300 "$SECREV_TMP/git-diff.log")"
  : > "$CHANGED"
fi
log "changed files: $(wc -l < "$CHANGED")"

matching() { grep -E "$1" "$CHANGED" | head -n "$MAX_FILES" || true; }
TF_FILES=$(matching '\.(tf|tfvars|hcl)$|\.tf\.json$')
PY_FILES=$(matching '\.py$')
JS_FILES=$(matching '\.(js|jsx|mjs|cjs|ts|tsx|vue|svelte)$')
GHA_FILES=$(matching '^\.github/(workflows|actions)/.*\.ya?ml$')
DOCKER_FILES=$(matching '(^|/)Dockerfile[^/]*$|\.dockerfile$')
ANSIBLE_FILES=$(matching '(^|/)(roles|playbooks|group_vars|host_vars|inventory|inventories|tasks|handlers)/.*\.ya?ml$|(^|/)(site|main|playbook[^/]*)\.ya?ml$|(^|/)ansible\.cfg$')
# A YAML file only counts as Ansible when the repo looks like an Ansible project.
if [ -n "$ANSIBLE_FILES" ] && ! { [ -f ansible.cfg ] || [ -d roles ] || [ -d playbooks ] || [ -d group_vars ] \
    || [ -d inventory ] || [ -d inventories ] || ls ./*playbook*.yml ./site.yml >/dev/null 2>&1; }; then
  ANSIBLE_FILES=""
fi

domains=()
[ -n "$TF_FILES" ] && domains+=(terraform)
[ -n "$ANSIBLE_FILES" ] && domains+=(ansible)
[ -n "$PY_FILES" ] && domains+=(python)
[ -n "$JS_FILES" ] && domains+=(javascript)
[ -n "$GHA_FILES" ] && domains+=(github-actions)
[ -n "$DOCKER_FILES" ] && domains+=(docker)
export SECREV_DOMAINS="${domains[*]:-}"
log "domains: ${SECREV_DOMAINS:-none}"

# ---------------------------------------------------------------- install (CI only)
pip_install() { python3 -m pip install --quiet --disable-pip-version-check --no-input "$@"; }
if [ "$SECREV_INSTALL" = "1" ]; then
  # shellcheck disable=SC1091  # created just above
  python3 -m venv "$SECREV_TMP/venv" && . "$SECREV_TMP/venv/bin/activate"
  pkgs=()
  [ -n "$TF_FILES$ANSIBLE_FILES$DOCKER_FILES" ] && pkgs+=("checkov==$CHECKOV_VERSION")
  [ -n "$ANSIBLE_FILES" ] && pkgs+=("ansible-lint==$ANSIBLE_LINT_VERSION" "ansible-core==$ANSIBLE_CORE_VERSION")
  [ -n "$PY_FILES" ] && pkgs+=("bandit[sarif]==$BANDIT_VERSION")
  [ -n "$PY_FILES$JS_FILES$GHA_FILES" ] && pkgs+=("semgrep==$SEMGREP_VERSION")
  [ -n "$GHA_FILES" ] && pkgs+=("zizmor==$ZIZMOR_VERSION")
  if [ "${#pkgs[@]}" -gt 0 ]; then
    log "installing: ${pkgs[*]}"
    pip_install "${pkgs[@]}" > "$SECREV_TMP/pip.log" 2>&1 || log "pip install failed: $(tail -c 500 "$SECREV_TMP/pip.log")"
  fi
  mkdir -p "$SECREV_TMP/bin"
  tarball="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
  if curl -sSfL -o "$SECREV_TMP/$tarball" "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${tarball}" \
     && echo "${GITLEAKS_SHA256_LINUX_X64}  $SECREV_TMP/$tarball" | sha256sum -c --quiet -; then
    tar -xzf "$SECREV_TMP/$tarball" -C "$SECREV_TMP/bin" gitleaks
  else
    log "gitleaks download or checksum verification failed"
  fi
  export PATH="$SECREV_TMP/bin:$PATH"
fi

# ---------------------------------------------------------------- tool runner
# run_tool NAME OUTPUT_FILE CMD... : runs CMD with a timeout and records a status file.
# Tools signal findings through their exit codes, so success means "produced output".
run_tool() {
  local name=$1 output=$2; shift 2
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '{"status":"error","error":"%s not installed"}\n' "$1" > "$OUT_DIR/$name.status.json"
    log "$name: not installed"; return
  fi
  local start rc status
  start=$(date +%s)
  timeout "$TOOL_TIMEOUT" "$@" > "$SECREV_TMP/$name.stdout" 2> "$SECREV_TMP/$name.stderr"
  rc=$?
  if [ "$rc" -eq 124 ]; then status=timeout
  elif [ -s "$output" ]; then status=ran
  else status=error
  fi
  printf '{"status":"%s","exit_code":%d,"duration_s":%d}\n' "$status" "$rc" "$(( $(date +%s) - start ))" > "$OUT_DIR/$name.status.json"
  [ "$status" = ran ] || tail -c 2000 "$SECREV_TMP/$name.stderr" > "$OUT_DIR/$name.stderr.txt"
  log "$name: $status (exit $rc)"
}
skip_tool() { printf '{"status":"skipped","reason":"%s"}\n' "$2" > "$OUT_DIR/$1.status.json"; }
as_args() { printf '%s\n' "$1" | sed '/^$/d'; }

# gitleaks: every commit in the PR, so a secret added and later removed is still reported.
# Repo-level .gitleaks.toml and .gitleaksignore are ignored on purpose; output is redacted.
: > "$SECREV_TMP/empty.gitleaksignore"
run_tool gitleaks "$OUT_DIR/gitleaks.sarif" \
  gitleaks git --log-opts="$BASE_SHA..$HEAD_SHA" --config "$SECREV_DIR/gitleaks.toml" \
  --gitleaks-ignore-path "$SECREV_TMP/empty.gitleaksignore" --redact --no-banner \
  --report-format sarif --report-path "$OUT_DIR/gitleaks.sarif" --exit-code 0 .

# checkov: once per changed IaC directory (keeps Terraform module context, and lets the
# bundler prefix paths, which checkov reports relative to the scanned directory).
IAC_DIRS=$(printf '%s\n%s\n%s\n' "$TF_FILES" "$ANSIBLE_FILES" "$DOCKER_FILES" | sed '/^$/d' | xargs -r -n1 dirname | sort -u)
if [ -z "$IAC_DIRS" ]; then
  skip_tool checkov "no Terraform, Ansible or Dockerfile changes"
else
  [ "$(printf '%s\n' "$IAC_DIRS" | wc -l)" -gt "$MAX_DIRS" ] && IAC_DIRS="."
  : > "$OUT_DIR/checkov-dirs.txt"
  i=0; ok=0; start=$(date +%s)
  while IFS= read -r dir; do
    i=$((i + 1)); outdir="$SECREV_TMP/checkov-$i"
    printf '%d\t%s\n' "$i" "$dir" >> "$OUT_DIR/checkov-dirs.txt"
    if command -v checkov >/dev/null 2>&1; then
      timeout "$TOOL_TIMEOUT" checkov --directory "$dir" --framework terraform ansible dockerfile \
        --output sarif --output-file-path "$outdir" --soft-fail --quiet --compact --skip-download \
        > "$SECREV_TMP/checkov-$i.stdout" 2> "$SECREV_TMP/checkov-$i.stderr"
      if [ -s "$outdir/results_sarif.sarif" ]; then
        cp "$outdir/results_sarif.sarif" "$OUT_DIR/checkov-$i.sarif"; ok=$((ok + 1))
      fi
    fi
  done <<< "$IAC_DIRS"
  status=error; [ "$ok" -gt 0 ] && status=ran
  printf '{"status":"%s","directories":%d,"duration_s":%d}\n' "$status" "$i" "$(( $(date +%s) - start ))" > "$OUT_DIR/checkov.status.json"
  command -v checkov >/dev/null 2>&1 || echo "checkov not installed" > "$SECREV_TMP/checkov-0.stderr"
  [ "$status" = ran ] || cat "$SECREV_TMP"/checkov-*.stderr 2>/dev/null | tail -c 2000 > "$OUT_DIR/checkov.stderr.txt"
  log "checkov: $status ($ok/$i directories)"
fi

# ansible-lint: changed Ansible files only, central config, no Galaxy installs.
if [ -z "$ANSIBLE_FILES" ]; then
  skip_tool ansible-lint "no Ansible changes"
else
  mapfile -t files < <(as_args "$ANSIBLE_FILES" | grep -v 'ansible\.cfg$')
  if [ "${#files[@]}" -eq 0 ]; then
    skip_tool ansible-lint "only ansible.cfg changed"
  else
    run_tool ansible-lint "$OUT_DIR/ansible-lint.sarif" \
      ansible-lint --offline --nocolor -q -c "$SECREV_DIR/ansible-lint.yml" \
      --sarif-file "$OUT_DIR/ansible-lint.sarif" "${files[@]}"
  fi
fi

# bandit: changed Python files only.
if [ -z "$PY_FILES" ]; then
  skip_tool bandit "no Python changes"
else
  mapfile -t files < <(as_args "$PY_FILES")
  run_tool bandit "$OUT_DIR/bandit.sarif" bandit -q --exit-zero -f sarif -o "$OUT_DIR/bandit.sarif" "${files[@]}"
fi

# semgrep CE: the p/default registry ruleset (Python, JS/TS, GitHub Actions, secrets).
# The per-language rulesets are much thinner without a Semgrep login. --baseline-commit
# keeps only findings this PR introduces.
if [ -z "$PY_FILES$JS_FILES$GHA_FILES" ]; then
  skip_tool semgrep "no Python, JavaScript/TypeScript or workflow changes"
else
  run_tool semgrep "$OUT_DIR/semgrep.sarif" \
    semgrep scan --config p/default --baseline-commit "$BASE_SHA" --metrics=off --disable-version-check \
    --quiet --sarif --output "$OUT_DIR/semgrep.sarif" .
fi

# zizmor: GitHub Actions workflows (repo-level zizmor config ignored).
if [ -z "$GHA_FILES" ]; then
  skip_tool zizmor "no GitHub Actions changes"
else
  online=(--offline)
  [ -n "${GH_TOKEN:-}" ] && online=()
  if command -v zizmor >/dev/null 2>&1; then
    # shellcheck disable=SC2016  # $@ and $0 belong to the inner sh
    run_tool zizmor "$OUT_DIR/zizmor.sarif" \
      sh -c 'zizmor --no-config --format sarif "$@" > "$0"' "$OUT_DIR/zizmor.sarif" "${online[@]}" .github/workflows
  else
    printf '{"status":"error","error":"zizmor not installed"}\n' > "$OUT_DIR/zizmor.status.json"
  fi
fi

# ---------------------------------------------------------------- bundle
python3 "$SECREV_DIR/bundle.py" "$OUT_DIR" "$CHANGED" > "$OUT_DIR/secrev.json" \
  || log "bundling failed"
log "bundle: $(wc -c < "$OUT_DIR/secrev.json" 2>/dev/null || echo 0) bytes"
exit 0
