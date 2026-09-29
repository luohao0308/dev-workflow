#!/usr/bin/env bash
set -euo pipefail

export DEV_WORKFLOW_NON_INTERACTIVE=1

fail() {
  echo "Assertion failed: $1" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "$2"
}

assert_not_file() {
  [[ ! -f "$1" ]] || fail "$2"
}

assert_no_installed_packs() {
  tr -d '[:space:]' < "$1" | grep -Fq '"installedPacks":[]' || fail "$2"
}

assert_json_string() {
  local path="$1"
  local field="$2"
  local expected="$3"
  local message="$4"
  grep -Eq "\"$field\"[[:space:]]*:[[:space:]]*\"$expected\"" "$path" || fail "$message"
}

assert_json_boolean() {
  local path="$1"
  local field="$2"
  local expected="$3"
  local message="$4"
  grep -Eq "\"$field\"[[:space:]]*:[[:space:]]*$expected" "$path" || fail "$message"
}

assert_v4_safety_defaults() {
  local path="$1"
  local context="$2"
  assert_json_string "$path" pullRequestMode manual "$context adds safe pull request mode"
  assert_json_string "$path" pullRequestActor user "$context adds safe pull request actor"
  assert_json_boolean "$path" pullRequestRequired true "$context requires pull requests"
  assert_json_boolean "$path" ciRequired true "$context requires CI"
  assert_json_boolean "$path" independentReviewRequired true "$context requires independent review"
  assert_json_boolean "$path" forcePushAllowed false "$context denies force push"
  assert_json_boolean "$path" directProtectedBranchPushAllowed false "$context denies direct protected branch push"
  assert_json_boolean "$path" deleteAllowed false "$context denies delete"
  assert_json_string "$path" privilegedOperationsDefault deny "$context denies privileged operations by default"
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print tolower($1)}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$path" | sed -E 's/^.*= //' | tr '[:upper:]' '[:lower:]'
  else
    fail "SHA-256 tool is required"
  fi
}

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
install_script="$repo_root/scripts/install.sh"
uninstall_script="$repo_root/scripts/uninstall.sh"
audit_script="$repo_root/scripts/audit.sh"
workflow_version="$(tr -d '[:space:]' < "$repo_root/VERSION")"

assert_audit_rejects() {
  local target="$1"
  local message="$2"
  local audit_code
  set +e
  bash "$audit_script" --target "$target" >/dev/null
  audit_code=$?
  set -e
  [[ "$audit_code" -eq 1 ]] || fail "$message"
}

if bash "$install_script" --help | grep -Eq -- '--delete'; then
  fail "installer does not expose a delete permission option"
fi
temp_base="${TMPDIR:-/tmp}"
temp_root="$(mktemp -d "$temp_base/dev-workflow-integration.XXXXXX")"

cleanup() {
  case "$temp_root" in
    "$temp_base"/dev-workflow-integration.*) rm -rf -- "$temp_root" ;;
    *) echo "Refusing to clean unexpected test path: $temp_root" >&2 ;;
  esac
}
trap cleanup EXIT

fresh_target="$temp_root/fresh"
mkdir -p "$fresh_target"
git -C "$fresh_target" init -q
printf '%s\n' '# user exclude' '/user-local-only/' >> "$fresh_target/.git/info/exclude"
printf '%s\n' '/project-local-only/' > "$fresh_target/.gitignore"
gitignore_hash_before_install="$(sha256_file "$fresh_target/.gitignore")"
bash "$install_script" --target "$fresh_target" --all-packs --enable-capabilities api:rest-openapi,containers:compose >/dev/null
fresh_manifest="$fresh_target/.dev-workflow/manifest.json"
assert_file "$fresh_manifest" "new install creates manifest"
grep -Eq '"schemaVersion"[[:space:]]*:[[:space:]]*5' "$fresh_manifest" || fail "new installs use schema 5"
grep -Fq '"api:rest-openapi"' "$fresh_manifest" && grep -Fq '"containers:compose"' "$fresh_manifest" || fail "installer persists enabled capabilities"
assert_json_string "$fresh_manifest" pushMode manual "push defaults to manual approval"
assert_json_string "$fresh_manifest" pushActor user "push defaults to user execution"
assert_json_string "$fresh_manifest" pullRequestMode manual "pull request defaults to manual approval"
assert_json_string "$fresh_manifest" pullRequestActor user "pull request defaults to user execution"
assert_json_string "$fresh_manifest" mergeMode manual "merge defaults to manual approval"
assert_json_string "$fresh_manifest" mergeActor user "merge defaults to user execution"
assert_json_boolean "$fresh_manifest" pullRequestRequired true "pull requests are required by default"
assert_json_boolean "$fresh_manifest" ciRequired true "CI is required by default"
assert_json_boolean "$fresh_manifest" independentReviewRequired true "independent review is required by default"
assert_json_boolean "$fresh_manifest" forcePushAllowed false "force push is denied by default"
assert_json_boolean "$fresh_manifest" directProtectedBranchPushAllowed false "direct protected branch push is denied by default"
assert_json_boolean "$fresh_manifest" deleteAllowed false "delete is always denied"
assert_json_string "$fresh_manifest" privilegedOperationsDefault deny "privileged operations default to deny"
assert_json_string "$fresh_manifest" policyChangedBy default "safe defaults record their policy origin"
bash "$install_script" --target "$fresh_target" --non-interactive >/dev/null
grep -Fq '"api:rest-openapi"' "$fresh_manifest" && grep -Fq '"containers:compose"' "$fresh_manifest" || fail "upgrade preserves enabled capabilities"
bash "$install_script" --target "$fresh_target" --non-interactive --disable-capabilities containers:compose >/dev/null
grep -Fq '"api:rest-openapi"' "$fresh_manifest" && ! grep -Fq '"containers:compose"' "$fresh_manifest" || fail "installer disables only requested capability"
if bash "$install_script" --target "$fresh_target" --non-interactive --enable-capabilities api:not-real >/dev/null 2>&1; then fail "installer rejects unknown capability IDs"; fi
grep -Eq '"policyChangedAt"[[:space:]]*:[[:space:]]*"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"' "$fresh_manifest" || fail "new installs timestamp the initial policy"
grep -Eq '"path":"AGENTS.md","source":"core","action":"created"' "$fresh_manifest" || fail "new installs record created ownership"
grep -Fq '## 大型计划拆分与确认门' "$fresh_target/AGENTS.md" || fail "Core install includes the large-plan approval gate"
grep -Fq '## 默认开发闭环（轻量核心 + 风险插件）' "$fresh_target/AGENTS.md" || fail "Core install includes the lightweight development loop"
grep -Fq '## 自适应技术决策门' "$fresh_target/AGENTS.md" || fail "Core install includes the adaptive technical decision gate"
grep -Fq 'L0' "$fresh_target/AGENTS.md" && grep -Fq 'L1' "$fresh_target/AGENTS.md" && grep -Fq 'L2' "$fresh_target/AGENTS.md" || fail "Core install includes all decision levels"
grep -Fq '技术分析本身不构成授权门' "$fresh_target/AGENTS.md" || fail "decision levels do not add redundant approval gates"
grep -Fq '## 交付治理与权限策略' "$fresh_target/AGENTS.md" || fail "Core install includes the delivery governance policy"
grep -Fq '一次性授权必须绑定' "$fresh_target/AGENTS.md" || fail "Core install scopes one-time authorization to an exact operation"
grep -Fq 'awaiting_user_confirmation' "$fresh_target/docs/plans/README.md" || fail "delivery plans expose the approval state"
grep -Fq '## 7. 偏移控制' "$fresh_target/docs/plans/TEMPLATE.md" || fail "delivery plan template includes drift control"
grep -Fq 'Test/Eval/Check' "$fresh_target/docs/plans/TEMPLATE.md" || fail "delivery plan template maps claims to executable checks"
grep -Fq 'codex/*' "$fresh_target/docs/development/GIT-WORKTREE-WORKFLOW.md" || fail "delivery workflow protects local Codex branches"
assert_file "$fresh_target/docs/development/DELIVERY-DECISION-MATRIX.md" "delivery install includes the single decision authority"
grep -Fq 'DELIVERY-DECISION-MATRIX.md' "$fresh_target/docs/development/GIT-WORKTREE-WORKFLOW.md" || fail "worktree workflow references the single decision authority"
grep -Fq 'DELIVERY-DECISION-MATRIX.md' "$fresh_target/docs/development/README.md" || fail "development README references the single decision authority"
assert_file "$fresh_target/scripts/delivery_guard.py" "Core installs the delivery preflight guard"
assert_file "$fresh_target/scripts/check-git-boundaries.py" "delivery installs the Git boundary check"
assert_file "$fresh_target/scripts/report-worktrees.py" "delivery installs the read-only worktree report"
grep -Eq '"path":"scripts/report-worktrees.py","source":"delivery"' "$fresh_manifest" || fail "manifest records worktree report ownership"
assert_file "$fresh_target/docs/development/CI-BOUNDARY-CHECK.md" "delivery documents CI enforcement for Git boundaries"
grep -Eq '"path":"scripts/check-git-boundaries.py","source":"delivery"' "$fresh_manifest" || fail "manifest records Git boundary check ownership"
grep -Eq '"path":"scripts/delivery_guard.py","source":"core"' "$fresh_manifest" || fail "manifest records delivery guard ownership"
grep -Eq '"path":"scripts/feature_catalog.py","source":"feature-catalog"' "$fresh_manifest" || fail "all-packs installs feature-catalog ownership"

guard_collision_target="$temp_root/guard-collision"
mkdir -p "$guard_collision_target/scripts"
printf 'untrusted guard\n' > "$guard_collision_target/scripts/delivery_guard.py"
set +e
bash "$install_script" --target "$guard_collision_target" --non-interactive >/dev/null 2>&1
guard_collision_code=$?
set -e
[[ "$guard_collision_code" -ne 0 ]] || fail "install rejects an untrusted pre-existing delivery guard"
grep -Fq 'untrusted guard' "$guard_collision_target/scripts/delivery_guard.py" || fail "rejected guard collision is not overwritten"
assert_not_file "$guard_collision_target/.dev-workflow/manifest.json" "guard collision fails before manifest creation"

guard_tamper_target="$temp_root/guard-tamper"
mkdir -p "$guard_tamper_target"
bash "$install_script" --target "$guard_tamper_target" --non-interactive >/dev/null
printf 'tampered guard\n' > "$guard_tamper_target/scripts/delivery_guard.py"
guard_tamper_manifest="$guard_tamper_target/.dev-workflow/manifest.json"
guard_tamper_manifest_hash="$(sha256_file "$guard_tamper_manifest")"
set +e
bash "$audit_script" --target "$guard_tamper_target" >/dev/null 2>&1
guard_tamper_audit_code=$?
set -e
[[ "$guard_tamper_audit_code" -eq 1 ]] || fail "audit rejects a modified managed delivery guard"
set +e
bash "$install_script" --target "$guard_tamper_target" --non-interactive >/dev/null 2>&1
guard_tamper_code=$?
set -e
[[ "$guard_tamper_code" -ne 0 ]] || fail "reinstall rejects a modified managed delivery guard"
[[ "$(sha256_file "$guard_tamper_manifest")" == "$guard_tamper_manifest_hash" ]] || fail "rejected guard tamper leaves manifest unchanged"
grep -Fq '# BEGIN dev-workflow managed excludes' "$fresh_target/.git/info/exclude" || fail "install adds a managed Git exclude block"
grep -Fq '/.dev-workflow/' "$fresh_target/.git/info/exclude" || fail "Git exclude hides dev-workflow metadata"
grep -Fq '/docs/README.md' "$fresh_target/.git/info/exclude" || fail "Git exclude hides a created Core file"
grep -Fq '/docs/project-memory/' "$fresh_target/.git/info/exclude" || fail "Git exclude hides the complete long-term memory directory"
grep -Fq '/docs/working-context/' "$fresh_target/.git/info/exclude" || fail "Git exclude hides the complete working-context directory"
grep -Fq '/docs/工作日志/' "$fresh_target/.git/info/exclude" || fail "Git exclude hides the complete workflow journal directory"
grep -Fq '# user exclude' "$fresh_target/.git/info/exclude" || fail "install preserves user Git excludes"
git -C "$fresh_target" check-ignore -q -- .dev-workflow/manifest.json || fail "Git check-ignore matches dev-workflow metadata"
git -C "$fresh_target" check-ignore -q -- docs/README.md || fail "Git check-ignore matches created workflow files"
mkdir -p "$fresh_target/docs/project-memory/runbooks" "$fresh_target/docs/working-context" "$fresh_target/docs/工作日志"
touch "$fresh_target/docs/project-memory/runbooks/future-memory.md" "$fresh_target/docs/working-context/future-task.md" "$fresh_target/docs/工作日志/future-session.md"
git -C "$fresh_target" check-ignore -q -- docs/project-memory/runbooks/future-memory.md || fail "Git ignores future long-term memory files"
git -C "$fresh_target" check-ignore -q -- docs/working-context/future-task.md || fail "Git ignores future working-context files"
git -C "$fresh_target" check-ignore -q -- 'docs/工作日志/future-session.md' || fail "Git ignores future workflow journal files"
while IFS= read -r installed_path; do
  [[ -n "$installed_path" ]] || continue
  case "$installed_path" in
    docs/operations/runbooks/*)
      git -C "$fresh_target" check-ignore -q -- "$installed_path" && fail "Git must keep shared runbooks visible: $installed_path"
      continue
      ;;
  esac
  git -C "$fresh_target" check-ignore -q -- "$installed_path" || fail "Git excludes every installer-created path: $installed_path"
done < <(sed -n -E 's/.*"path":"([^"]+)".*"action":"created".*/\1/p' "$fresh_manifest")
git -C "$fresh_target" check-ignore -q -- docs/operations/runbooks/RUNBOOK-TEMPLATE.md && fail "Git must not ignore the shared runbook template"
[[ "$(sha256_file "$fresh_target/.gitignore")" == "$gitignore_hash_before_install" ]] || fail "install does not modify project .gitignore"

automated_git_target="$temp_root/automated-git"
mkdir -p "$automated_git_target"
set +e
bash "$install_script" \
  --target "$automated_git_target" \
  --push-mode auto \
  --push-actor ai \
  --pull-request-mode auto \
  --pull-request-actor ai \
  --merge-mode auto \
  --merge-actor ai \
  --non-interactive >/dev/null 2>&1
non_interactive_automation_code=$?
set -e
[[ "$non_interactive_automation_code" -ne 0 ]] || fail "non-interactive install cannot self-authorize AI automation"
assert_not_file "$automated_git_target/.dev-workflow/manifest.json" "rejected non-interactive automation does not write a manifest"

redirected_git_target="$temp_root/redirected-git"
mkdir -p "$redirected_git_target"
set +e
printf 'YES\n' | DEV_WORKFLOW_NON_INTERACTIVE= bash "$install_script" \
  --target "$redirected_git_target" \
  --push-mode auto \
  --push-actor ai >/dev/null 2>&1
redirected_automation_code=$?
set -e
[[ "$redirected_automation_code" -ne 0 ]] || fail "redirected stdin cannot authorize AI automation"
assert_not_file "$redirected_git_target/.dev-workflow/manifest.json" "rejected redirected automation does not write a manifest"

existing_policy_target="$temp_root/existing-policy-change"
mkdir -p "$existing_policy_target"
bash "$install_script" --target "$existing_policy_target" >/dev/null
existing_policy_manifest="$existing_policy_target/.dev-workflow/manifest.json"
existing_policy_hash="$(sha256_file "$existing_policy_manifest")"
set +e
bash "$install_script" --target "$existing_policy_target" --push-actor ai --non-interactive >/dev/null 2>&1
existing_policy_change_code=$?
set -e
[[ "$existing_policy_change_code" -ne 0 ]] || fail "non-interactive install cannot change an existing actor"
[[ "$(sha256_file "$existing_policy_manifest")" == "$existing_policy_hash" ]] || fail "rejected existing policy change leaves the manifest unchanged"

policy_narrowing_tmp="$existing_policy_manifest.auto"
sed -E \
  -e 's/"pushMode"[[:space:]]*:[[:space:]]*"manual"/"pushMode": "auto"/' \
  -e 's/"pushActor"[[:space:]]*:[[:space:]]*"user"/"pushActor": "ai"/' \
  -e 's/"policyChangedBy"[[:space:]]*:[[:space:]]*"default"/"policyChangedBy": "user"/' \
  "$existing_policy_manifest" > "$policy_narrowing_tmp"
mv -- "$policy_narrowing_tmp" "$existing_policy_manifest"
automated_policy_hash="$(sha256_file "$existing_policy_manifest")"
set +e
bash "$install_script" \
  --target "$existing_policy_target" \
  --push-mode manual \
  --push-actor user \
  --non-interactive >/dev/null 2>&1
policy_narrowing_code=$?
set -e
[[ "$policy_narrowing_code" -ne 0 ]] || fail "non-interactive install cannot narrow an existing policy"
[[ "$(sha256_file "$existing_policy_manifest")" == "$automated_policy_hash" ]] || fail "rejected policy narrowing leaves the manifest unchanged"

invalid_git_target="$temp_root/invalid-git"
mkdir -p "$invalid_git_target"
set +e
bash "$install_script" --target "$invalid_git_target" --push-mode auto --push-actor user >/dev/null 2>&1
invalid_git_code=$?
set -e
[[ "$invalid_git_code" -ne 0 ]] || fail "automatic push with a user actor is rejected"
assert_not_file "$invalid_git_target/.dev-workflow/manifest.json" "invalid Git policy does not write a manifest"

invalid_merge_target="$temp_root/invalid-merge"
mkdir -p "$invalid_merge_target"
set +e
bash "$install_script" --target "$invalid_merge_target" --merge-mode auto --merge-actor user >/dev/null 2>&1
invalid_merge_code=$?
set -e
[[ "$invalid_merge_code" -ne 0 ]] || fail "automatic merge with a user actor is rejected"
assert_not_file "$invalid_merge_target/.dev-workflow/manifest.json" "invalid merge policy does not write a manifest"

audit_policy_target="$temp_root/audit-policy"
mkdir -p "$audit_policy_target"
bash "$install_script" --target "$audit_policy_target" >/dev/null
audit_policy_manifest="$audit_policy_target/.dev-workflow/manifest.json"
audit_policy_baseline="$audit_policy_target/manifest.baseline.json"
cp -- "$audit_policy_manifest" "$audit_policy_baseline"

python3 - "$audit_policy_baseline" "$audit_policy_manifest" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["enabledCapabilities"] = ["api:not-real"]
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(manifest, handle)
PY
assert_audit_rejects "$audit_policy_target" "audit rejects an unknown enabled capability"
cp -- "$audit_policy_baseline" "$audit_policy_manifest"

sed -E 's/"pullRequestMode"[[:space:]]*:[[:space:]]*"manual"/"pullRequestMode": "sometimes"/' \
  "$audit_policy_baseline" > "$audit_policy_manifest"
assert_audit_rejects "$audit_policy_target" "audit rejects an invalid pull request mode"

sed -E \
  -e 's/"pullRequestMode"[[:space:]]*:[[:space:]]*"manual"/"pullRequestMode": "auto"/' \
  -e 's/"pullRequestActor"[[:space:]]*:[[:space:]]*"user"/"pullRequestActor": "user"/' \
  "$audit_policy_baseline" > "$audit_policy_manifest"
assert_audit_rejects "$audit_policy_target" "audit rejects automatic pull requests executed by a user actor"

while IFS='|' read -r safety_field secure_value relaxed_value; do
  sed -E "s/\"$safety_field\"[[:space:]]*:[[:space:]]*$secure_value/\"$safety_field\": $relaxed_value/" \
    "$audit_policy_baseline" > "$audit_policy_manifest"
  assert_audit_rejects "$audit_policy_target" "audit rejects relaxed $safety_field"
done <<'EOF'
pullRequestRequired|true|false
ciRequired|true|false
independentReviewRequired|true|false
forcePushAllowed|false|true
directProtectedBranchPushAllowed|false|true
deleteAllowed|false|true
EOF

sed -E 's/"privilegedOperationsDefault"[[:space:]]*:[[:space:]]*"deny"/"privilegedOperationsDefault": "allow"/' \
  "$audit_policy_baseline" > "$audit_policy_manifest"
assert_audit_rejects "$audit_policy_target" "audit rejects privileged operations that do not default to deny"

sed -E '/"pullRequestActor"[[:space:]]*:/d' "$audit_policy_baseline" > "$audit_policy_manifest"
assert_audit_rejects "$audit_policy_target" "audit rejects a missing pull request actor"

sed -E '/"ciRequired"[[:space:]]*:/d' "$audit_policy_baseline" > "$audit_policy_manifest"
assert_audit_rejects "$audit_policy_target" "audit rejects a missing required safety gate"

python3 - "$audit_policy_baseline" "$audit_policy_manifest" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
manifest["gitPolicy"]["forcePushAllowed"] = True
manifest["gitPolicy"]["directProtectedBranchPushAllowed"] = True
manifest["gitPolicy"]["privilegedOperationsDefault"] = "allow"
manifest["shadow"] = {
    "forcePushAllowed": False,
    "directProtectedBranchPushAllowed": False,
    "privilegedOperationsDefault": "deny",
}
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, separators=(",", ":"))
PY
assert_audit_rejects "$audit_policy_target" "structured policy parsing ignores safe-looking sibling fields"

sed -E 's/("policyChangedAt"[[:space:]]*:[[:space:]]*"[0-9T:-]+)Z"/\1.1234567Z"/' \
  "$audit_policy_baseline" > "$audit_policy_manifest"
set +e
bash "$audit_script" --target "$audit_policy_target" >/dev/null
fractional_timestamp_code=$?
set -e
[[ "$fractional_timestamp_code" -eq 2 ]] || fail "audit accepts PowerShell-style fractional policy timestamps"

python3 - "$audit_policy_baseline" "$audit_policy_manifest" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
del manifest["gitPolicy"]
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2)
PY
missing_policy_hash="$(sha256_file "$audit_policy_manifest")"
set +e
bash "$uninstall_script" --target "$audit_policy_target" --dry-run >/dev/null 2>&1
missing_policy_uninstall_code=$?
set -e
[[ "$missing_policy_uninstall_code" -ne 0 ]] || fail "uninstall rejects a schema 4 manifest without gitPolicy"
[[ "$(sha256_file "$audit_policy_manifest")" == "$missing_policy_hash" ]] || fail "rejected missing-policy uninstall leaves the manifest unchanged"

cp -- "$audit_policy_baseline" "$audit_policy_manifest"

dry_run_git_target="$temp_root/dry-run-git"
mkdir -p "$dry_run_git_target"
git -C "$dry_run_git_target" init -q
printf '%s\n' '# dry-run user exclude' >> "$dry_run_git_target/.git/info/exclude"
dry_run_exclude_hash="$(sha256_file "$dry_run_git_target/.git/info/exclude")"
bash "$install_script" --target "$dry_run_git_target" --all-packs --dry-run >/dev/null
assert_not_file "$dry_run_git_target/.dev-workflow/manifest.json" "install dry-run does not write the manifest"
[[ "$(sha256_file "$dry_run_git_target/.git/info/exclude")" == "$dry_run_exclude_hash" ]] || fail "install dry-run does not modify Git exclude"

tracked_target="$temp_root/tracked"
mkdir -p "$tracked_target"
git -C "$tracked_target" init -q
printf '%s\n' '# Existing tracked project rules' > "$tracked_target/AGENTS.md"
git -C "$tracked_target" add AGENTS.md
bash "$install_script" --target "$tracked_target" >/dev/null 2>"$tracked_target/install.stderr"
grep -Fq 'info/exclude 不会阻止上传：AGENTS.md' "$tracked_target/install.stderr" || fail "install warns when a tracked file receives dev-workflow content"
if grep -Fqx '/AGENTS.md' "$tracked_target/.git/info/exclude"; then
  fail "install does not hide an existing tracked project file as a whole"
fi
git -C "$tracked_target" add -f .dev-workflow/manifest.json
bash "$install_script" --target "$tracked_target" >/dev/null 2>"$tracked_target/reinstall.stderr"
grep -Fq 'info/exclude 不会阻止上传：.dev-workflow/' "$tracked_target/reinstall.stderr" || fail "install warns when Git already tracks dev-workflow metadata"
set +e
bash "$audit_script" --target "$tracked_target" >"$tracked_target/audit.stdout"
tracked_audit_code=$?
set -e
[[ "$tracked_audit_code" -eq 2 ]] || fail "tracked-file audit still reports the pending onboarding state"
grep -Fq 'info/exclude 无法阻止上传：AGENTS.md' "$tracked_target/audit.stdout" || fail "audit warns when Git tracks a file containing dev-workflow content"
grep -Fq 'info/exclude 无法阻止上传：.dev-workflow/' "$tracked_target/audit.stdout" || fail "audit warns when Git tracks dev-workflow metadata"

special_repo="$temp_root/special-repo"
special_relative='[local] space#bang!star*question?'
special_target="$special_repo/$special_relative"
mkdir -p "$special_target"
git -C "$special_repo" init -q
bash "$install_script" --target "$special_target" >/dev/null
git -C "$special_repo" check-ignore -q -- "$special_relative/.dev-workflow/manifest.json" || fail "Git exclude escapes special characters in nested target paths"
git -C "$special_repo" check-ignore -q -- "$special_relative/docs/README.md" || fail "Git exclude protects created files under a special-character target path"

misordered_install_target="$temp_root/misordered-install"
mkdir -p "$misordered_install_target"
git -C "$misordered_install_target" init -q
printf '%s\n' \
  '# END dev-workflow managed excludes' \
  '/keep-between/' \
  '# BEGIN dev-workflow managed excludes' \
  '/keep-after/' > "$misordered_install_target/.git/info/exclude"
misordered_install_exclude_hash="$(sha256_file "$misordered_install_target/.git/info/exclude")"
set +e
bash "$install_script" --target "$misordered_install_target" >/dev/null 2>&1
misordered_install_code=$?
set -e
[[ "$misordered_install_code" -ne 0 ]] || fail "install rejects a misordered managed Git exclude block"
assert_not_file "$misordered_install_target/.dev-workflow/manifest.json" "Git exclude preflight fails before install mutations"
assert_not_file "$misordered_install_target/AGENTS.md" "Git exclude preflight prevents partial Core installation"
[[ "$(sha256_file "$misordered_install_target/.git/info/exclude")" == "$misordered_install_exclude_hash" ]] || fail "failed install preserves a misordered user exclude file byte-for-byte"

misordered_uninstall_target="$temp_root/misordered-uninstall"
mkdir -p "$misordered_uninstall_target"
git -C "$misordered_uninstall_target" init -q
bash "$install_script" --target "$misordered_uninstall_target" >/dev/null
misordered_uninstall_agents_hash="$(sha256_file "$misordered_uninstall_target/AGENTS.md")"
printf '%s\n' \
  '# END dev-workflow managed excludes' \
  '/keep-between/' \
  '# BEGIN dev-workflow managed excludes' \
  '/keep-after/' > "$misordered_uninstall_target/.git/info/exclude"
set +e
bash "$uninstall_script" --target "$misordered_uninstall_target" >/dev/null 2>&1
misordered_uninstall_code=$?
set -e
[[ "$misordered_uninstall_code" -ne 0 ]] || fail "uninstall rejects a misordered managed Git exclude block"
assert_file "$misordered_uninstall_target/.dev-workflow/manifest.json" "Git exclude preflight fails before uninstall removes the manifest"
[[ "$(sha256_file "$misordered_uninstall_target/AGENTS.md")" == "$misordered_uninstall_agents_hash" ]] || fail "Git exclude preflight prevents partial Core uninstall"
grep -Fq '/keep-after/' "$misordered_uninstall_target/.git/info/exclude" || fail "failed uninstall preserves user exclude content after a misordered marker"

negated_target="$temp_root/negated-ignore"
mkdir -p "$negated_target"
git -C "$negated_target" init -q
printf '%s\n' '!/.dev-workflow/' '!/.dev-workflow/**' > "$negated_target/.gitignore"
bash "$install_script" --target "$negated_target" >/dev/null 2>"$negated_target/install.stderr"
grep -Fq '最终 ignore 规则未排除 dev-workflow 元数据' "$negated_target/install.stderr" || fail "install warns when project .gitignore overrides the local metadata exclude"
if git -C "$negated_target" check-ignore --no-index -q -- .dev-workflow/manifest.json; then
  fail "negating .gitignore fixture must expose dev-workflow metadata"
fi
set +e
bash "$audit_script" --target "$negated_target" >"$negated_target/audit.stdout"
negated_audit_code=$?
set -e
[[ "$negated_audit_code" -eq 2 ]] || fail "negated-exclude audit still reports the pending onboarding state"
grep -Fq '最终 ignore 规则未排除 dev-workflow 元数据' "$negated_target/audit.stdout" || fail "audit warns when the final Git ignore result is ineffective"

worktree_repo="$temp_root/worktree-repo"
worktree_target="$temp_root/worktree-target"
mkdir -p "$worktree_repo"
git -C "$worktree_repo" init -q
printf '%s\n' 'base' > "$worktree_repo/base.txt"
git -C "$worktree_repo" add base.txt
git -C "$worktree_repo" -c user.name=dev-workflow -c user.email=dev-workflow@example.invalid commit -qm init
git -C "$worktree_repo" worktree add -q -b dev-workflow-test "$worktree_target"
bash "$install_script" --target "$worktree_target" --packs architecture >/dev/null
worktree_exclude="$(git -C "$worktree_target" rev-parse --git-path info/exclude)"
grep -Fq '# BEGIN dev-workflow managed excludes' "$worktree_exclude" || fail "worktree install uses Git's resolved info/exclude"
git -C "$worktree_target" check-ignore -q -- docs/architecture/SYSTEM.md || fail "worktree Git exclude applies to installed files"

non_git_target="$temp_root/non-git"
mkdir -p "$non_git_target"
bash "$install_script" --target "$non_git_target" >/dev/null 2>"$non_git_target/install.stderr"
assert_file "$non_git_target/.dev-workflow/manifest.json" "non-Git directories still install"
grep -Fq '不在 Git 仓库中' "$non_git_target/install.stderr" || fail "non-Git install reports the local exclude skip"
assert_not_file "$non_git_target/.git/info/exclude" "non-Git install does not fabricate a Git exclude file"

python3 "$fresh_target/scripts/feature_catalog.py" --root "$fresh_target" --init >/dev/null
python3 "$fresh_target/scripts/feature_catalog.py" --root "$fresh_target" --generate >/dev/null
python3 "$fresh_target/scripts/feature_catalog.py" --root "$fresh_target" --check >/dev/null
catalog_hash_before_reinstall="$(sha256_file "$fresh_target/docs/development/ai/feature-catalog.json")"
exclude_hash_before_reinstall="$(sha256_file "$fresh_target/.git/info/exclude")"
bash "$install_script" --target "$fresh_target" --all-packs >/dev/null
catalog_hash_after_reinstall="$(sha256_file "$fresh_target/docs/development/ai/feature-catalog.json")"
[[ "$catalog_hash_before_reinstall" == "$catalog_hash_after_reinstall" ]] || fail "reinstall does not overwrite active feature catalog"
[[ "$(grep -cF '# BEGIN dev-workflow managed excludes' "$fresh_target/.git/info/exclude")" -eq 1 ]] || fail "reinstall does not duplicate the managed Git exclude block"
[[ "$(sha256_file "$fresh_target/.git/info/exclude")" == "$exclude_hash_before_reinstall" ]] || fail "reinstall leaves the Git exclude file byte-stable"
git -C "$fresh_target" check-ignore -q -- docs/project-memory/runbooks/future-memory.md || fail "reinstall keeps future long-term memory ignored"

first_updated_at="$(grep -E '"updatedAt"' "$fresh_manifest")"
bash "$install_script" --target "$fresh_target" --all-packs >/dev/null
second_updated_at="$(grep -E '"updatedAt"' "$fresh_manifest")"
[[ "$first_updated_at" == "$second_updated_at" ]] || fail "idempotent reinstall preserves updatedAt"

set +e
bash "$audit_script" --target "$fresh_target" >/dev/null
audit_code=$?
set -e
[[ "$audit_code" -eq 2 ]] || fail "valid pending install returns audit exit code 2"

manifest_ready_tmp="$fresh_manifest.ready"
sed -E \
  -e 's/"status"[[:space:]]*:[[:space:]]*"pending"/"status": "ready"/' \
  -e 's/"lastAuditAt"[[:space:]]*:[[:space:]]*null/"lastAuditAt": "2026-01-01T00:00:00Z"/' \
  "$fresh_manifest" > "$manifest_ready_tmp"
mv -- "$manifest_ready_tmp" "$fresh_manifest"
printf '# Project summary\n\nVerified project facts.\n' > "$fresh_target/docs/PROJECT-SUMMARY.md"
printf '%s\n' \
  '---' \
  'workflow: dev-workflow' \
  'status: ready' \
  'updated: 2026-01-01' \
  '---' \
  '' \
  '# Adoption' \
  '' \
  'Verified.' > "$fresh_target/docs/WORKFLOW-ADOPTION.md"
printf '\nmanual matrix drift\n' >> "$fresh_target/docs/FEATURE-MATRIX.md"
set +e
bash "$audit_script" --target "$fresh_target" --strict >/dev/null
feature_matrix_drift_code=$?
set -e
[[ "$feature_matrix_drift_code" -eq 1 ]] || fail "strict audit rejects feature matrix drift"
python3 "$fresh_target/scripts/feature_catalog.py" --root "$fresh_target" --generate >/dev/null
set +e
bash "$audit_script" --target "$fresh_target" --strict >/dev/null
strict_audit_code=$?
set -e
[[ "$strict_audit_code" -eq 0 ]] || fail "completed schema 4 install passes strict audit"

exclude_without_core="$fresh_target/.git/info/exclude.without-core"
sed '\|^/docs/README\.md$|d' "$fresh_target/.git/info/exclude" > "$exclude_without_core"
mv -- "$exclude_without_core" "$fresh_target/.git/info/exclude"
set +e
bash "$audit_script" --target "$fresh_target" --strict >/dev/null
missing_exclude_audit_code=$?
set -e
[[ "$missing_exclude_audit_code" -eq 1 ]] || fail "strict audit rejects a missing created-file Git exclude"
bash "$install_script" --target "$fresh_target" --all-packs >/dev/null

modified_delivery_file="$fresh_target/docs/development/README.md"
printf '\n项目自定义内容。\n' >> "$modified_delivery_file"
policy_changed_at_before_uninstall="$(grep -E '"policyChangedAt"' "$fresh_manifest")"
policy_changed_by_before_uninstall="$(grep -E '"policyChangedBy"' "$fresh_manifest")"
bash "$uninstall_script" --target "$fresh_target" --packs delivery --dry-run >/dev/null
assert_file "$fresh_target/docs/plans/TEMPLATE.md" "dry-run does not delete files"

bash "$uninstall_script" --target "$fresh_target" --packs delivery >/dev/null
assert_file "$modified_delivery_file" "modified managed files are preserved"
assert_not_file "$fresh_target/docs/plans/TEMPLATE.md" "unchanged pack files are deleted"
assert_file "$fresh_target/scripts/delivery_guard.py" "partial delivery uninstall preserves the Core guard"
grep -Fq '"api:rest-openapi"' "$fresh_manifest" || fail "partial uninstall preserves enabled capabilities"
if tr -d '\r\n' < "$fresh_manifest" | grep -Eq '"installedPacks"[[:space:]]*:[[:space:]]*\[[^]]*"delivery"'; then
  fail "partial uninstall removes pack from manifest"
fi
grep -Fq '"source":"delivery"' "$fresh_manifest" && fail "partial uninstall removes pack inventory entries"
assert_json_string "$fresh_manifest" pushMode manual "partial uninstall preserves push mode"
assert_json_string "$fresh_manifest" pushActor user "partial uninstall preserves push actor"
assert_json_string "$fresh_manifest" pullRequestMode manual "partial uninstall preserves pull request mode"
assert_json_string "$fresh_manifest" pullRequestActor user "partial uninstall preserves pull request actor"
assert_json_string "$fresh_manifest" mergeMode manual "partial uninstall preserves merge mode"
assert_json_string "$fresh_manifest" mergeActor user "partial uninstall preserves merge actor"
assert_json_boolean "$fresh_manifest" pullRequestRequired true "partial uninstall preserves the pull request gate"
assert_json_boolean "$fresh_manifest" ciRequired true "partial uninstall preserves the CI gate"
assert_json_boolean "$fresh_manifest" independentReviewRequired true "partial uninstall preserves the independent review gate"
assert_json_boolean "$fresh_manifest" forcePushAllowed false "partial uninstall preserves denied force push"
assert_json_boolean "$fresh_manifest" directProtectedBranchPushAllowed false "partial uninstall preserves denied direct protected branch push"
assert_json_boolean "$fresh_manifest" deleteAllowed false "partial uninstall preserves denied delete permission"
assert_json_string "$fresh_manifest" privilegedOperationsDefault deny "partial uninstall preserves denied privileged operations"
[[ "$(grep -E '"policyChangedAt"' "$fresh_manifest")" == "$policy_changed_at_before_uninstall" ]] || fail "partial uninstall preserves the policy timestamp"
[[ "$(grep -E '"policyChangedBy"' "$fresh_manifest")" == "$policy_changed_by_before_uninstall" ]] || fail "partial uninstall preserves the policy origin"
grep -Fq '/docs/README.md' "$fresh_target/.git/info/exclude" || fail "partial uninstall preserves Core Git excludes"
grep -Fq '/docs/project-memory/' "$fresh_target/.git/info/exclude" || fail "partial uninstall preserves local memory exclusion"
if grep -Fq '/docs/working-context/' "$fresh_target/.git/info/exclude" || grep -Fq '/docs/工作日志/' "$fresh_target/.git/info/exclude"; then
  fail "partial uninstall removes Delivery-only directory excludes"
fi
if grep -Fq '/docs/plans/TEMPLATE.md' "$fresh_target/.git/info/exclude"; then
  fail "partial uninstall removes pack Git excludes"
fi
[[ "$(grep -cF '# BEGIN dev-workflow managed excludes' "$fresh_target/.git/info/exclude")" -eq 1 ]] || fail "partial uninstall keeps one managed Git exclude block"

bash "$uninstall_script" --target "$fresh_target" >/dev/null
assert_not_file "$fresh_manifest" "full uninstall removes manifest"
assert_file "$modified_delivery_file" "project-modified content remains after full uninstall"
assert_file "$fresh_target/docs/development/ai/feature-catalog.json" "full uninstall preserves active feature catalog"
assert_file "$fresh_target/docs/FEATURE-MATRIX.md" "full uninstall preserves generated feature matrix"
if grep -Fq 'dev-workflow managed excludes' "$fresh_target/.git/info/exclude"; then
  fail "full uninstall removes the managed Git exclude block"
fi
grep -Fq '# user exclude' "$fresh_target/.git/info/exclude" || fail "full uninstall preserves user Git excludes"
[[ "$(sha256_file "$fresh_target/.gitignore")" == "$gitignore_hash_before_install" ]] || fail "uninstall does not modify project .gitignore"

invalid_install_target="$temp_root/invalid-install-packs"
mkdir -p "$invalid_install_target"
set +e
bash "$install_script" --target "$invalid_install_target" --packs "" >/dev/null 2>&1
empty_install_packs_code=$?
bash "$install_script" --target "$invalid_install_target" --packs "   " >/dev/null 2>&1
blank_install_packs_code=$?
bash "$install_script" --target "$invalid_install_target" --packs ",,," >/dev/null 2>&1
comma_install_packs_code=$?
set -e
[[ "$empty_install_packs_code" -eq 2 ]] || fail "install rejects an empty explicit pack list"
[[ "$blank_install_packs_code" -eq 2 ]] || fail "install rejects a whitespace-only pack list"
[[ "$comma_install_packs_code" -eq 2 ]] || fail "install rejects a comma-only pack list"
assert_not_file "$invalid_install_target/.dev-workflow/manifest.json" "rejected pack lists do not install Core"

core_only_target="$temp_root/core-only"
mkdir -p "$core_only_target"
bash "$install_script" --target "$core_only_target" >/dev/null
core_only_manifest="$core_only_target/.dev-workflow/manifest.json"
assert_no_installed_packs "$core_only_manifest" "Core-only install records an empty pack list"
core_only_manifest_hash="$(sha256_file "$core_only_manifest")"

set +e
bash "$audit_script" --target "$core_only_target" >/dev/null
core_only_audit_code=$?
bash "$uninstall_script" --target "$core_only_target" --packs architecture >/dev/null 2>&1
core_only_pack_uninstall_code=$?
bash "$uninstall_script" --target "$core_only_target" --packs "" >/dev/null 2>&1
empty_uninstall_packs_code=$?
bash "$uninstall_script" --target "$core_only_target" --packs "   " >/dev/null 2>&1
blank_uninstall_packs_code=$?
bash "$uninstall_script" --target "$core_only_target" --packs ",,," >/dev/null 2>&1
comma_uninstall_packs_code=$?
set -e
[[ "$core_only_audit_code" -eq 2 ]] || fail "Core-only pending install returns audit exit code 2"
[[ "$core_only_pack_uninstall_code" -eq 2 ]] || fail "Core-only uninstall reports an uninstalled requested pack"
[[ "$empty_uninstall_packs_code" -eq 2 ]] || fail "uninstall rejects an empty explicit pack list"
[[ "$blank_uninstall_packs_code" -eq 2 ]] || fail "uninstall rejects a whitespace-only pack list"
[[ "$comma_uninstall_packs_code" -eq 2 ]] || fail "uninstall rejects a comma-only pack list"
assert_file "$core_only_manifest" "rejected Core-only partial uninstall preserves manifest"
[[ "$(sha256_file "$core_only_manifest")" == "$core_only_manifest_hash" ]] || fail "rejected pack lists leave the manifest unchanged"
assert_file "$core_only_target/AGENTS.md" "rejected pack lists preserve Core files"
bash "$uninstall_script" --target "$core_only_target" >/dev/null
assert_not_file "$core_only_manifest" "Core-only full uninstall removes manifest"

single_pack_target="$temp_root/single-pack"
mkdir -p "$single_pack_target"
bash "$install_script" --target "$single_pack_target" --packs architecture >/dev/null
single_pack_manifest="$single_pack_target/.dev-workflow/manifest.json"
bash "$uninstall_script" --target "$single_pack_target" --packs architecture >/dev/null
assert_no_installed_packs "$single_pack_manifest" "removing the last pack records an empty pack list"

set +e
bash "$audit_script" --target "$single_pack_target" >/dev/null
single_pack_audit_code=$?
set -e
[[ "$single_pack_audit_code" -eq 2 ]] || fail "Core remains valid after removing the last pack"
bash "$uninstall_script" --target "$single_pack_target" >/dev/null
assert_not_file "$single_pack_manifest" "full uninstall removes manifest after the last pack is removed"

feature_pack_target="$temp_root/feature-pack"
mkdir -p "$feature_pack_target"
bash "$install_script" --target "$feature_pack_target" --packs feature-catalog >/dev/null
feature_pack_manifest="$feature_pack_target/.dev-workflow/manifest.json"
python3 "$feature_pack_target/scripts/feature_catalog.py" --root "$feature_pack_target" --init >/dev/null
python3 "$feature_pack_target/scripts/feature_catalog.py" --root "$feature_pack_target" --generate >/dev/null
bash "$uninstall_script" --target "$feature_pack_target" --packs feature-catalog >/dev/null
assert_no_installed_packs "$feature_pack_manifest" "removing feature-catalog leaves a Core-only manifest"
assert_not_file "$feature_pack_target/scripts/feature_catalog.py" "partial uninstall removes unchanged feature-catalog tool"
assert_file "$feature_pack_target/docs/development/ai/feature-catalog.json" "partial uninstall preserves active feature catalog"
assert_file "$feature_pack_target/docs/FEATURE-MATRIX.md" "partial uninstall preserves generated feature matrix"
bash "$uninstall_script" --target "$feature_pack_target" >/dev/null
assert_not_file "$feature_pack_manifest" "full uninstall removes Core manifest after feature pack removal"
assert_file "$feature_pack_target/docs/development/ai/feature-catalog.json" "Core uninstall still preserves active feature catalog"

existing_target="$temp_root/existing"
mkdir -p "$existing_target/docs"
printf '# Existing project rules\n' > "$existing_target/AGENTS.md"
printf '# Existing tasks\n' > "$existing_target/docs/TASKS.md"
bash "$install_script" --target "$existing_target" >/dev/null
existing_manifest="$existing_target/.dev-workflow/manifest.json"
grep -Eq '"path":"AGENTS.md","source":"core","action":"appended"' "$existing_manifest" || fail "existing AGENTS records appended ownership"
grep -Eq '"path":"docs/TASKS.md","source":"core","action":"preserved"' "$existing_manifest" || fail "pre-existing files record preserved ownership"
grep -Fq '## 大型计划拆分与确认门' "$existing_target/AGENTS.md" || fail "existing AGENTS receives the large-plan approval gate"
grep -Fq '## 交付治理与权限策略' "$existing_target/AGENTS.md" || fail "existing AGENTS receives the delivery governance policy"

bash "$uninstall_script" --target "$existing_target" >/dev/null
grep -Fq '# Existing project rules' "$existing_target/AGENTS.md" || fail "existing AGENTS content is preserved"
grep -Fq 'AI-WORKFLOW:CORE:START' "$existing_target/AGENTS.md" && fail "managed AGENTS core block is removed"
assert_file "$existing_target/docs/TASKS.md" "pre-existing files survive uninstall"

blank_agents_target="$temp_root/blank-agents"
mkdir -p "$blank_agents_target"
printf '\n' > "$blank_agents_target/AGENTS.md"
bash "$install_script" --target "$blank_agents_target" >/dev/null
bash "$uninstall_script" --target "$blank_agents_target" >/dev/null
assert_file "$blank_agents_target/AGENTS.md" "a pre-existing blank AGENTS.md is not deleted"

tampered_target="$temp_root/tampered"
mkdir -p "$tampered_target"
bash "$install_script" --target "$tampered_target" >/dev/null
tampered_manifest="$tampered_target/.dev-workflow/manifest.json"
tampered_tmp="$tampered_manifest.tampered"
sed -E 's/("path":"docs\/TASKS.md","source":)"core"/\1"uninstalled-pack"/' "$tampered_manifest" > "$tampered_tmp"
mv -- "$tampered_tmp" "$tampered_manifest"

set +e
bash "$audit_script" --target "$tampered_target" >/dev/null
tampered_audit_code=$?
bash "$install_script" --target "$tampered_target" >/dev/null 2>&1
tampered_install_code=$?
bash "$uninstall_script" --target "$tampered_target" >/dev/null 2>&1
tampered_uninstall_code=$?
set -e
[[ "$tampered_audit_code" -eq 1 ]] || fail "audit rejects inventory assigned to an uninstalled pack"
[[ "$tampered_install_code" -ne 0 ]] || fail "installer rejects inventory assigned to an uninstalled pack"
[[ "$tampered_uninstall_code" -ne 0 ]] || fail "uninstaller rejects inventory assigned to an uninstalled pack"
assert_file "$tampered_target/docs/TASKS.md" "rejected uninstall leaves managed files untouched"

extra_path_target="$temp_root/extra-paths"
mkdir -p "$extra_path_target"
bash "$install_script" --target "$extra_path_target" --packs architecture >/dev/null
extra_core_path="$extra_path_target/USER-NOTES.md"
extra_pack_path="$extra_path_target/PACK-NOTES.md"
printf 'User-owned core note.\n' > "$extra_core_path"
printf 'User-owned pack note.\n' > "$extra_pack_path"
extra_manifest="$extra_path_target/.dev-workflow/manifest.json"
extra_manifest_tmp="$extra_manifest.extra"
extra_core_hash="$(sha256_file "$extra_core_path")"
extra_pack_hash="$(sha256_file "$extra_pack_path")"
awk -v core_hash="$extra_core_hash" -v pack_hash="$extra_pack_hash" '
  { print }
  /"path":"AGENTS.md"/ {
    print "    {\"path\":\"USER-NOTES.md\",\"source\":\"core\",\"action\":\"created\",\"installedSha256\":\"" core_hash "\"},"
    print "    {\"path\":\"PACK-NOTES.md\",\"source\":\"architecture\",\"action\":\"created\",\"installedSha256\":\"" pack_hash "\"},"
  }
' "$extra_manifest" > "$extra_manifest_tmp"
mv -- "$extra_manifest_tmp" "$extra_manifest"

set +e
bash "$audit_script" --target "$extra_path_target" >/dev/null
extra_audit_code=$?
bash "$install_script" --target "$extra_path_target" >/dev/null 2>&1
extra_install_code=$?
bash "$uninstall_script" --target "$extra_path_target" >/dev/null 2>&1
extra_uninstall_code=$?
set -e
[[ "$extra_audit_code" -eq 1 ]] || fail "audit rejects inventory paths outside their workflow overlays"
[[ "$extra_install_code" -ne 0 ]] || fail "installer rejects inventory paths outside their workflow overlays"
[[ "$extra_uninstall_code" -ne 0 ]] || fail "uninstaller rejects inventory paths outside their workflow overlays"
assert_file "$extra_core_path" "rejected uninstall preserves a forged Core-owned user file"
assert_file "$extra_pack_path" "rejected uninstall preserves a forged pack-owned user file"

forged_ownership_target="$temp_root/forged-ownership"
mkdir -p "$forged_ownership_target/docs/architecture"
forged_core_path="$forged_ownership_target/docs/TASKS.md"
forged_pack_path="$forged_ownership_target/docs/architecture/SYSTEM.md"
printf 'Pre-existing tasks.\n' > "$forged_core_path"
printf 'Pre-existing architecture.\n' > "$forged_pack_path"
bash "$install_script" --target "$forged_ownership_target" --packs architecture >/dev/null
forged_manifest="$forged_ownership_target/.dev-workflow/manifest.json"
grep -Eq '"path":"docs/TASKS.md","source":"core","action":"preserved"' "$forged_manifest" || fail "pre-existing Core files start as preserved"
grep -Eq '"path":"docs/architecture/SYSTEM.md","source":"architecture","action":"preserved"' "$forged_manifest" || fail "pre-existing pack files start as preserved"
forged_core_hash="$(sha256_file "$forged_core_path")"
forged_pack_hash="$(sha256_file "$forged_pack_path")"
forged_manifest_tmp="$forged_manifest.forged"
awk -v core_hash="$forged_core_hash" -v pack_hash="$forged_pack_hash" '
  /"path":"docs\/TASKS.md"/ {
    sub(/"action":"preserved"/, "\"action\":\"created\"")
    sub(/"installedSha256":null/, "\"installedSha256\":\"" core_hash "\"")
  }
  /"path":"docs\/architecture\/SYSTEM.md"/ {
    sub(/"action":"preserved"/, "\"action\":\"created\"")
    sub(/"installedSha256":null/, "\"installedSha256\":\"" pack_hash "\"")
  }
  { print }
' "$forged_manifest" > "$forged_manifest_tmp"
mv -- "$forged_manifest_tmp" "$forged_manifest"

set +e
bash "$audit_script" --target "$forged_ownership_target" >/dev/null
forged_audit_code=$?
bash "$install_script" --target "$forged_ownership_target" >/dev/null 2>&1
forged_install_code=$?
bash "$uninstall_script" --target "$forged_ownership_target" >/dev/null 2>&1
forged_uninstall_code=$?
set -e
[[ "$forged_audit_code" -eq 1 ]] || fail "audit rejects forged created ownership for real overlay paths"
[[ "$forged_install_code" -ne 0 ]] || fail "installer rejects forged created ownership for real overlay paths"
[[ "$forged_uninstall_code" -ne 0 ]] || fail "uninstaller rejects forged created ownership for real overlay paths"
assert_file "$forged_core_path" "forged Core ownership cannot delete a pre-existing user file"
assert_file "$forged_pack_path" "forged pack ownership cannot delete a pre-existing user file"

schema3_target="$temp_root/schema3-upgrade"
mkdir -p "$schema3_target"
bash "$install_script" --target "$schema3_target" >/dev/null
schema3_manifest="$schema3_target/.dev-workflow/manifest.json"
schema3_tmp="$schema3_manifest.old"
awk '
  /"schemaVersion"[[:space:]]*:/ { sub(/5/, "3") }
  /"pushActor"[[:space:]]*:/ { sub(/"user"/, "\"ai\"") }
  /"mergeActor"[[:space:]]*:/ { sub(/"user"/, "\"ai\"") }
  /"pullRequestMode"|"pullRequestActor"|"pullRequestRequired"|"ciRequired"|"independentReviewRequired"|"forcePushAllowed"|"directProtectedBranchPushAllowed"|"privilegedOperationsDefault"|"policyChangedAt"|"policyChangedBy"/ { next }
  /"deleteAllowed"[[:space:]]*:/ { sub(/,[[:space:]]*$/, "") }
  { print }
' "$schema3_manifest" > "$schema3_tmp"
mv -- "$schema3_tmp" "$schema3_manifest"
bash "$install_script" --target "$schema3_target" >/dev/null
grep -Eq '"schemaVersion"[[:space:]]*:[[:space:]]*5' "$schema3_manifest" || fail "schema 3 manifests upgrade to schema 5"
assert_json_string "$schema3_manifest" pushMode manual "schema 3 upgrade preserves push mode"
assert_json_string "$schema3_manifest" pushActor ai "schema 3 upgrade preserves push actor"
assert_json_string "$schema3_manifest" mergeMode manual "schema 3 upgrade preserves merge mode"
assert_json_string "$schema3_manifest" mergeActor ai "schema 3 upgrade preserves merge actor"
assert_v4_safety_defaults "$schema3_manifest" "schema 3 upgrade"
assert_json_string "$schema3_manifest" policyChangedBy migration "schema 3 upgrade records migration as the policy origin"

schema2_target="$temp_root/schema2-upgrade"
mkdir -p "$schema2_target"
bash "$install_script" --target "$schema2_target" >/dev/null
schema2_manifest="$schema2_target/.dev-workflow/manifest.json"
schema2_tmp="$schema2_manifest.old"
awk '
  /"schemaVersion"[[:space:]]*:/ { sub(/5/, "2") }
  /"workflowVersion"[[:space:]]*:/ { sub(/"[^"]+"[[:space:]]*,[[:space:]]*$/, "\"0.1.9\",") }
  /"pushActor"[[:space:]]*:/ { sub(/"user"/, "\"ai\"") }
  /"mergeActor"[[:space:]]*:/ { sub(/"user"/, "\"ai\"") }
  /"pullRequestMode"|"pullRequestActor"|"pullRequestRequired"|"ciRequired"|"independentReviewRequired"|"forcePushAllowed"|"directProtectedBranchPushAllowed"|"privilegedOperationsDefault"|"policyChangedAt"|"policyChangedBy"/ { next }
  /"deleteAllowed"[[:space:]]*:/ { sub(/,[[:space:]]*$/, "") }
  /"path":"docs\/TASKS.md"/ { sub(/"installedSha256":"[0-9a-f]{64}"/, "\"installedSha256\":\"0000000000000000000000000000000000000000000000000000000000000000\"") }
  { print }
' "$schema2_manifest" > "$schema2_tmp"
mv -- "$schema2_tmp" "$schema2_manifest"
bash "$install_script" --target "$schema2_target" >/dev/null
grep -Eq '"path":"docs/TASKS.md","source":"core","action":"legacy","installedSha256":null' "$schema2_manifest" || fail "changed created ownership becomes legacy during a version upgrade"
grep -Eq '"schemaVersion"[[:space:]]*:[[:space:]]*5' "$schema2_manifest" || fail "schema 2 manifests upgrade to schema 5"
grep -Eq "\"workflowVersion\"[[:space:]]*:[[:space:]]*\"$workflow_version\"" "$schema2_manifest" || fail "schema 2 upgrade records current workflow version"
assert_json_string "$schema2_manifest" pushMode manual "schema 2 upgrade preserves push mode"
assert_json_string "$schema2_manifest" pushActor ai "schema 2 upgrade preserves push actor"
assert_json_string "$schema2_manifest" mergeMode manual "schema 2 upgrade preserves merge mode"
assert_json_string "$schema2_manifest" mergeActor ai "schema 2 upgrade preserves merge actor"
assert_v4_safety_defaults "$schema2_manifest" "schema 2 upgrade"
assert_json_string "$schema2_manifest" policyChangedBy migration "schema 2 upgrade records migration as the policy origin"

legacy_target="$temp_root/schema1-upgrade"
mkdir -p "$legacy_target"
bash "$install_script" --target "$legacy_target" --packs architecture >/dev/null
legacy_manifest="$legacy_target/.dev-workflow/manifest.json"
legacy_tmp="$legacy_manifest.legacy"
awk '
  /"schemaVersion"[[:space:]]*:/ { sub(/5/, "1") }
  /"gitPolicy"[[:space:]]*:[[:space:]]*\{/ { skipping_policy=1; next }
  skipping_policy && /^[[:space:]]*\},[[:space:]]*$/ { skipping_policy=0; next }
  /"files"[[:space:]]*:[[:space:]]*\[/ { skipping_files=1; next }
  skipping_files && /^[[:space:]]*\],[[:space:]]*$/ { skipping_files=0; next }
  !skipping_policy && !skipping_files { print }
' "$legacy_manifest" > "$legacy_tmp"
mv -- "$legacy_tmp" "$legacy_manifest"

bash "$install_script" --target "$legacy_target" >/dev/null
grep -Eq '"schemaVersion"[[:space:]]*:[[:space:]]*5' "$legacy_manifest" || fail "schema 1 manifests upgrade to schema 5"
assert_json_string "$legacy_manifest" pushMode manual "schema 1 upgrade adds safe push mode"
assert_json_string "$legacy_manifest" pushActor user "schema 1 upgrade adds safe push actor"
assert_json_string "$legacy_manifest" mergeMode manual "schema 1 upgrade adds safe merge mode"
assert_json_string "$legacy_manifest" mergeActor user "schema 1 upgrade adds safe merge actor"
assert_v4_safety_defaults "$legacy_manifest" "schema 1 upgrade"
assert_json_string "$legacy_manifest" policyChangedBy migration "schema 1 upgrade records migration as the policy origin"
grep -Eq '"path":"docs/architecture/SYSTEM.md","source":"architecture","action":"legacy"' "$legacy_manifest" || fail "legacy pack files remain conservatively owned"

echo 'Bash integration tests passed.'
