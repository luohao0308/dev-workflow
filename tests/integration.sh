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
bash "$install_script" --target "$fresh_target" --all-packs >/dev/null
fresh_manifest="$fresh_target/.dev-workflow/manifest.json"
assert_file "$fresh_manifest" "new install creates manifest"
grep -Eq '"schemaVersion"[[:space:]]*:[[:space:]]*3' "$fresh_manifest" || fail "new installs use schema 3"
grep -Eq '"pushMode"[[:space:]]*:[[:space:]]*"manual"' "$fresh_manifest" || fail "push defaults to manual approval"
grep -Eq '"pushActor"[[:space:]]*:[[:space:]]*"user"' "$fresh_manifest" || fail "push defaults to user execution"
grep -Eq '"mergeMode"[[:space:]]*:[[:space:]]*"manual"' "$fresh_manifest" || fail "merge defaults to manual approval"
grep -Eq '"mergeActor"[[:space:]]*:[[:space:]]*"user"' "$fresh_manifest" || fail "merge defaults to user execution"
grep -Eq '"deleteAllowed"[[:space:]]*:[[:space:]]*false' "$fresh_manifest" || fail "delete is always denied"
grep -Eq '"path":"AGENTS.md","source":"core","action":"created"' "$fresh_manifest" || fail "new installs record created ownership"
grep -Fq '## 大型计划拆分与确认门' "$fresh_target/AGENTS.md" || fail "Core install includes the large-plan approval gate"
grep -Fq '## 默认开发闭环（轻量核心 + 风险插件）' "$fresh_target/AGENTS.md" || fail "Core install includes the lightweight development loop"
grep -Fq '## Git 交付权限策略' "$fresh_target/AGENTS.md" || fail "Core install includes the Git delivery permission policy"
grep -Fq 'awaiting_user_confirmation' "$fresh_target/docs/plans/README.md" || fail "delivery plans expose the approval state"
grep -Fq '## 7. 偏移控制' "$fresh_target/docs/plans/TEMPLATE.md" || fail "delivery plan template includes drift control"
grep -Fq 'Test/Eval/Check' "$fresh_target/docs/plans/TEMPLATE.md" || fail "delivery plan template maps claims to executable checks"
grep -Fq 'codex/*' "$fresh_target/docs/development/GIT-WORKTREE-WORKFLOW.md" || fail "delivery workflow protects local Codex branches"
grep -Eq '"path":"scripts/feature_catalog.py","source":"feature-catalog"' "$fresh_manifest" || fail "all-packs installs feature-catalog ownership"
grep -Fq '# BEGIN dev-workflow managed excludes' "$fresh_target/.git/info/exclude" || fail "install adds a managed Git exclude block"
grep -Fq '/.dev-workflow/' "$fresh_target/.git/info/exclude" || fail "Git exclude hides dev-workflow metadata"
grep -Fq '/docs/README.md' "$fresh_target/.git/info/exclude" || fail "Git exclude hides a created Core file"
grep -Fq '# user exclude' "$fresh_target/.git/info/exclude" || fail "install preserves user Git excludes"
git -C "$fresh_target" check-ignore -q -- .dev-workflow/manifest.json || fail "Git check-ignore matches dev-workflow metadata"
git -C "$fresh_target" check-ignore -q -- docs/README.md || fail "Git check-ignore matches created workflow files"
while IFS= read -r installed_path; do
  [[ -n "$installed_path" ]] || continue
  git -C "$fresh_target" check-ignore -q -- "$installed_path" || fail "Git excludes every installer-created path: $installed_path"
done < <(sed -n -E 's/.*"path":"([^"]+)".*"action":"created".*/\1/p' "$fresh_manifest")
[[ "$(sha256_file "$fresh_target/.gitignore")" == "$gitignore_hash_before_install" ]] || fail "install does not modify project .gitignore"

automated_git_target="$temp_root/automated-git"
mkdir -p "$automated_git_target"
bash "$install_script" \
  --target "$automated_git_target" \
  --push-mode auto \
  --push-actor ai \
  --merge-mode auto \
  --merge-actor ai >/dev/null
automated_git_manifest="$automated_git_target/.dev-workflow/manifest.json"
grep -Eq '"pushMode"[[:space:]]*:[[:space:]]*"auto"' "$automated_git_manifest" || fail "explicit push automation is recorded"
grep -Eq '"pushActor"[[:space:]]*:[[:space:]]*"ai"' "$automated_git_manifest" || fail "explicit AI push actor is recorded"
grep -Eq '"mergeMode"[[:space:]]*:[[:space:]]*"auto"' "$automated_git_manifest" || fail "explicit merge automation is recorded"
grep -Eq '"mergeActor"[[:space:]]*:[[:space:]]*"ai"' "$automated_git_manifest" || fail "explicit AI merge actor is recorded"
grep -Eq '"deleteAllowed"[[:space:]]*:[[:space:]]*false' "$automated_git_manifest" || fail "delete remains denied when Git automation is enabled"
bash "$install_script" --target "$automated_git_target" >/dev/null
grep -Eq '"pushMode"[[:space:]]*:[[:space:]]*"auto"' "$automated_git_manifest" || fail "reinstall preserves explicit push automation"
grep -Eq '"mergeMode"[[:space:]]*:[[:space:]]*"auto"' "$automated_git_manifest" || fail "reinstall preserves explicit merge automation"

tampered_delete_manifest="$automated_git_manifest.tampered"
sed -E 's/"deleteAllowed"[[:space:]]*:[[:space:]]*false/"deleteAllowed": true/' "$automated_git_manifest" > "$tampered_delete_manifest"
mv -- "$tampered_delete_manifest" "$automated_git_manifest"
set +e
bash "$audit_script" --target "$automated_git_target" >/dev/null
tampered_delete_code=$?
set -e
[[ "$tampered_delete_code" -eq 1 ]] || fail "audit rejects granted delete permission"

invalid_git_target="$temp_root/invalid-git"
mkdir -p "$invalid_git_target"
set +e
bash "$install_script" --target "$invalid_git_target" --push-mode auto --push-actor user >/dev/null 2>&1
invalid_git_code=$?
set -e
[[ "$invalid_git_code" -ne 0 ]] || fail "automatic push with a user actor is rejected"
assert_not_file "$invalid_git_target/.dev-workflow/manifest.json" "invalid Git policy does not write a manifest"

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
[[ "$strict_audit_code" -eq 0 ]] || fail "completed schema 3 install passes strict audit"

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
bash "$uninstall_script" --target "$fresh_target" --packs delivery --dry-run >/dev/null
assert_file "$fresh_target/docs/plans/TEMPLATE.md" "dry-run does not delete files"

bash "$uninstall_script" --target "$fresh_target" --packs delivery >/dev/null
assert_file "$modified_delivery_file" "modified managed files are preserved"
assert_not_file "$fresh_target/docs/plans/TEMPLATE.md" "unchanged pack files are deleted"
if tr -d '\r\n' < "$fresh_manifest" | grep -Eq '"installedPacks"[[:space:]]*:[[:space:]]*\[[^]]*"delivery"'; then
  fail "partial uninstall removes pack from manifest"
fi
grep -Fq '"source":"delivery"' "$fresh_manifest" && fail "partial uninstall removes pack inventory entries"
grep -Eq '"pushMode"[[:space:]]*:[[:space:]]*"manual"' "$fresh_manifest" || fail "partial uninstall preserves push policy"
grep -Eq '"mergeActor"[[:space:]]*:[[:space:]]*"user"' "$fresh_manifest" || fail "partial uninstall preserves merge policy"
grep -Eq '"deleteAllowed"[[:space:]]*:[[:space:]]*false' "$fresh_manifest" || fail "partial uninstall preserves denied delete permission"
grep -Fq '/docs/README.md' "$fresh_target/.git/info/exclude" || fail "partial uninstall preserves Core Git excludes"
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

upgrade_target="$temp_root/schema2-upgrade"
mkdir -p "$upgrade_target"
bash "$install_script" --target "$upgrade_target" >/dev/null
upgrade_manifest="$upgrade_target/.dev-workflow/manifest.json"
upgrade_manifest_without_policy="$upgrade_manifest.without-policy"
awk '
  /"gitPolicy"[[:space:]]*:[[:space:]]*\{/ { skipping_policy=1; next }
  skipping_policy && /^[[:space:]]*\},[[:space:]]*$/ { skipping_policy=0; next }
  !skipping_policy { print }
' "$upgrade_manifest" > "$upgrade_manifest_without_policy"
upgrade_manifest_tmp="$upgrade_manifest.old"
sed -E \
  -e 's/"schemaVersion"[[:space:]]*:[[:space:]]*3/"schemaVersion": 2/' \
  -e 's/"workflowVersion"[[:space:]]*:[[:space:]]*"[^"]+"/"workflowVersion": "0.1.9"/' \
  -e '/"path":"docs\/TASKS.md"/ s/"installedSha256":"[0-9a-f]{64}"/"installedSha256":"0000000000000000000000000000000000000000000000000000000000000000"/' \
  "$upgrade_manifest_without_policy" > "$upgrade_manifest_tmp"
mv -- "$upgrade_manifest_tmp" "$upgrade_manifest"
bash "$install_script" --target "$upgrade_target" >/dev/null
grep -Eq '"path":"docs/TASKS.md","source":"core","action":"legacy","installedSha256":null' "$upgrade_manifest" || fail "changed created ownership becomes legacy during a version upgrade"
grep -Eq '"schemaVersion"[[:space:]]*:[[:space:]]*3' "$upgrade_manifest" || fail "schema 2 manifests upgrade to schema 3"
grep -Eq "\"workflowVersion\"[[:space:]]*:[[:space:]]*\"$workflow_version\"" "$upgrade_manifest" || fail "schema 2 upgrade records current workflow version"
grep -Eq '"pushMode"[[:space:]]*:[[:space:]]*"manual"' "$upgrade_manifest" || fail "upgrade adds safe push policy when missing"
grep -Eq '"mergeActor"[[:space:]]*:[[:space:]]*"user"' "$upgrade_manifest" || fail "upgrade adds safe merge actor when missing"

legacy_target="$temp_root/legacy"
mkdir -p "$legacy_target"
bash "$install_script" --target "$legacy_target" --packs architecture >/dev/null
legacy_manifest="$legacy_target/.dev-workflow/manifest.json"
legacy_tmp="$legacy_manifest.legacy"
awk '
  /"schemaVersion"[[:space:]]*:[[:space:]]*3/ { sub(/3/, "1") }
  /"gitPolicy"[[:space:]]*:[[:space:]]*\{/ { skipping_policy=1; next }
  skipping_policy && /^[[:space:]]*\},[[:space:]]*$/ { skipping_policy=0; next }
  /"files"[[:space:]]*:[[:space:]]*\[/ { skipping=1; next }
  skipping && /^[[:space:]]*\],[[:space:]]*$/ { skipping=0; next }
  !skipping && !skipping_policy { print }
' "$legacy_manifest" > "$legacy_tmp"
mv -- "$legacy_tmp" "$legacy_manifest"

bash "$install_script" --target "$legacy_target" >/dev/null
grep -Eq '"schemaVersion"[[:space:]]*:[[:space:]]*3' "$legacy_manifest" || fail "legacy manifests migrate to schema 3"
grep -Eq '"path":"docs/architecture/SYSTEM.md","source":"architecture","action":"legacy"' "$legacy_manifest" || fail "legacy pack files remain conservatively owned"

echo 'Bash integration tests passed.'
