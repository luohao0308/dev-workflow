#!/usr/bin/env bash
set -euo pipefail

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
bash "$install_script" --target "$fresh_target" --all-packs >/dev/null
fresh_manifest="$fresh_target/.dev-workflow/manifest.json"
assert_file "$fresh_manifest" "new install creates manifest"
grep -Eq '"schemaVersion"[[:space:]]*:[[:space:]]*2' "$fresh_manifest" || fail "new installs use schema 2"
grep -Eq '"path":"AGENTS.md","source":"core","action":"created"' "$fresh_manifest" || fail "new installs record created ownership"

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
set +e
bash "$audit_script" --target "$fresh_target" --strict >/dev/null
strict_audit_code=$?
set -e
[[ "$strict_audit_code" -eq 0 ]] || fail "completed schema 2 install passes strict audit"

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

bash "$uninstall_script" --target "$fresh_target" >/dev/null
assert_not_file "$fresh_manifest" "full uninstall removes manifest"
assert_file "$modified_delivery_file" "project-modified content remains after full uninstall"

existing_target="$temp_root/existing"
mkdir -p "$existing_target/docs"
printf '# Existing project rules\n' > "$existing_target/AGENTS.md"
printf '# Existing tasks\n' > "$existing_target/docs/TASKS.md"
bash "$install_script" --target "$existing_target" >/dev/null
existing_manifest="$existing_target/.dev-workflow/manifest.json"
grep -Eq '"path":"AGENTS.md","source":"core","action":"appended"' "$existing_manifest" || fail "existing AGENTS records appended ownership"
grep -Eq '"path":"docs/TASKS.md","source":"core","action":"preserved"' "$existing_manifest" || fail "pre-existing files record preserved ownership"

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
upgrade_manifest_tmp="$upgrade_manifest.old"
sed -E \
  -e 's/"workflowVersion"[[:space:]]*:[[:space:]]*"[^"]+"/"workflowVersion": "0.1.9"/' \
  -e '/"path":"docs\/TASKS.md"/ s/"installedSha256":"[0-9a-f]{64}"/"installedSha256":"0000000000000000000000000000000000000000000000000000000000000000"/' \
  "$upgrade_manifest" > "$upgrade_manifest_tmp"
mv -- "$upgrade_manifest_tmp" "$upgrade_manifest"
bash "$install_script" --target "$upgrade_target" >/dev/null
grep -Eq '"path":"docs/TASKS.md","source":"core","action":"legacy","installedSha256":null' "$upgrade_manifest" || fail "changed created ownership becomes legacy during a version upgrade"
grep -Eq "\"workflowVersion\"[[:space:]]*:[[:space:]]*\"$workflow_version\"" "$upgrade_manifest" || fail "schema 2 upgrade records current workflow version"

legacy_target="$temp_root/legacy"
mkdir -p "$legacy_target"
bash "$install_script" --target "$legacy_target" --packs architecture >/dev/null
legacy_manifest="$legacy_target/.dev-workflow/manifest.json"
legacy_tmp="$legacy_manifest.legacy"
awk '
  /"schemaVersion"[[:space:]]*:[[:space:]]*2/ { sub(/2/, "1") }
  /"files"[[:space:]]*:[[:space:]]*\[/ { skipping=1; next }
  skipping && /^[[:space:]]*\],[[:space:]]*$/ { skipping=0; next }
  !skipping { print }
' "$legacy_manifest" > "$legacy_tmp"
mv -- "$legacy_tmp" "$legacy_manifest"

bash "$install_script" --target "$legacy_target" >/dev/null
grep -Eq '"schemaVersion"[[:space:]]*:[[:space:]]*2' "$legacy_manifest" || fail "legacy manifests migrate to schema 2"
grep -Eq '"path":"docs/architecture/SYSTEM.md","source":"architecture","action":"legacy"' "$legacy_manifest" || fail "legacy pack files remain conservatively owned"

echo 'Bash integration tests passed.'
