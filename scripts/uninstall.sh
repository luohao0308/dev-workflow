#!/usr/bin/env bash
set -euo pipefail

# Bash 3.2 treats an empty array expansion as unbound under `set -u`.
# The `${items[@]+"${items[@]}"}` form expands all items, or nothing when empty.

usage() {
  cat <<'EOF'
用法：
  bash scripts/uninstall.sh --target /path/to/project [options]

选项：
  --packs delivery,operations  只卸载指定流程包（至少一个名称）；不提供时卸载 Core 和全部流程包
  --dry-run                    只显示动作，不写文件
  -h, --help                   显示帮助

说明：
  只删除安装后未修改的受管文件。已修改、安装前已存在或旧版来源不明的文件会保留。
  AGENTS.md 只移除 AI-WORKFLOW 受管核心区块。
EOF
}

json_string_field() {
  local field="$1"
  local path="$2"
  sed -n -E "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\1/p" "$path" | head -n 1
}

json_number_field() {
  local field="$1"
  local path="$2"
  sed -n -E "s/.*\"$field\"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p" "$path" | head -n 1
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

contains_item() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print tolower($1)}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print tolower($1)}'
    return
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$path" | sed -E 's/^.*= //' | tr '[:upper:]' '[:lower:]'
    return
  fi
  echo "缺少 SHA-256 工具（需要 sha256sum、shasum 或 openssl）。" >&2
  exit 1
}

read_manifest_packs() {
  local path="$1"
  local compact
  local segment
  local residual
  compact="$(tr -d '\r\n' < "$path")"
  if ! printf '%s' "$compact" | grep -Eq '"installedPacks"[[:space:]]*:[[:space:]]*\[[^]]*\]'; then
    return 1
  fi
  segment="$(printf '%s' "$compact" | sed -n -E 's/.*"installedPacks"[[:space:]]*:[[:space:]]*\[([^]]*)\].*/\1/p')"
  residual="$(printf '%s' "$segment" | sed -E 's/"[0-9A-Za-z._-]+"//g; s/[[:space:],]//g')"
  [[ -z "$residual" ]] || return 1
  printf '%s' "$segment" |
    tr ',' '\n' |
    sed -n -E 's/^[[:space:]]*"([0-9A-Za-z._-]+)"[[:space:]]*$/\1/p'
}

read_manifest_file_objects() {
  local path="$1"
  awk '
    /"files"[[:space:]]*:[[:space:]]*\[/ { in_files=1; next }
    in_files {
      if (!in_object && $0 ~ /^[[:space:]]*\]/) { exit }
      if (!in_object && index($0, "{") > 0) {
        in_object=1
        object=$0
      } else if (in_object) {
        object=object " " $0
      }
      if (in_object && index($0, "}") > 0) {
        gsub(/[[:space:]]+/, " ", object)
        print object
        in_object=0
        object=""
      }
    }
  ' "$path"
}

read_manifest_files() {
  local path="$1"
  local object
  local entry_path
  local source
  local action
  local hash
  local count=0
  while IFS= read -r object; do
    [[ -n "$object" ]] || continue
    entry_path="$(printf '%s' "$object" | sed -n -E 's/.*"path"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p')"
    source="$(printf '%s' "$object" | sed -n -E 's/.*"source"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p')"
    action="$(printf '%s' "$object" | sed -n -E 's/.*"action"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p')"
    hash="$(printf '%s' "$object" | sed -n -E 's/.*"installedSha256"[[:space:]]*:[[:space:]]*"([0-9A-Fa-f]+)".*/\1/p' | tr '[:upper:]' '[:lower:]')"
    [[ -n "$entry_path" && -n "$source" && -n "$action" ]] || return 1
    case "$entry_path" in
      /*|../*|*/../*|*/..|*'|'*|*$'\t'*|*$'\r'*|*$'\n'*) return 1 ;;
    esac
    case "$action" in
      created|appended|managed-block|preserved|legacy) ;;
      *) return 1 ;;
    esac
    if [[ "$action" == "created" && ! "$hash" =~ ^[0-9a-f]{64}$ ]]; then
      return 1
    fi
    if [[ "$action" != "created" && -n "$hash" ]]; then
      return 1
    fi
    printf '%s|%s|%s|%s\n' "$entry_path" "$source" "$action" "$hash"
    count=$((count + 1))
  done < <(read_manifest_file_objects "$path")
  [[ "$count" -gt 0 ]]
}

inventory_index() {
  local needle="$1"
  local index
  for index in "${!file_paths[@]}"; do
    if [[ "${file_paths[$index]}" == "$needle" ]]; then
      printf '%s' "$index"
      return 0
    fi
  done
  return 1
}

set_inventory() {
  local path="$1"
  local source="$2"
  local action="$3"
  local hash="$4"
  local index
  if index="$(inventory_index "$path")"; then
    file_sources[$index]="$source"
    file_actions[$index]="$action"
    file_hashes[$index]="$hash"
  else
    file_paths+=("$path")
    file_sources+=("$source")
    file_actions+=("$action")
    file_hashes+=("$hash")
  fi
}

inventory_summary() {
  local index
  for index in "${!file_paths[@]}"; do
    printf '%s|%s|%s|%s\n' \
      "${file_paths[$index]}" \
      "${file_sources[$index]}" \
      "${file_actions[$index]}" \
      "${file_hashes[$index]}"
  done | LC_ALL=C sort
}

build_manifest() {
  local version="$1"
  local installed_at="$2"
  local updated_at="$3"
  local onboarding_status="$4"
  local last_audit_at="$5"
  local pack
  local packs_json=""
  for pack in "${installed_packs[@]+"${installed_packs[@]}"}"; do
    [[ -n "$packs_json" ]] && packs_json+=","
    packs_json+=$'\n    '"\"$(json_escape "$pack")\""
  done
  local last_audit_json="null"
  [[ -n "$last_audit_at" ]] && last_audit_json="\"$(json_escape "$last_audit_at")\""
  cat <<EOF
{
  "schemaVersion": 2,
  "managedBy": "dev-workflow",
  "workflowVersion": "$(json_escape "$version")",
  "installedPacks": [$packs_json
  ],
  "files": [
EOF
  local sorted_inventory
  sorted_inventory="$(inventory_summary)"
  local inventory_count=0
  [[ -n "$sorted_inventory" ]] && inventory_count="$(printf '%s\n' "$sorted_inventory" | wc -l | tr -d '[:space:]')"
  local current=0
  while IFS='|' read -r entry_path source action hash; do
    [[ -n "$entry_path" ]] || continue
    current=$((current + 1))
    local comma=","
    [[ "$current" -eq "$inventory_count" ]] && comma=""
    local hash_json="null"
    [[ -n "$hash" ]] && hash_json="\"$(json_escape "$hash")\""
    printf '    {"path":"%s","source":"%s","action":"%s","installedSha256":%s}%s\n' \
      "$(json_escape "$entry_path")" \
      "$(json_escape "$source")" \
      "$(json_escape "$action")" \
      "$hash_json" \
      "$comma"
  done <<< "$sorted_inventory"
  cat <<EOF
  ],
  "installedAt": "$(json_escape "$installed_at")",
  "updatedAt": "$(json_escape "$updated_at")",
  "onboarding": {
    "status": "$(json_escape "$onboarding_status")",
    "lastAuditAt": $last_audit_json
  }
}
EOF
}

target=""
packs_csv=""
dry_run=0
packs_option_seen=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -ge 2 ]] || { echo "--target 需要目录参数" >&2; exit 2; }
      target="$2"
      shift 2
      ;;
    --packs)
      [[ $# -ge 2 ]] || { echo "--packs 需要逗号分隔的流程包列表" >&2; exit 2; }
      packs_option_seen=1
      if [[ -n "$packs_csv" ]]; then
        packs_csv="$packs_csv,$2"
      else
        packs_csv="$2"
      fi
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "未知参数：$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$packs_option_seen" -eq 1 ]] && [[ -z "$(printf '%s' "$packs_csv" | tr -d '[:space:],')" ]]; then
  echo "--packs 需要至少一个流程包名称" >&2
  exit 2
fi

[[ -n "$target" ]] || { echo "必须提供 --target" >&2; usage >&2; exit 2; }
[[ -d "$target" ]] || { echo "目标目录不存在：$target" >&2; exit 1; }

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
target_root="$(CDPATH= cd -- "$target" && pwd)"
case "$target_root" in
  "$source_root"|"$source_root"/*)
    echo "目标目录不能是 dev-workflow 发布仓库或其子目录。" >&2
    exit 1
    ;;
esac

manifest_path="$target_root/.dev-workflow/manifest.json"
[[ -f "$manifest_path" ]] || { echo "缺少 dev-workflow manifest：$manifest_path" >&2; exit 1; }
grep -Eq '"managedBy"[[:space:]]*:[[:space:]]*"dev-workflow"' "$manifest_path" || {
  echo "manifest 不是由 dev-workflow 管理：$manifest_path" >&2
  exit 1
}
schema_version="$(json_number_field schemaVersion "$manifest_path")"
case "$schema_version" in
  1|2) ;;
  *) echo "不支持的 dev-workflow manifest schema：${schema_version:-missing}" >&2; exit 1 ;;
esac

manifest_version="$(json_string_field workflowVersion "$manifest_path")"
installed_at="$(json_string_field installedAt "$manifest_path")"
onboarding_status="$(json_string_field status "$manifest_path")"
last_audit_at="$(json_string_field lastAuditAt "$manifest_path")"
case "$onboarding_status" in
  pending|ready|blocked) ;;
  *) echo "manifest onboarding.status 无效：${onboarding_status:-missing}" >&2; exit 1 ;;
esac
distribution_version="$(tr -d '[:space:]' < "$source_root/VERSION")"
if [[ "$schema_version" == "2" && "$distribution_version" != "$manifest_version" ]]; then
  echo "卸载需要 dev-workflow $manifest_version，但当前分发版本是 $distribution_version。" >&2
  exit 1
fi

installed_packs=()
pack_output="$(read_manifest_packs "$manifest_path")" || {
  echo "manifest installedPacks 格式无效：$manifest_path" >&2
  exit 1
}
while IFS= read -r pack; do
  [[ -n "$pack" ]] && installed_packs+=("$(printf '%s' "$pack" | tr '[:upper:]' '[:lower:]')")
done <<< "$pack_output"

requested_packs=()
if [[ "$packs_option_seen" -eq 1 ]]; then
  IFS=',' read -r -a raw_packs <<< "$packs_csv"
  for pack in "${raw_packs[@]+"${raw_packs[@]}"}"; do
    pack="$(printf '%s' "$pack" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    [[ -n "$pack" ]] || continue
    contains_item "$pack" "${installed_packs[@]+"${installed_packs[@]}"}" || {
      echo "流程包未安装：$pack。已安装：${installed_packs[*]-none}" >&2
      exit 2
    }
    contains_item "$pack" "${requested_packs[@]+"${requested_packs[@]}"}" || requested_packs+=("$pack")
  done
fi
full_uninstall=0
[[ "$packs_option_seen" -eq 0 ]] && full_uninstall=1

file_paths=()
file_sources=()
file_actions=()
file_hashes=()
if [[ "$schema_version" == "2" ]]; then
  manifest_file_output="$(read_manifest_files "$manifest_path")" || {
    echo "manifest files 格式无效：$manifest_path" >&2
    exit 1
  }
  while IFS='|' read -r entry_path source action hash; do
    [[ -n "$entry_path" ]] || continue
    if inventory_index "$entry_path" >/dev/null; then
      echo "manifest files 包含重复路径：$entry_path" >&2
      exit 1
    fi
    if [[ "$source" != "core" ]] && ! contains_item "$source" "${installed_packs[@]+"${installed_packs[@]}"}"; then
      echo "manifest 将 $entry_path 归属于未安装流程包：$source" >&2
      exit 1
    fi
    owner_root="$source_root/core"
    [[ "$source" == "core" ]] || owner_root="$source_root/packs/$source"
    if [[ ! -f "$owner_root/$entry_path" ]]; then
      echo "manifest 文件 $entry_path 不属于流程源 $source" >&2
      exit 1
    fi
    if [[ "$action" == "created" ]]; then
      source_hash="$(sha256_file "$owner_root/$entry_path")"
      if [[ "$hash" != "$source_hash" ]]; then
        echo "manifest created 文件哈希与流程源不一致：$entry_path" >&2
        exit 1
      fi
    fi
    set_inventory "$entry_path" "$source" "$action" "$hash"
  done <<< "$manifest_file_output"
else
  overlay_names=("core")
  overlay_roots=("$source_root/core")
  for pack in "${installed_packs[@]+"${installed_packs[@]}"}"; do
    [[ -d "$source_root/packs/$pack" ]] || { echo "旧 manifest 引用了不存在的流程包：$pack" >&2; exit 1; }
    overlay_names+=("$pack")
    overlay_roots+=("$source_root/packs/$pack")
  done
  for index in "${!overlay_roots[@]}"; do
    overlay_name="${overlay_names[$index]}"
    overlay_root="${overlay_roots[$index]}"
    [[ -d "$overlay_root" ]] || { echo "流程 overlay 不存在：$overlay_root" >&2; exit 1; }
    while IFS= read -r source_path; do
      relative_path="${source_path#"$overlay_root"/}"
      if inventory_index "$relative_path" >/dev/null; then
        echo "流程 overlay 路径冲突：$relative_path" >&2
        exit 1
      fi
      action="legacy"
      [[ "$relative_path" == "AGENTS.md" ]] && action="managed-block"
      set_inventory "$relative_path" "$overlay_name" "$action" ""
    done < <(find "$overlay_root" -type f | LC_ALL=C sort)
  done
fi

plan_kinds=()
plan_paths=()
plan_reasons=()
core_start='<!-- AI-WORKFLOW:CORE:START -->'
core_end='<!-- AI-WORKFLOW:CORE:END -->'

for index in "${!file_paths[@]}"; do
  entry_path="${file_paths[$index]}"
  source="${file_sources[$index]}"
  action="${file_actions[$index]}"
  hash="${file_hashes[$index]}"
  if [[ "$full_uninstall" -eq 0 ]] && ! contains_item "$source" "${requested_packs[@]+"${requested_packs[@]}"}"; then
    continue
  fi
  target_path="$target_root/$entry_path"
  case "$target_path" in
    "$target_root"/*) ;;
    *) echo "manifest 路径越出目标目录：$entry_path" >&2; exit 1 ;;
  esac
  if [[ ! -f "$target_path" ]]; then
    plan_kinds+=("missing")
    plan_paths+=("$entry_path")
    plan_reasons+=("already missing")
    continue
  fi
  current_hash="$(sha256_file "$target_path")"
  owner_root="$source_root/core"
  [[ "$source" == "core" ]] || owner_root="$source_root/packs/$source"
  source_hash="$(sha256_file "$owner_root/$entry_path")"
  if [[ "$entry_path" == "AGENTS.md" ]]; then
    start_count="$(grep -cF "$core_start" "$target_path" || true)"
    end_count="$(grep -cF "$core_end" "$target_path" || true)"
    if [[ "$start_count" -ne "$end_count" || "$start_count" -gt 1 ]]; then
      echo "AGENTS.md 包含不完整或重复的 AI-WORKFLOW 核心标记；卸载未执行。" >&2
      exit 1
    fi
    if [[ "$action" == "created" && "$current_hash" == "$hash" && "$hash" == "$source_hash" ]]; then
      kind="delete"
      reason="unchanged managed file"
    elif [[ "$start_count" -eq 1 ]]; then
      start_line="$(grep -nF "$core_start" "$target_path" | head -n 1 | cut -d: -f1)"
      end_line="$(grep -nF "$core_end" "$target_path" | head -n 1 | cut -d: -f1)"
      [[ "$start_line" -lt "$end_line" ]] || { echo "AGENTS.md 核心标记顺序无效；卸载未执行。" >&2; exit 1; }
      kind="remove-block"
      reason="remove managed core block"
    else
      kind="keep"
      reason="managed core block is already absent"
    fi
  elif [[ "$action" == "created" && "$current_hash" == "$hash" && "$hash" == "$source_hash" ]]; then
    kind="delete"
    reason="unchanged managed file"
  elif [[ "$action" == "created" ]]; then
    kind="keep"
    reason="file was modified after installation"
  else
    kind="keep"
    reason="ownership is $action"
  fi
  plan_kinds+=("$kind")
  plan_paths+=("$entry_path")
  plan_reasons+=("$reason")
done

if [[ "$dry_run" -eq 1 ]]; then
  echo "dev-workflow 卸载 dry-run（未写入文件）"
else
  echo "dev-workflow 卸载"
fi
echo "target: $target_root"
if [[ "$full_uninstall" -eq 1 ]]; then
  echo "scope: Core 和全部已安装流程包"
else
  echo "scope: ${requested_packs[*]}"
fi
for index in "${!plan_kinds[@]}"; do
  case "${plan_kinds[$index]}" in
    delete) echo "[delete] ${plan_paths[$index]}" ;;
    remove-block) echo "[edit] AGENTS.md（移除 AI-WORKFLOW 受管核心区块）" ;;
    missing) echo "[skip] ${plan_paths[$index]}（已不存在）" ;;
    keep) echo "[keep] ${plan_paths[$index]}（${plan_reasons[$index]}）" ;;
  esac
done

if [[ "$dry_run" -eq 1 ]]; then
  if [[ "$full_uninstall" -eq 1 ]]; then
    echo "[delete] .dev-workflow/manifest.json"
  else
    echo "[update] .dev-workflow/manifest.json"
  fi
  exit 0
fi

removed_paths=()
for index in "${!plan_kinds[@]}"; do
  kind="${plan_kinds[$index]}"
  entry_path="${plan_paths[$index]}"
  target_path="$target_root/$entry_path"
  if [[ "$kind" == "delete" ]]; then
    rm -f -- "$target_path"
    removed_paths+=("$target_path")
  elif [[ "$kind" == "remove-block" ]]; then
    temp_path="$(mktemp "${target_path}.dev-workflow.XXXXXX")"
    if ! awk -v start="$core_start" -v end="$core_end" '
      index($0, start) { skipping=1; next }
      index($0, end) { skipping=0; next }
      !skipping { print }
    ' "$target_path" > "$temp_path"; then
      rm -f -- "$temp_path"
      exit 1
    fi
    mv -- "$temp_path" "$target_path"
  fi
done

if [[ "$full_uninstall" -eq 1 ]]; then
  rm -f -- "$manifest_path"
  rmdir -- "$target_root/.dev-workflow" 2>/dev/null || true
else
  remaining_packs=()
  for pack in "${installed_packs[@]+"${installed_packs[@]}"}"; do
    contains_item "$pack" "${requested_packs[@]+"${requested_packs[@]}"}" || remaining_packs+=("$pack")
  done
  installed_packs=("${remaining_packs[@]+"${remaining_packs[@]}"}")

  remaining_paths=()
  remaining_sources=()
  remaining_actions=()
  remaining_hashes=()
  for index in "${!file_paths[@]}"; do
    source="${file_sources[$index]}"
    if contains_item "$source" "${requested_packs[@]+"${requested_packs[@]}"}"; then
      continue
    fi
    remaining_paths+=("${file_paths[$index]}")
    remaining_sources+=("$source")
    remaining_actions+=("${file_actions[$index]}")
    remaining_hashes+=("${file_hashes[$index]}")
  done
  file_paths=("${remaining_paths[@]+"${remaining_paths[@]}"}")
  file_sources=("${remaining_sources[@]+"${remaining_sources[@]}"}")
  file_actions=("${remaining_actions[@]+"${remaining_actions[@]}"}")
  file_hashes=("${remaining_hashes[@]+"${remaining_hashes[@]}"}")

  manifest_tmp="$(mktemp "$manifest_path.XXXXXX")"
  now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  if ! build_manifest "$manifest_version" "$installed_at" "$now" "$onboarding_status" "$last_audit_at" > "$manifest_tmp"; then
    rm -f -- "$manifest_tmp"
    exit 1
  fi
  mv -- "$manifest_tmp" "$manifest_path"
fi

for removed_path in "${removed_paths[@]+"${removed_paths[@]}"}"; do
  parent="$(dirname -- "$removed_path")"
  while [[ "$parent" == "$target_root"/* && "$parent" != "$target_root" ]]; do
    rmdir -- "$parent" 2>/dev/null || break
    parent="$(dirname -- "$parent")"
  done
done

echo "result: complete"
