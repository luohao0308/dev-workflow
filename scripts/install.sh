#!/usr/bin/env bash
set -euo pipefail

# Bash 3.2 treats an empty array expansion as unbound under `set -u`.
# The `${items[@]+"${items[@]}"}` form expands all items, or nothing when empty.

usage() {
  cat <<'EOF'
用法：
  bash scripts/install.sh --target /path/to/project [options]

选项：
  --packs architecture,design,delivery  安装指定流程包（至少一个名称）
  --all-packs                           安装全部流程包
  --dry-run                             只显示动作，不写文件
  -h, --help                            显示帮助

说明：
  Core 始终安装。已存在的普通文件不会覆盖；已有 AGENTS.md 会保留原内容并追加核心区块。
EOF
}

read_workflow_version() {
  local version_file="$1"
  [[ -f "$version_file" ]] || { echo "VERSION 文件不存在：$version_file" >&2; exit 1; }
  local version
  version="$(tr -d '[:space:]' < "$version_file")"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
    echo "VERSION 格式无效：$version" >&2
    exit 1
  }
  printf '%s' "$version"
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

contains_item() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

directory_has_entries() {
  local path="$1"
  local entry
  for entry in "$path"/* "$path"/.[!.]* "$path"/..?*; do
    if [[ -e "$entry" || -L "$entry" ]]; then
      return 0
    fi
  done
  return 1
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
  if [[ -n "$residual" ]]; then
    return 1
  fi
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
  local index
  local packs_json=""
  for pack in "${installed_packs[@]+"${installed_packs[@]}"}"; do
    if [[ -n "$packs_json" ]]; then
      packs_json+=","
    fi
    packs_json+=$'\n    '"\"$pack\""
  done
  local last_audit_json="null"
  [[ -n "$last_audit_at" ]] && last_audit_json="\"$last_audit_at\""
  cat <<EOF
{
  "schemaVersion": 2,
  "managedBy": "dev-workflow",
  "workflowVersion": "$version",
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
  "installedAt": "$installed_at",
  "updatedAt": "$updated_at",
  "onboarding": {
    "status": "$onboarding_status",
    "lastAuditAt": $last_audit_json
  }
}
EOF
}

dry_run=0
all_packs=0
target=""
packs_csv=""
packs_option_seen=0
script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
core_root="$source_root/core"
packs_root="$source_root/packs"
workflow_version="$(read_workflow_version "$source_root/VERSION")"

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
    --all-packs)
      all_packs=1
      shift
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
[[ -d "$core_root" ]] || { echo "Core overlay 不存在：$core_root" >&2; exit 1; }
[[ -d "$packs_root" ]] || { echo "Packs 目录不存在：$packs_root" >&2; exit 1; }

target_root="$(CDPATH= cd -- "$target" && pwd)"
case "$target_root/" in
  "$source_root/"*)
    echo "目标目录不能是 dev-workflow 发布仓库或其子目录。" >&2
    exit 1
    ;;
esac

metadata_root="$target_root/.dev-workflow"
manifest_path="$metadata_root/manifest.json"
if [[ -e "$metadata_root" && ! -d "$metadata_root" ]]; then
  echo ".dev-workflow 元数据路径不是目录：$metadata_root" >&2
  exit 1
fi
if [[ -d "$metadata_root" && ! -f "$manifest_path" ]]; then
  if directory_has_entries "$metadata_root"; then
    echo ".dev-workflow 目录包含未受管理文件，但缺少 manifest：$metadata_root" >&2
    exit 1
  fi
fi

existing_manifest=0
existing_installed_at=""
existing_updated_at=""
existing_onboarding_status="pending"
existing_schema_version=""
existing_packs=()
file_paths=()
file_sources=()
file_actions=()
file_hashes=()
if [[ -f "$manifest_path" ]]; then
  grep -Eq '"managedBy"[[:space:]]*:[[:space:]]*"dev-workflow"' "$manifest_path" || {
    echo "manifest 已存在但不是由 dev-workflow 管理：$manifest_path" >&2
    exit 1
  }
  existing_schema_version="$(json_number_field schemaVersion "$manifest_path")"
  case "$existing_schema_version" in
    1|2) ;;
    *)
    echo "不支持的 dev-workflow manifest schema：$manifest_path" >&2
    exit 1
      ;;
  esac
  existing_manifest=1
  existing_installed_at="$(json_string_field installedAt "$manifest_path")"
  existing_updated_at="$(json_string_field updatedAt "$manifest_path")"
  existing_onboarding_status="$(json_string_field status "$manifest_path")"
  case "$existing_onboarding_status" in
    pending|ready|blocked) ;;
    *)
      echo "manifest onboarding.status 无效：${existing_onboarding_status:-missing}" >&2
      exit 1
      ;;
  esac
  if [[ "$existing_schema_version" == "2" ]]; then
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
      set_inventory "$entry_path" "$source" "$action" "$hash"
    done <<< "$manifest_file_output"
  fi
fi

available_packs=()
for pack_dir in "$packs_root"/*; do
  [[ -d "$pack_dir" ]] && available_packs+=("$(basename -- "$pack_dir")")
done

if [[ "$existing_manifest" -eq 1 ]]; then
  manifest_pack_output="$(read_manifest_packs "$manifest_path")" || {
    echo "manifest installedPacks 格式无效：$manifest_path" >&2
    exit 1
  }
  while IFS= read -r pack; do
    [[ -n "$pack" ]] || continue
    pack="$(printf '%s' "$pack" | tr '[:upper:]' '[:lower:]')"
    contains_item "$pack" "${available_packs[@]+"${available_packs[@]}"}" || {
      echo "manifest 引用了不存在的流程包：$pack" >&2
      exit 1
    }
    contains_item "$pack" "${existing_packs[@]+"${existing_packs[@]}"}" || existing_packs+=("$pack")
  done <<< "$manifest_pack_output"
fi

for index in "${!file_paths[@]}"; do
  source="${file_sources[$index]}"
  if [[ "$source" != "core" ]] && ! contains_item "$source" "${existing_packs[@]+"${existing_packs[@]}"}"; then
    echo "manifest 将 ${file_paths[$index]} 归属于未安装流程包：$source" >&2
    exit 1
  fi
  owner_root="$core_root"
  [[ "$source" == "core" ]] || owner_root="$packs_root/$source"
  if [[ ! -f "$owner_root/${file_paths[$index]}" ]]; then
    echo "manifest 文件 ${file_paths[$index]} 不属于流程源 $source" >&2
    exit 1
  fi
  if [[ "${file_actions[$index]}" == "created" ]]; then
    source_hash="$(sha256_file "$owner_root/${file_paths[$index]}")"
    if [[ "${file_hashes[$index]}" != "$source_hash" ]]; then
      if [[ "$existing_schema_version" == "2" && "$(json_string_field workflowVersion "$manifest_path")" == "$workflow_version" ]]; then
        echo "manifest created 文件哈希与流程源不一致：${file_paths[$index]}" >&2
        exit 1
      fi
      file_actions[$index]="legacy"
      file_hashes[$index]=""
    fi
  fi
done

selected_packs=()
if [[ "$all_packs" -eq 1 ]]; then
  selected_packs=("${available_packs[@]+"${available_packs[@]}"}")
elif [[ "$packs_option_seen" -eq 1 ]]; then
  IFS=',' read -r -a requested_packs <<< "$packs_csv"
  for pack in "${requested_packs[@]+"${requested_packs[@]}"}"; do
    pack="$(printf '%s' "$pack" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    [[ -n "$pack" ]] || continue
    if [[ "$pack" == "all" ]]; then
      selected_packs=("${available_packs[@]+"${available_packs[@]}"}")
      break
    fi
    contains_item "$pack" "${available_packs[@]+"${available_packs[@]}"}" || {
      echo "未知流程包：$pack。可用流程包：${available_packs[*]-none}" >&2
      exit 2
    }
    contains_item "$pack" "${selected_packs[@]+"${selected_packs[@]}"}" || selected_packs+=("$pack")
  done
fi

installed_packs=()
for pack in "${available_packs[@]+"${available_packs[@]}"}"; do
  if contains_item "$pack" "${existing_packs[@]+"${existing_packs[@]}"}" || contains_item "$pack" "${selected_packs[@]+"${selected_packs[@]}"}"; then
    installed_packs+=("$pack")
  fi
done

if [[ "$existing_schema_version" == "1" ]]; then
  for pack in "${existing_packs[@]+"${existing_packs[@]}"}"; do
    legacy_pack_root="$packs_root/$pack"
    while IFS= read -r source_path; do
      relative_path="${source_path#"$legacy_pack_root"/}"
      if inventory_index "$relative_path" >/dev/null; then
        echo "旧版流程包文件归属冲突：$relative_path" >&2
        exit 1
      fi
      set_inventory "$relative_path" "$pack" "legacy" ""
    done < <(find "$legacy_pack_root" -type f | LC_ALL=C sort)
  done
fi

now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
installed_at="$existing_installed_at"
[[ -n "$installed_at" ]] || installed_at="$now"
old_version=""
if [[ "$existing_manifest" -eq 1 ]]; then
  old_version="$(json_string_field workflowVersion "$manifest_path")"
fi
old_pack_summary="${existing_packs[*]-}"
new_pack_summary="${installed_packs[*]-}"
old_inventory_summary="$(inventory_summary)"
manifest_action="[create] .dev-workflow/manifest.json"
[[ "$existing_manifest" -eq 1 ]] && manifest_action="[update] .dev-workflow/manifest.json"

core_block="$(awk '
  /<!-- AI-WORKFLOW:CORE:START -->/ { capture=1 }
  capture { print }
  /<!-- AI-WORKFLOW:CORE:END -->/ { capture=0 }
' "$core_root/AGENTS.md")"
[[ -n "$core_block" ]] || { echo "模板缺少 AI-WORKFLOW 核心标记" >&2; exit 1; }

overlay_names=("core")
overlay_roots=("$core_root")
for pack in "${selected_packs[@]+"${selected_packs[@]}"}"; do
  overlay_names+=("$pack")
  overlay_roots+=("$packs_root/$pack")
done

actions=()
seen_paths=()

for index in "${!overlay_roots[@]}"; do
  overlay_name="${overlay_names[$index]}"
  overlay_root="${overlay_roots[$index]}"

  while IFS= read -r source_path; do
    [[ -n "$source_path" ]] || continue
    relative_path="${source_path#"$overlay_root"/}"

    if contains_item "$relative_path" "${seen_paths[@]+"${seen_paths[@]}"}"; then
      echo "Overlay 路径冲突：$relative_path" >&2
      exit 1
    fi
    seen_paths+=("$relative_path")

    existing_index=""
    if existing_index="$(inventory_index "$relative_path")"; then
      if [[ "${file_sources[$existing_index]}" != "$overlay_name" ]]; then
        echo "manifest 文件归属冲突：$relative_path（${file_sources[$existing_index]} / $overlay_name）" >&2
        exit 1
      fi
    fi

    target_path="$target_root/$relative_path"
    if [[ -e "$target_path" && ! -f "$target_path" ]]; then
      echo "目标路径存在但不是文件：$target_path" >&2
      exit 1
    fi

    if [[ "$relative_path" == "AGENTS.md" && -f "$target_path" ]]; then
      start_count="$(grep -c '<!-- AI-WORKFLOW:CORE:START -->' "$target_path" || true)"
      end_count="$(grep -c '<!-- AI-WORKFLOW:CORE:END -->' "$target_path" || true)"
      if [[ "$start_count" -eq 1 && "$end_count" -eq 1 ]]; then
        start_line="$(grep -n '<!-- AI-WORKFLOW:CORE:START -->' "$target_path" | head -n 1 | cut -d: -f1)"
        end_line="$(grep -n '<!-- AI-WORKFLOW:CORE:END -->' "$target_path" | head -n 1 | cut -d: -f1)"
        if [[ "$start_line" -ge "$end_line" ]]; then
          echo "现有 AGENTS.md 的 AI-WORKFLOW 核心标记顺序无效：$target_path" >&2
          exit 1
        fi
        actions+=("[skip] $relative_path（已存在受管控核心区块）")
        if [[ -z "$existing_index" ]]; then
          set_inventory "$relative_path" "$overlay_name" "managed-block" ""
        fi
      elif [[ "$start_count" -gt 0 || "$end_count" -gt 0 ]]; then
        echo "现有 AGENTS.md 包含不完整或重复的 AI-WORKFLOW 核心标记：$target_path" >&2
        exit 1
      elif [[ "$dry_run" -eq 1 ]]; then
        actions+=("[append] $relative_path（保留现有内容，追加通用核心区块）")
        set_inventory "$relative_path" "$overlay_name" "appended" ""
      else
        temp_path="$(mktemp "${target_path}.dev-workflow.XXXXXX")"
        if ! {
          cat "$target_path"
          printf '\n\n%s\n' "$core_block"
        } > "$temp_path"; then
          rm -f -- "$temp_path"
          exit 1
        fi
        mv "$temp_path" "$target_path"
        actions+=("[append] $relative_path（保留现有内容，追加通用核心区块）")
        set_inventory "$relative_path" "$overlay_name" "appended" ""
      fi
      continue
    fi

    if [[ -f "$target_path" ]]; then
      actions+=("[skip] $relative_path（目标项目已有文件，不覆盖）")
      if [[ -z "$existing_index" ]]; then
        ownership_action="preserved"
        [[ "$existing_schema_version" == "1" ]] && ownership_action="legacy"
        set_inventory "$relative_path" "$overlay_name" "$ownership_action" ""
      fi
      continue
    fi

    if [[ "$dry_run" -eq 1 ]]; then
      actions+=("[create] $relative_path [$overlay_name]")
      set_inventory "$relative_path" "$overlay_name" "created" "$(sha256_file "$source_path")"
      continue
    fi

    mkdir -p "$(dirname -- "$target_path")"
    cp "$source_path" "$target_path"
    actions+=("[create] $relative_path [$overlay_name]")
    set_inventory "$relative_path" "$overlay_name" "created" "$(sha256_file "$target_path")"
  done < <(find "$overlay_root" -type f | LC_ALL=C sort)
done

new_inventory_summary="$(inventory_summary)"
manifest_changed=0
if [[
  "$existing_manifest" -eq 0 ||
  "$existing_schema_version" != "2" ||
  "$old_version" != "$workflow_version" ||
  "$old_pack_summary" != "$new_pack_summary" ||
  "$old_inventory_summary" != "$new_inventory_summary"
]]; then
  manifest_changed=1
fi
updated_at="$existing_updated_at"
if [[ "$manifest_changed" -eq 1 || -z "$updated_at" ]]; then
  updated_at="$now"
fi

if [[ "$manifest_changed" -eq 1 ]]; then
  if [[ "$dry_run" -eq 1 ]]; then
    actions+=("$manifest_action（dry-run；version $workflow_version）")
  else
    mkdir -p "$metadata_root"
    manifest_tmp="$(mktemp "$manifest_path.XXXXXX")"
    last_audit_at=""
    if [[ "$existing_manifest" -eq 1 ]]; then
      last_audit_at="$(json_string_field lastAuditAt "$manifest_path")"
    fi
    if ! build_manifest "$workflow_version" "$installed_at" "$updated_at" "$existing_onboarding_status" "$last_audit_at" > "$manifest_tmp"; then
      rm -f -- "$manifest_tmp"
      exit 1
    fi
    mv -- "$manifest_tmp" "$manifest_path"
    actions+=("$manifest_action（version $workflow_version）")
  fi
else
  actions+=("[skip] .dev-workflow/manifest.json（已是当前版本）")
fi

if [[ "${#selected_packs[@]}" -eq 0 ]]; then
  pack_summary="none"
else
  pack_summary="${selected_packs[*]}"
fi

if [[ "$dry_run" -eq 1 ]]; then
  echo "dev-workflow dry-run（未写入文件；packs: $pack_summary）"
else
  echo "dev-workflow 安装完成（packs: $pack_summary）"
fi
printf '%s\n' "${actions[@]+"${actions[@]}"}"
