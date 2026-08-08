#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
用法：
  bash scripts/install.sh --target /path/to/project [options]

选项：
  --packs architecture,design,delivery  安装指定流程包
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

build_manifest() {
  local version="$1"
  local installed_at="$2"
  local updated_at="$3"
  local onboarding_status="$4"
  local last_audit_at="$5"
  shift 5
  local pack
  local packs_json=""
  for pack in "$@"; do
    if [[ -n "$packs_json" ]]; then
      packs_json+=","
    fi
    packs_json+=$'\n    '"\"$pack\""
  done
  local last_audit_json="null"
  [[ -n "$last_audit_at" ]] && last_audit_json="\"$last_audit_at\""
  cat <<EOF
{
  "schemaVersion": 1,
  "managedBy": "dev-workflow",
  "workflowVersion": "$version",
  "installedPacks": [$packs_json
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
existing_packs=()
if [[ -f "$manifest_path" ]]; then
  grep -Eq '"managedBy"[[:space:]]*:[[:space:]]*"dev-workflow"' "$manifest_path" || {
    echo "manifest 已存在但不是由 dev-workflow 管理：$manifest_path" >&2
    exit 1
  }
  grep -Eq '"schemaVersion"[[:space:]]*:[[:space:]]*1' "$manifest_path" || {
    echo "不支持的 dev-workflow manifest schema：$manifest_path" >&2
    exit 1
  }
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
    contains_item "$pack" "${available_packs[@]}" || {
      echo "manifest 引用了不存在的流程包：$pack" >&2
      exit 1
    }
    contains_item "$pack" "${existing_packs[@]}" || existing_packs+=("$pack")
  done <<< "$manifest_pack_output"
fi

selected_packs=()
if [[ "$all_packs" -eq 1 ]]; then
  selected_packs=("${available_packs[@]}")
elif [[ -n "$packs_csv" ]]; then
  IFS=',' read -r -a requested_packs <<< "$packs_csv"
  for pack in "${requested_packs[@]}"; do
    pack="$(printf '%s' "$pack" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    [[ -n "$pack" ]] || continue
    if [[ "$pack" == "all" ]]; then
      selected_packs=("${available_packs[@]}")
      break
    fi
    contains_item "$pack" "${available_packs[@]}" || {
      echo "未知流程包：$pack。可用流程包：${available_packs[*]}" >&2
      exit 2
    }
    contains_item "$pack" "${selected_packs[@]}" || selected_packs+=("$pack")
  done
fi

installed_packs=()
for pack in "${available_packs[@]}"; do
  if contains_item "$pack" "${existing_packs[@]}" || contains_item "$pack" "${selected_packs[@]}"; then
    installed_packs+=("$pack")
  fi
done

now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
installed_at="$existing_installed_at"
[[ -n "$installed_at" ]] || installed_at="$now"
old_version=""
if [[ "$existing_manifest" -eq 1 ]]; then
  old_version="$(json_string_field workflowVersion "$manifest_path")"
fi
old_pack_summary="${existing_packs[*]-}"
new_pack_summary="${installed_packs[*]-}"
manifest_changed=0
if [[ "$existing_manifest" -eq 0 || "$old_version" != "$workflow_version" || "$old_pack_summary" != "$new_pack_summary" ]]; then
  manifest_changed=1
fi
updated_at="$existing_updated_at"
if [[ "$manifest_changed" -eq 1 || -z "$updated_at" ]]; then
  updated_at="$now"
fi
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
for pack in "${selected_packs[@]}"; do
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

    if contains_item "$relative_path" "${seen_paths[@]}"; then
      echo "Overlay 路径冲突：$relative_path" >&2
      exit 1
    fi
    seen_paths+=("$relative_path")

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
      elif [[ "$start_count" -gt 0 || "$end_count" -gt 0 ]]; then
        echo "现有 AGENTS.md 包含不完整或重复的 AI-WORKFLOW 核心标记：$target_path" >&2
        exit 1
      elif [[ "$dry_run" -eq 1 ]]; then
        actions+=("[append] $relative_path（保留现有内容，追加通用核心区块）")
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
      fi
      continue
    fi

    if [[ -f "$target_path" ]]; then
      actions+=("[skip] $relative_path（目标项目已有文件，不覆盖）")
      continue
    fi

    if [[ "$dry_run" -eq 1 ]]; then
      actions+=("[create] $relative_path [$overlay_name]")
      continue
    fi

    mkdir -p "$(dirname -- "$target_path")"
    cp "$source_path" "$target_path"
    actions+=("[create] $relative_path [$overlay_name]")
  done < <(find "$overlay_root" -type f | LC_ALL=C sort)
done

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
    if ! build_manifest "$workflow_version" "$installed_at" "$updated_at" "$existing_onboarding_status" "$last_audit_at" "${installed_packs[@]}" > "$manifest_tmp"; then
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
printf '%s\n' "${actions[@]}"
