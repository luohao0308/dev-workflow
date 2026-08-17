#!/usr/bin/env bash
set -uo pipefail

# Bash 3.2 treats an empty array expansion as unbound under `set -u`.
# The `${items[@]+"${items[@]}"}` form expands all items, or nothing when empty.

usage() {
  cat <<'EOF'
用法：
  bash scripts/audit.sh --target /path/to/project [--strict]

选项：
  --strict     将占位内容、版本落后等告警视为失败
  -h, --help   显示帮助

退出码：
  0  接入状态为 ready，且未发现阻断问题
  1  安装结构或 manifest 无效；strict 模式下也用于告警
  2  接入状态仍为 pending 或 blocked
EOF
}

add_error() {
  errors+=("$1")
}

add_warning() {
  warnings+=("$1")
}

feature_catalog_issue() {
  local message="$1"
  if [[ "$manifest_status" == "ready" && "$adoption_status" == "ready" ]]; then
    add_error "$message"
  else
    add_warning "$message"
  fi
}

check_feature_catalog_pack() {
  contains_item "feature-catalog" "${installed_packs[@]+"${installed_packs[@]}"}" || return 0

  local tool="$target_root/scripts/feature_catalog.py"
  local catalog="$target_root/docs/development/ai/feature-catalog.json"
  local matrix="$target_root/docs/FEATURE-MATRIX.md"
  local interpreter=""
  if command -v python3 >/dev/null 2>&1; then
    interpreter="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then
    interpreter="$(command -v python)"
  fi

  if [[ ! -f "$catalog" ]]; then
    feature_catalog_issue "feature-catalog active catalog is missing; run python3 scripts/feature_catalog.py --init."
    return 0
  fi
  if [[ ! -f "$matrix" ]]; then
    feature_catalog_issue "feature-catalog generated matrix is missing; run python3 scripts/feature_catalog.py --generate."
    return 0
  fi
  if [[ -z "$interpreter" ]]; then
    feature_catalog_issue "feature-catalog requires Python 3 for validation and drift checks."
    return 0
  fi
  if [[ ! -f "$tool" ]] || ! "$interpreter" "$tool" --check >/dev/null 2>&1; then
    feature_catalog_issue "feature-catalog validation or generated-matrix drift check failed."
  fi
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
  return 1
}

inventory_source_for() {
  local needle="$1"
  local index
  for index in "${!inventory_paths[@]}"; do
    if [[ "${inventory_paths[$index]}" == "$needle" ]]; then
      printf '%s' "${inventory_sources[$index]}"
      return 0
    fi
  done
  return 1
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

validate_json_when_available() {
  local path="$1"
  if command -v jq >/dev/null 2>&1; then
    jq empty "$path" >/dev/null 2>&1
    return $?
  fi
  if command -v python >/dev/null 2>&1 && python -c 'import json' >/dev/null 2>&1; then
    python -c 'import json, sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$path" >/dev/null 2>&1
    return $?
  fi
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import json' >/dev/null 2>&1; then
    python3 -c 'import json, sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$path" >/dev/null 2>&1
    return $?
  fi
  if command -v node >/dev/null 2>&1; then
    node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$path" >/dev/null 2>&1
    return $?
  fi
  return 2
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

target=""
strict=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      if [[ $# -lt 2 ]]; then
        echo "--target 需要目录参数" >&2
        exit 2
      fi
      target="$2"
      shift 2
      ;;
    --strict)
      strict=1
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

if [[ -z "$target" ]]; then
  echo "必须提供 --target" >&2
  usage >&2
  exit 2
fi
if [[ ! -d "$target" ]]; then
  echo "目标目录不存在：$target" >&2
  exit 1
fi

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
target_root="$(CDPATH= cd -- "$target" && pwd)"

case "$target_root" in
  "$source_root"|"$source_root"/*)
    echo "目标目录不能是 dev-workflow 发布仓库或其子目录。" >&2
    exit 1
    ;;
esac

errors=()
warnings=()
core_files=(
  "AGENTS.md"
  "docs/README.md"
  "docs/TASKS.md"
  "docs/WORKING-CONTEXT.md"
  "docs/WORKFLOW-ADOPTION.md"
  "docs/PROJECT-SUMMARY.md"
  "docs/project-memory/README.md"
)

core_source_path="$source_root/core/AGENTS.md"
if [[ ! -f "$core_source_path" ]] || ! grep -Fq '## 大型计划拆分与确认门' "$core_source_path" || ! grep -Fq 'awaiting_user_confirmation' "$core_source_path"; then
  add_error "分发 Core 缺少大型计划拆分确认门契约。"
fi
delivery_readme_source="$source_root/packs/delivery/docs/plans/README.md"
delivery_template_source="$source_root/packs/delivery/docs/plans/TEMPLATE.md"
if [[ ! -f "$delivery_readme_source" ]] || ! grep -Fq '大型计划确认门' "$delivery_readme_source"; then
  add_error "分发 delivery 计划导航缺少大型计划确认门契约。"
fi
if [[ ! -f "$delivery_template_source" ]] || ! grep -Fq 'awaiting_user_confirmation' "$delivery_template_source" || ! grep -Fq '## 7. 偏移控制' "$delivery_template_source"; then
  add_error "分发 delivery 计划模板缺少确认状态或偏移控制契约。"
fi

for relative_path in "${core_files[@]+"${core_files[@]}"}"; do
  if [[ ! -f "$target_root/$relative_path" ]]; then
    add_error "缺少 Core 文件：$relative_path"
  fi
done

agents_path="$target_root/AGENTS.md"
if [[ -f "$agents_path" ]]; then
  start_count="$(grep -c '<!-- AI-WORKFLOW:CORE:START -->' "$agents_path" || true)"
  end_count="$(grep -c '<!-- AI-WORKFLOW:CORE:END -->' "$agents_path" || true)"
  start_line="$(grep -n '<!-- AI-WORKFLOW:CORE:START -->' "$agents_path" | head -n 1 | cut -d: -f1 || true)"
  end_line="$(grep -n '<!-- AI-WORKFLOW:CORE:END -->' "$agents_path" | head -n 1 | cut -d: -f1 || true)"
  if [[ "$start_count" -ne 1 || "$end_count" -ne 1 || "$start_line" -ge "$end_line" ]]; then
    add_error "AGENTS.md 必须包含且只包含一组完整的 AI-WORKFLOW 核心标记。"
  fi
fi

manifest_path="$target_root/.dev-workflow/manifest.json"
manifest_status="missing"
manifest_version=""
installed_packs=()
inventory_paths=()
inventory_sources=()
inventory_actions=()
inventory_hashes=()

if [[ ! -f "$manifest_path" ]]; then
  add_error "缺少 .dev-workflow/manifest.json；请重新运行安装器。"
else
  validate_json_when_available "$manifest_path"
  json_result=$?
  if [[ "$json_result" -eq 1 ]]; then
    add_error "manifest.json 不是可解析的 JSON。"
  fi

  managed_by="$(json_string_field managedBy "$manifest_path")"
  schema_version="$(json_number_field schemaVersion "$manifest_path")"
  manifest_version="$(json_string_field workflowVersion "$manifest_path")"
  manifest_status="$(json_string_field status "$manifest_path")"

  if [[ "$managed_by" != "dev-workflow" ]]; then
    add_error "manifest.json 不是由 dev-workflow 管理。"
  fi
  case "$schema_version" in
    1) add_warning "manifest.json 仍使用 schemaVersion 1；请用当前版本安装器升级，以获得安全卸载所需的文件归属信息。" ;;
    2) ;;
    *) add_error "manifest.json 使用了不支持的 schemaVersion。" ;;
  esac
  if [[ ! "$manifest_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
    add_error "manifest workflowVersion 无效：${manifest_version:-missing}"
  fi
  case "$manifest_status" in
    pending|ready|blocked) ;;
    *) add_error "manifest onboarding.status 无效：${manifest_status:-missing}" ;;
  esac
  last_audit_at="$(json_string_field lastAuditAt "$manifest_path")"
  if [[ "$manifest_status" == "ready" && -z "$last_audit_at" ]]; then
    add_warning "ready 接入状态尚未记录 onboarding.lastAuditAt。"
  fi

  if ! grep -Eq '"installedPacks"[[:space:]]*:' "$manifest_path"; then
    add_error "manifest.json 缺少 installedPacks。"
  else
    pack_output="$(read_manifest_packs "$manifest_path")"
    pack_result=$?
    if [[ "$pack_result" -ne 0 ]]; then
      add_error "manifest installedPacks 格式无效。"
    else
      while IFS= read -r pack; do
        [[ -n "$pack" ]] && installed_packs+=("$(printf '%s' "$pack" | tr '[:upper:]' '[:lower:]')")
      done <<< "$pack_output"
    fi
  fi

  if [[ "$schema_version" == "2" ]]; then
    manifest_file_output="$(read_manifest_files "$manifest_path")"
    file_result=$?
    if [[ "$file_result" -ne 0 ]]; then
      add_error "manifest files 格式无效。"
    else
      while IFS='|' read -r entry_path source action hash; do
        [[ -n "$entry_path" ]] || continue
        if contains_item "$entry_path" "${inventory_paths[@]+"${inventory_paths[@]}"}"; then
          add_error "manifest files 包含重复路径：$entry_path"
        else
          inventory_paths+=("$entry_path")
          inventory_sources+=("$source")
          inventory_actions+=("$action")
          inventory_hashes+=("$hash")
          if [[ "$source" != "core" ]] && ! contains_item "$source" "${installed_packs[@]+"${installed_packs[@]}"}"; then
            add_error "manifest 文件 $entry_path 归属于未安装流程包：$source"
          else
            owner_root="$source_root/core"
            [[ "$source" == "core" ]] || owner_root="$source_root/packs/$source"
            if [[ ! -f "$owner_root/$entry_path" ]]; then
              add_error "manifest 文件 $entry_path 不属于流程源 $source"
            fi
          fi
        fi
      done <<< "$manifest_file_output"
    fi
  fi

  source_version_path="$source_root/VERSION"
  if [[ ! -f "$source_version_path" ]]; then
    add_error "分发仓库缺少 VERSION 文件。"
  else
    source_version="$(tr -d '[:space:]' < "$source_version_path")"
    if [[ ! "$source_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
      add_error "分发仓库 VERSION 格式无效：${source_version:-missing}"
    elif [[ -n "$manifest_version" && "$manifest_version" != "$source_version" ]]; then
      add_warning "manifest 版本 $manifest_version 不是当前分发版本 $source_version；可先执行安装器 dry-run 查看升级差异。"
    fi
  fi

  if [[ "$schema_version" == "2" && -n "${source_version:-}" && "$manifest_version" == "${source_version:-}" ]]; then
    for index in "${!inventory_paths[@]}"; do
      [[ "${inventory_actions[$index]}" == "created" ]] || continue
      owner_root="$source_root/core"
      [[ "${inventory_sources[$index]}" == "core" ]] || owner_root="$source_root/packs/${inventory_sources[$index]}"
      if [[ -f "$owner_root/${inventory_paths[$index]}" ]]; then
        source_hash="$(sha256_file "$owner_root/${inventory_paths[$index]}")" || {
          add_error "缺少 SHA-256 工具，无法验证 created 文件归属。"
          break
        }
        if [[ "${inventory_hashes[$index]}" != "$source_hash" ]]; then
          add_error "manifest created 文件哈希与流程源不一致：${inventory_paths[$index]}"
        fi
      fi
    done
  fi

  seen_packs=()
  for pack in "${installed_packs[@]+"${installed_packs[@]}"}"; do
    duplicate=0
    for seen_pack in "${seen_packs[@]+"${seen_packs[@]}"}"; do
      if [[ "$seen_pack" == "$pack" ]]; then
        duplicate=1
        break
      fi
    done
    if [[ "$duplicate" -eq 1 ]]; then
      add_error "manifest installedPacks 包含重复项：$pack"
      continue
    fi
    seen_packs+=("$pack")

    pack_root="$source_root/packs/$pack"
    if [[ ! -d "$pack_root" ]]; then
      add_error "manifest 引用了不存在的流程包：$pack"
      continue
    fi
    while IFS= read -r source_file; do
      [[ -n "$source_file" ]] || continue
      relative_path="${source_file#"$pack_root"/}"
      if [[ ! -f "$target_root/$relative_path" ]]; then
        add_error "流程包 $pack 缺少文件：$relative_path"
      fi
      if [[ "$schema_version" == "2" ]] && ! contains_item "$relative_path" "${inventory_paths[@]+"${inventory_paths[@]}"}"; then
        add_error "manifest 文件归属清单缺少流程包文件：$relative_path"
      elif [[ "$schema_version" == "2" ]]; then
        inventory_source="$(inventory_source_for "$relative_path")"
        if [[ "$inventory_source" != "$pack" ]]; then
          add_error "manifest 将 $relative_path 归属于 $inventory_source，而不是 $pack"
        fi
      fi
    done < <(find "$pack_root" -type f | LC_ALL=C sort)
  done
  if [[ "$schema_version" == "2" ]]; then
    for relative_path in "${core_files[@]+"${core_files[@]}"}"; do
      if ! contains_item "$relative_path" "${inventory_paths[@]+"${inventory_paths[@]}"}"; then
        add_error "manifest 文件归属清单缺少 Core 文件：$relative_path"
      else
        inventory_source="$(inventory_source_for "$relative_path")"
        if [[ "$inventory_source" != "core" ]]; then
          add_error "manifest 将 Core 文件 $relative_path 归属于 $inventory_source"
        fi
      fi
    done
  fi
fi

adoption_path="$target_root/docs/WORKFLOW-ADOPTION.md"
adoption_status="missing"
if [[ -f "$adoption_path" ]]; then
  adoption_status="$(tr -d '\r' < "$adoption_path" | sed -n -E 's/^status:[[:space:]]*(pending|ready|blocked)[[:space:]]*$/\1/p' | head -n 1)"
  if [[ -z "$adoption_status" ]]; then
    adoption_status="missing"
    add_error "WORKFLOW-ADOPTION.md 缺少有效的 status。"
  fi
  if [[ "$adoption_status" == "ready" ]] && grep -Eq '^- \[ \] ' "$adoption_path"; then
    add_warning "WORKFLOW-ADOPTION.md 已标记 ready，但仍有未勾选的接入项。"
  fi
else
  add_error "缺少 docs/WORKFLOW-ADOPTION.md。"
fi

if [[ "$manifest_status" != "missing" && "$adoption_status" != "missing" && "$manifest_status" != "$adoption_status" ]]; then
  add_error "manifest 与 WORKFLOW-ADOPTION 状态不一致：$manifest_status / $adoption_status"
fi

check_feature_catalog_pack

context_path="$target_root/docs/WORKING-CONTEXT.md"
if [[ -f "$context_path" ]]; then
  context_status="$(tr -d '\r' < "$context_path" | sed -n -E 's/^status:[[:space:]]*(active|inactive)[[:space:]]*$/\1/p' | head -n 1)"
  if [[ -z "$context_status" ]]; then
    add_error "WORKING-CONTEXT.md 缺少有效的 active/inactive 状态。"
  fi
fi

initialization_files=("docs/PROJECT-SUMMARY.md" "docs/WORKFLOW-ADOPTION.md")
for relative_path in "${initialization_files[@]+"${initialization_files[@]}"}"; do
  path="$target_root/$relative_path"
  if [[ -f "$path" ]] && grep -Eq 'YYYY-MM-DD|待初始化|<!--[[:space:]]*(填写|path|command|repo/path)' "$path"; then
    add_warning "仍包含接入占位内容：$relative_path"
  fi
done

echo "dev-workflow audit"
echo "target: $target_root"
if [[ -f "$manifest_path" ]]; then
  echo "workflowVersion: ${manifest_version:-unknown}"
  if [[ "${#installed_packs[@]}" -eq 0 ]]; then
    echo "installedPacks: none"
  else
    echo "installedPacks: ${installed_packs[*]}"
  fi
  echo "onboarding: $manifest_status"
fi
for message in "${errors[@]+"${errors[@]}"}"; do
  echo "[error] $message"
done
for message in "${warnings[@]+"${warnings[@]}"}"; do
  echo "[warn] $message"
done

if [[ "${#errors[@]}" -gt 0 ]]; then
  echo "result: invalid"
  exit 1
fi
if [[ "$manifest_status" == "pending" || "$adoption_status" == "pending" ]]; then
  echo "result: pending (完成首次项目画像后再依据项目事实修改代码)"
  exit 2
fi
if [[ "$manifest_status" == "blocked" || "$adoption_status" == "blocked" ]]; then
  echo "result: blocked (解决接入阻塞后重新审计)"
  exit 2
fi
if [[ "$strict" -eq 1 && "${#warnings[@]}" -gt 0 ]]; then
  echo "result: warning (strict 模式将告警视为失败)"
  exit 1
fi

echo "result: ready"
exit 0
