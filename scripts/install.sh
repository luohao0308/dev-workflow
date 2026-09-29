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
  --enable-capabilities api:rest-openapi,containers:compose  启用项目技术能力（升级默认保留）
  --disable-capabilities api:rest-openapi,containers:compose 禁用项目技术能力
  --push-mode manual|auto              push 审批模式（默认 manual）
  --push-actor user|ai                 push 执行角色（默认 user）
  --merge-mode manual|auto             merge 审批模式（默认 manual）
  --merge-actor user|ai                merge 执行角色（默认 user）
  --pull-request-mode manual|auto      pull request 审批模式（默认 manual）
  --pull-request-actor user|ai         pull request 执行角色（默认 user）
  --non-interactive                    不询问 Git 策略，使用参数、已有值或安全默认值
  --dry-run                             只显示动作，不写文件
  -h, --help                            显示帮助

说明：
  Core 始终安装。已存在的普通文件不会覆盖；已有 AGENTS.md 会保留原内容并追加核心区块。
  新安装会确认 push/pull request/merge 策略；非交互环境默认 manual + user。
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

json_boolean_field() {
  local field="$1"
  local path="$2"
  sed -n -E "s/.*\"$field\"[[:space:]]*:[[:space:]]*(true|false).*/\1/p" "$path" | head -n 1
}

git_policy_field() {
  local field="$1"
  local path="$2"
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json, sys
p=json.load(open(sys.argv[1], encoding="utf-8")).get("gitPolicy")
if not isinstance(p, dict) or sys.argv[2] not in p or isinstance(p[sys.argv[2]], (dict, list)) or p[sys.argv[2]] is None: raise SystemExit(1)
v=p[sys.argv[2]]
print(str(v).lower() if isinstance(v, bool) else v)' "$path" "$field"
    return $?
  fi
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg field "$field" '
      .gitPolicy as $p |
      if ($p | type) != "object" or ($p | has($field) | not) then error("missing gitPolicy field")
      elif ($p[$field] | type) == "boolean" then ($p[$field] | if . then "true" else "false" end)
      elif (($p[$field] | type) == "string" or ($p[$field] | type) == "number") then ($p[$field] | tostring)
      else error("invalid gitPolicy field") end
    ' "$path"
    return $?
  fi
  if command -v node >/dev/null 2>&1; then
    node -e 'const fs=require("fs"); const d=JSON.parse(fs.readFileSync(process.argv[1], "utf8")); const p=d.gitPolicy; const f=process.argv[2]; if (!p || typeof p !== "object" || !(f in p) || p[f] === null || typeof p[f] === "object") process.exit(1); process.stdout.write(String(p[f]));' "$path" "$field"
    return $?
  fi
  echo "读取 manifest gitPolicy 需要 python3、jq 或 node；未找到可用的结构化 JSON 解析器。" >&2
  return 2
}

git_policy_string_field() {
  git_policy_field "$1" "$2"
}

git_policy_boolean_field() {
  git_policy_field "$1" "$2"
}

git_exclude_begin='# BEGIN dev-workflow managed excludes'
git_exclude_end='# END dev-workflow managed excludes'

escape_git_exclude_path() {
  case "$1" in
    *$'\r'*|*$'\n'*) echo "Git exclude 路径不能包含换行符。" >&2; return 1 ;;
  esac
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/[][?*#! ]/\\&/g'
}

detect_git_exclude() {
  git_repo_root=""
  git_exclude_path=""
  git_target_prefix=""
  git_exclude_available=0
  git_repo_root="$(git -C "$target_root" rev-parse --show-toplevel 2>/dev/null || true)"
  [[ -n "$git_repo_root" ]] || return 0
  git_path="$(git -C "$target_root" rev-parse --git-path info/exclude 2>/dev/null || true)"
  [[ -n "$git_path" ]] || return 0
  case "$git_path" in
    /*) git_exclude_path="$git_path" ;;
    *) git_exclude_path="$(CDPATH= cd -- "$target_root/$(dirname -- "$git_path")" && pwd)/$(basename -- "$git_path")" ;;
  esac
  git_target_prefix="$(git -C "$target_root" rev-parse --show-prefix 2>/dev/null || true)"
  git_target_prefix="${git_target_prefix%/}"
  git_exclude_available=1
}

git_exclude_pattern_for() {
  local relative_path="$1"
  local escaped_relative_path
  local escaped_target_prefix
  escaped_relative_path="$(escape_git_exclude_path "$relative_path")"
  if [[ -n "$git_target_prefix" ]]; then
    escaped_target_prefix="$(escape_git_exclude_path "$git_target_prefix")"
    printf '/%s/%s' "$escaped_target_prefix" "$escaped_relative_path"
  else
    printf '/%s' "$escaped_relative_path"
  fi
}

validate_git_exclude_block_for_write() {
  local exclude_path="$1"
  local begin_count
  local end_count
  local begin_line
  local end_line
  [[ -f "$exclude_path" ]] || return 0
  begin_count="$(grep -cF "$git_exclude_begin" "$exclude_path" || true)"
  end_count="$(grep -cF "$git_exclude_end" "$exclude_path" || true)"
  if [[ "$begin_count" -gt 1 || "$end_count" -gt 1 || "$begin_count" -ne "$end_count" ]]; then
    echo "Git exclude 中的 dev-workflow managed block 不完整或重复：$exclude_path" >&2
    return 1
  fi
  if [[ "$begin_count" -eq 1 ]]; then
    begin_line="$(grep -nF "$git_exclude_begin" "$exclude_path" | cut -d: -f1)"
    end_line="$(grep -nF "$git_exclude_end" "$exclude_path" | cut -d: -f1)"
    if [[ "$begin_line" -ge "$end_line" ]]; then
      echo "Git exclude 中的 dev-workflow managed block 标记顺序无效：$exclude_path" >&2
      return 1
    fi
  fi
}

contains_git_exclude_pattern() {
  local needle="$1"
  local item
  for item in "${git_exclude_patterns[@]+"${git_exclude_patterns[@]}"}"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

build_git_exclude_patterns() {
  local relative_path
  local source
  local action
  local hash
  local pattern
  git_exclude_patterns=()
  pattern="$(git_exclude_pattern_for '.dev-workflow/')"
  git_exclude_patterns+=("$pattern")
  pattern="$(git_exclude_pattern_for 'docs/project-memory/')"
  git_exclude_patterns+=("$pattern")
  if contains_item "delivery" "${installed_packs[@]+"${installed_packs[@]}"}"; then
    pattern="$(git_exclude_pattern_for 'docs/working-context/')"
    git_exclude_patterns+=("$pattern")
    pattern="$(git_exclude_pattern_for 'docs/工作日志/')"
    git_exclude_patterns+=("$pattern")
  fi
  while IFS='|' read -r relative_path source action hash; do
    [[ -n "$relative_path" && "$action" == "created" ]] || continue
    case "$relative_path" in docs/operations/runbooks/*) continue ;; esac
    pattern="$(git_exclude_pattern_for "$relative_path")"
    contains_git_exclude_pattern "$pattern" || git_exclude_patterns+=("$pattern")
  done <<< "$(inventory_summary)"
}

write_git_exclude_block() {
  local exclude_path="$1"
  local temp_path
  mkdir -p "$(dirname -- "$exclude_path")"
  validate_git_exclude_block_for_write "$exclude_path" || return 1
  temp_path="$(mktemp "${exclude_path}.dev-workflow.XXXXXX")"
  if [[ -f "$exclude_path" ]]; then
    awk -v begin="$git_exclude_begin" -v end="$git_exclude_end" '
      $0 == begin { skipping=1; next }
      $0 == end { skipping=0; next }
      !skipping { print }
    ' "$exclude_path" > "$temp_path"
  fi
  if [[ "${#git_exclude_patterns[@]}" -gt 0 ]]; then
    if [[ -s "$temp_path" ]] && [[ -n "$(tail -n 1 "$temp_path")" ]]; then
      printf '\n' >> "$temp_path"
    fi
    printf '%s\n' "$git_exclude_begin" >> "$temp_path"
    printf '%s\n' "${git_exclude_patterns[@]}" >> "$temp_path"
    printf '%s\n' "$git_exclude_end" >> "$temp_path"
  fi
  if [[ -f "$exclude_path" ]] && cmp -s "$temp_path" "$exclude_path"; then
    rm -f -- "$temp_path"
  else
    mv -- "$temp_path" "$exclude_path"
  fi
}

warn_tracked_git_excludes() {
  local index
  local repo_relative
  repo_relative="${git_target_prefix:+$git_target_prefix/}.dev-workflow/"
  if [[ -n "$(git -C "$git_repo_root" ls-files -- ":(literal)$repo_relative" 2>/dev/null)" ]]; then
    echo "警告：Git 已跟踪 dev-workflow 元数据，info/exclude 不会阻止上传：.dev-workflow/" >&2
  fi
  for index in "${!file_paths[@]}"; do
    case "${file_paths[$index]}" in docs/operations/runbooks/*) continue ;; esac
    case "${file_actions[$index]}" in
      created|appended|managed-block) ;;
      *) continue ;;
    esac
    repo_relative="${git_target_prefix:+$git_target_prefix/}${file_paths[$index]}"
    if git -C "$git_repo_root" ls-files --error-unmatch -- ":(literal)$repo_relative" >/dev/null 2>&1; then
      echo "警告：Git 已跟踪包含 dev-workflow 内容的文件，info/exclude 不会阻止上传：${file_paths[$index]}" >&2
    fi
  done
}

warn_ineffective_git_excludes() {
  local index
  if ! git -C "$target_root" check-ignore --no-index -q -- '.dev-workflow/manifest.json'; then
    echo "警告：Git 的最终 ignore 规则未排除 dev-workflow 元数据：.dev-workflow/manifest.json" >&2
  fi
  for index in "${!file_paths[@]}"; do
    [[ "${file_actions[$index]}" == "created" ]] || continue
    case "${file_paths[$index]}" in
      docs/operations/runbooks/*)
        if git -C "$target_root" check-ignore --no-index -q -- "${file_paths[$index]}"; then
          echo "警告：Git 的最终 ignore 规则错误地隐藏团队共享 Runbook：${file_paths[$index]}" >&2
        fi
        continue
        ;;
    esac
    if ! git -C "$target_root" check-ignore --no-index -q -- "${file_paths[$index]}"; then
      echo "警告：Git 的最终 ignore 规则未排除 dev-workflow 文件：${file_paths[$index]}" >&2
    fi
  done
}

prompt_choice() {
  local label="$1"
  local default_value="$2"
  local first_value="$3"
  local second_value="$4"
  local answer
  while true; do
    printf '%s [%s]: ' "$label" "$default_value" >&2
    IFS= read -r answer
    answer="$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    [[ -n "$answer" ]] || answer="$default_value"
    case "$answer" in
      "$first_value"|"$second_value")
        prompt_result="$answer"
        return
        ;;
      *) echo "请输入 ${first_value} 或 ${second_value}。" >&2 ;;
    esac
  done
}

confirm_policy_mutation() {
  local answer
  printf '即将变更 Git 权限策略。请输入 YES 确认：' >&2
  IFS= read -r answer
  [[ "$answer" == "YES" ]] || {
    echo "未确认 Git 权限策略变更，安装已取消。" >&2
    return 1
  }
}

validate_git_policy() {
  local operation="$1"
  local mode="$2"
  local actor="$3"
  case "$mode" in
    manual|auto) ;;
    *) echo "${operation} 模式无效：${mode}（仅支持 manual/auto）" >&2; return 1 ;;
  esac
  case "$actor" in
    user|ai) ;;
    *) echo "${operation} 执行角色无效：${actor}（仅支持 user/ai）" >&2; return 1 ;;
  esac
  if [[ "$mode" == "auto" && "$actor" != "ai" ]]; then
    echo "$operation 使用 auto 模式时执行角色必须是 ai。" >&2
    return 1
  fi
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

read_manifest_capabilities() {
  local path="$1"
  local compact segment residual
  compact="$(tr -d '\r\n' < "$path")"
  if ! printf '%s' "$compact" | grep -Eq '"enabledCapabilities"[[:space:]]*:[[:space:]]*\[[^]]*\]'; then
    return 1
  fi
  segment="$(printf '%s' "$compact" | sed -n -E 's/.*"enabledCapabilities"[[:space:]]*:[[:space:]]*\[([^]]*)\].*/\1/p')"
  residual="$(printf '%s' "$segment" | sed -E 's/"[a-z0-9-]+:[a-z0-9-]+"//g; s/[[:space:],]//g')"
  [[ -z "$residual" ]] || return 1
  printf '%s' "$segment" | tr ',' '\n' | sed -n -E 's/^[[:space:]]*"([a-z0-9-]+:[a-z0-9-]+)"[[:space:]]*$/\1/p'
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
  local capability
  local index
  local packs_json=""
  for pack in "${installed_packs[@]+"${installed_packs[@]}"}"; do
    if [[ -n "$packs_json" ]]; then
      packs_json+=","
    fi
    packs_json+=$'\n    '"\"$pack\""
  done
  local capabilities_json=""
  for capability in "${enabled_capabilities[@]+"${enabled_capabilities[@]}"}"; do
    if [[ -n "$capabilities_json" ]]; then capabilities_json+=","; fi
    capabilities_json+=$'\n    '"\"$capability\""
  done
  local last_audit_json="null"
  [[ -n "$last_audit_at" ]] && last_audit_json="\"$last_audit_at\""
  cat <<EOF
{
  "schemaVersion": 5,
  "managedBy": "dev-workflow",
  "workflowVersion": "$version",
  "installedPacks": [$packs_json
  ],
  "enabledCapabilities": [$capabilities_json
  ],
  "gitPolicy": {
    "pushMode": "$push_mode",
    "pushActor": "$push_actor",
    "mergeMode": "$merge_mode",
    "mergeActor": "$merge_actor",
    "pullRequestMode": "$pull_request_mode",
    "pullRequestActor": "$pull_request_actor",
    "pullRequestRequired": true,
    "ciRequired": true,
    "independentReviewRequired": true,
    "forcePushAllowed": false,
    "directProtectedBranchPushAllowed": false,
    "privilegedOperationsDefault": "deny",
    "deleteAllowed": false,
    "policyChangedAt": "$policy_changed_at",
    "policyChangedBy": "$policy_changed_by"
  },
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
enable_capabilities_csv=""
disable_capabilities_csv=""
push_mode_option=""
push_actor_option=""
merge_mode_option=""
merge_actor_option=""
pull_request_mode_option=""
pull_request_actor_option=""
non_interactive=0
case "${DEV_WORKFLOW_NON_INTERACTIVE:-}" in
  1|true|TRUE|yes|YES) non_interactive=1 ;;
esac
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
    --enable-capabilities)
      [[ $# -ge 2 ]] || { echo "--enable-capabilities 需要逗号分隔的能力 ID" >&2; exit 2; }
      enable_capabilities_csv="${enable_capabilities_csv:+$enable_capabilities_csv,}$2"
      shift 2
      ;;
    --disable-capabilities)
      [[ $# -ge 2 ]] || { echo "--disable-capabilities 需要逗号分隔的能力 ID" >&2; exit 2; }
      disable_capabilities_csv="${disable_capabilities_csv:+$disable_capabilities_csv,}$2"
      shift 2
      ;;
    --push-mode)
      [[ $# -ge 2 ]] || { echo "--push-mode 需要 manual 或 auto" >&2; exit 2; }
      push_mode_option="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
      shift 2
      ;;
    --push-actor)
      [[ $# -ge 2 ]] || { echo "--push-actor 需要 user 或 ai" >&2; exit 2; }
      push_actor_option="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
      shift 2
      ;;
    --merge-mode)
      [[ $# -ge 2 ]] || { echo "--merge-mode 需要 manual 或 auto" >&2; exit 2; }
      merge_mode_option="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
      shift 2
      ;;
    --merge-actor)
      [[ $# -ge 2 ]] || { echo "--merge-actor 需要 user 或 ai" >&2; exit 2; }
      merge_actor_option="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
      shift 2
      ;;
    --pull-request-mode)
      [[ $# -ge 2 ]] || { echo "--pull-request-mode 需要 manual 或 auto" >&2; exit 2; }
      pull_request_mode_option="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
      shift 2
      ;;
    --pull-request-actor)
      [[ $# -ge 2 ]] || { echo "--pull-request-actor 需要 user 或 ai" >&2; exit 2; }
      pull_request_actor_option="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
      shift 2
      ;;
    --non-interactive)
      non_interactive=1
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

detect_git_exclude
if [[ "$git_exclude_available" -eq 1 ]]; then
  validate_git_exclude_block_for_write "$git_exclude_path"
fi

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
existing_git_policy=0
existing_push_mode=""
existing_push_actor=""
existing_merge_mode=""
existing_merge_actor=""
existing_pull_request_mode=""
existing_pull_request_actor=""
existing_policy_changed_at=""
existing_policy_changed_by=""
existing_packs=()
enabled_capabilities=()
old_capabilities_summary=""
valid_capabilities=' api:rest-openapi api:graphql api:grpc api:websocket api:sse containers:oci-docker containers:compose cicd:github-actions cicd:gitlab-ci cicd:jenkins cicd:generic deployment:compose deployment:kubernetes-helm deployment:vm-systemd deployment:serverless deployment:generic '
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
    1|2|3|4|5) ;;
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
  if grep -Eq '"gitPolicy"[[:space:]]*:' "$manifest_path"; then
    existing_git_policy=1
    push_mode="$(git_policy_string_field pushMode "$manifest_path")"
    push_actor="$(git_policy_string_field pushActor "$manifest_path")"
    merge_mode="$(git_policy_string_field mergeMode "$manifest_path")"
    merge_actor="$(git_policy_string_field mergeActor "$manifest_path")"
    delete_allowed="$(git_policy_boolean_field deleteAllowed "$manifest_path")"
    validate_git_policy push "$push_mode" "$push_actor" || exit 1
    validate_git_policy merge "$merge_mode" "$merge_actor" || exit 1
    [[ "$delete_allowed" == "false" ]] || {
      echo "manifest gitPolicy.deleteAllowed 必须为 false。" >&2
      exit 1
    }
    existing_push_mode="$push_mode"
    existing_push_actor="$push_actor"
    existing_merge_mode="$merge_mode"
    existing_merge_actor="$merge_actor"
    if [[ "$existing_schema_version" == "4" || "$existing_schema_version" == "5" ]]; then
      existing_pull_request_mode="$(git_policy_string_field pullRequestMode "$manifest_path")"
      existing_pull_request_actor="$(git_policy_string_field pullRequestActor "$manifest_path")"
      existing_policy_changed_at="$(git_policy_string_field policyChangedAt "$manifest_path")"
      existing_policy_changed_by="$(git_policy_string_field policyChangedBy "$manifest_path")"
      validate_git_policy "pull request" "$existing_pull_request_mode" "$existing_pull_request_actor" || exit 1
      [[ "$(git_policy_boolean_field pullRequestRequired "$manifest_path")" == "true" ]] || { echo "manifest gitPolicy.pullRequestRequired 必须为 true。" >&2; exit 1; }
      [[ "$(git_policy_boolean_field ciRequired "$manifest_path")" == "true" ]] || { echo "manifest gitPolicy.ciRequired 必须为 true。" >&2; exit 1; }
      [[ "$(git_policy_boolean_field independentReviewRequired "$manifest_path")" == "true" ]] || { echo "manifest gitPolicy.independentReviewRequired 必须为 true。" >&2; exit 1; }
      [[ "$(git_policy_boolean_field forcePushAllowed "$manifest_path")" == "false" ]] || { echo "manifest gitPolicy.forcePushAllowed 必须为 false。" >&2; exit 1; }
      [[ "$(git_policy_boolean_field directProtectedBranchPushAllowed "$manifest_path")" == "false" ]] || { echo "manifest gitPolicy.directProtectedBranchPushAllowed 必须为 false。" >&2; exit 1; }
      [[ "$(git_policy_string_field privilegedOperationsDefault "$manifest_path")" == "deny" ]] || { echo "manifest gitPolicy.privilegedOperationsDefault 必须为 deny。" >&2; exit 1; }
      [[ -n "$existing_policy_changed_at" ]] || { echo "manifest gitPolicy.policyChangedAt 缺失。" >&2; exit 1; }
      case "$existing_policy_changed_by" in default|user|migration) ;; *) echo "manifest gitPolicy.policyChangedBy 无效。" >&2; exit 1 ;; esac
    fi
  fi
  if [[ ( "$existing_schema_version" == "4" || "$existing_schema_version" == "5" ) && "$existing_git_policy" -eq 0 ]]; then
    echo "schemaVersion ${existing_schema_version} manifest 缺少 gitPolicy。" >&2
    exit 1
  fi
  if [[ "$existing_schema_version" == "5" ]]; then
    capability_output="$(read_manifest_capabilities "$manifest_path")" || { echo "manifest enabledCapabilities 格式无效。" >&2; exit 1; }
    while IFS= read -r capability; do [[ -n "$capability" ]] && enabled_capabilities+=("$capability"); done <<< "$capability_output"
    old_capabilities_summary="${enabled_capabilities[*]-}"
    seen_capabilities=()
    for capability in "${enabled_capabilities[@]+"${enabled_capabilities[@]}"}"; do
      [[ "$valid_capabilities" == *" $capability "* ]] || { echo "未知 manifest 能力 ID：$capability" >&2; exit 1; }
      contains_item "$capability" "${seen_capabilities[@]+"${seen_capabilities[@]}"}" && { echo "manifest enabledCapabilities 包含重复项：$capability" >&2; exit 1; }
      seen_capabilities+=("$capability")
    done
  fi
  if [[ "$existing_schema_version" == "2" || "$existing_schema_version" == "3" || "$existing_schema_version" == "4" || "$existing_schema_version" == "5" ]]; then
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

for capability in ${enable_capabilities_csv//,/ }; do
  [[ "$valid_capabilities" == *" $capability "* ]] || { echo "未知能力 ID：$capability" >&2; exit 2; }
  contains_item "$capability" "${enabled_capabilities[@]+"${enabled_capabilities[@]}"}" || enabled_capabilities+=("$capability")
done
for capability in ${disable_capabilities_csv//,/ }; do
  [[ "$valid_capabilities" == *" $capability "* ]] || { echo "未知能力 ID：$capability" >&2; exit 2; }
  remaining_capabilities=()
  for existing_capability in "${enabled_capabilities[@]+"${enabled_capabilities[@]}"}"; do
    [[ "$existing_capability" == "$capability" ]] || remaining_capabilities+=("$existing_capability")
  done
  enabled_capabilities=("${remaining_capabilities[@]+"${remaining_capabilities[@]}"}")
done

push_mode="${push_mode:-manual}"
push_actor="${push_actor:-user}"
merge_mode="${merge_mode:-manual}"
merge_actor="${merge_actor:-user}"
pull_request_mode="${existing_pull_request_mode:-manual}"
pull_request_actor="${existing_pull_request_actor:-user}"
[[ -n "$push_mode_option" ]] && push_mode="$push_mode_option"
[[ -n "$push_actor_option" ]] && push_actor="$push_actor_option"
[[ -n "$merge_mode_option" ]] && merge_mode="$merge_mode_option"
[[ -n "$merge_actor_option" ]] && merge_actor="$merge_actor_option"
[[ -n "$pull_request_mode_option" ]] && pull_request_mode="$pull_request_mode_option"
[[ -n "$pull_request_actor_option" ]] && pull_request_actor="$pull_request_actor_option"

if [[ "$existing_git_policy" -eq 0 && "$non_interactive" -eq 0 && "$dry_run" -eq 0 ]]; then
  if [[ ! -t 0 ]]; then
    echo "首次安装需要交互式确认 push、pull request 和 merge 策略；当前 stdin 不是终端。请在交互式终端运行，或明确使用 --non-interactive 采用安全默认值。" >&2
    exit 2
  fi
  echo "配置 Git 交付策略。" >&2
  if [[ -z "$push_actor_option" ]]; then
    prompt_choice "push 执行角色 user/ai" "$push_actor" user ai
    push_actor="$prompt_result"
  fi
  if [[ -z "$push_mode_option" ]]; then
    prompt_choice "push 模式 manual（需人工确认）/auto（AI 自动执行）" "$push_mode" manual auto
    push_mode="$prompt_result"
  fi
  if [[ -z "$merge_actor_option" ]]; then
    prompt_choice "merge 执行角色 user/ai" "$merge_actor" user ai
    merge_actor="$prompt_result"
  fi
  if [[ -z "$merge_mode_option" ]]; then
    prompt_choice "merge 模式 manual（需人工确认）/auto（AI 自动执行）" "$merge_mode" manual auto
    merge_mode="$prompt_result"
  fi
  if [[ -z "$pull_request_actor_option" ]]; then
    prompt_choice "pull request 执行角色 user/ai" "$pull_request_actor" user ai
    pull_request_actor="$prompt_result"
  fi
  if [[ -z "$pull_request_mode_option" ]]; then
    prompt_choice "pull request 模式 manual（需人工确认）/auto（AI 自动执行）" "$pull_request_mode" manual auto
    pull_request_mode="$prompt_result"
  fi
fi

validate_git_policy push "$push_mode" "$push_actor" || exit 2
validate_git_policy merge "$merge_mode" "$merge_actor" || exit 2
validate_git_policy "pull request" "$pull_request_mode" "$pull_request_actor" || exit 2

policy_mutation=0
if [[ "$existing_git_policy" -eq 0 ]]; then
  [[ "$push_mode:$push_actor:$merge_mode:$merge_actor:$pull_request_mode:$pull_request_actor" == "manual:user:manual:user:manual:user" ]] || policy_mutation=1
else
  [[ "$existing_push_mode:$existing_push_actor:$existing_merge_mode:$existing_merge_actor:${existing_pull_request_mode:-manual}:${existing_pull_request_actor:-user}" == "$push_mode:$push_actor:$merge_mode:$merge_actor:$pull_request_mode:$pull_request_actor" ]] || policy_mutation=1
fi
if [[ "$policy_mutation" -eq 1 && "$dry_run" -eq 0 ]]; then
  if [[ "$non_interactive" -eq 1 || ! -t 0 ]]; then
    echo "已有持久 Git 策略的 mode/actor 变更或新安装的非默认策略必须由交互式人工确认。" >&2
    exit 2
  fi
  confirm_policy_mutation || exit 2
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
      if [[ "$existing_schema_version" != "1" && "$(json_string_field workflowVersion "$manifest_path")" == "$workflow_version" ]]; then
        echo "manifest created 文件哈希与流程源不一致：${file_paths[$index]}" >&2
        exit 1
      fi
      if [[ "${file_paths[$index]}" != "scripts/delivery_guard.py" ]]; then
        file_actions[$index]="legacy"
        file_hashes[$index]=""
      fi
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
      echo "未知流程包：${pack}。可用流程包：${available_packs[*]-none}" >&2
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
old_policy_summary=""
if [[ "$existing_git_policy" -eq 1 ]]; then
  old_policy_summary="$existing_push_mode|$existing_push_actor|$existing_merge_mode|$existing_merge_actor|${existing_pull_request_mode:-manual}|${existing_pull_request_actor:-user}|true|true|true|false|false|deny|false"
fi
new_policy_summary="$push_mode|$push_actor|$merge_mode|$merge_actor|$pull_request_mode|$pull_request_actor|true|true|true|false|false|deny|false"
policy_changed_at="$existing_policy_changed_at"
policy_changed_by="$existing_policy_changed_by"
if [[ "$existing_manifest" -eq 0 ]]; then
  policy_changed_at="$now"
  policy_changed_by="default"
  [[ "$new_policy_summary" == "manual|user|manual|user|manual|user|true|true|true|false|false|deny|false" ]] || policy_changed_by="user"
elif [[ "$policy_mutation" -eq 1 ]]; then
  policy_changed_at="$now"
  policy_changed_by="user"
elif [[ "$existing_schema_version" != "4" && "$existing_schema_version" != "5" ]]; then
  policy_changed_at="$now"
  policy_changed_by="migration"
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
        echo "manifest 文件归属冲突：${relative_path}（${file_sources[$existing_index]} / ${overlay_name}）" >&2
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
        actions+=("[skip] ${relative_path}（已存在受管控核心区块）")
        if [[ -z "$existing_index" ]]; then
          set_inventory "$relative_path" "$overlay_name" "managed-block" ""
        fi
      elif [[ "$start_count" -gt 0 || "$end_count" -gt 0 ]]; then
        echo "现有 AGENTS.md 包含不完整或重复的 AI-WORKFLOW 核心标记：$target_path" >&2
        exit 1
      elif [[ "$dry_run" -eq 1 ]]; then
        actions+=("[append] ${relative_path}（保留现有内容，追加通用核心区块）")
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
        actions+=("[append] ${relative_path}（保留现有内容，追加通用核心区块）")
        set_inventory "$relative_path" "$overlay_name" "appended" ""
      fi
      continue
    fi

    if [[ "$relative_path" == "scripts/delivery_guard.py" && -f "$target_path" ]]; then
      guard_source_hash="$(sha256_file "$source_path")"
      guard_target_hash="$(sha256_file "$target_path")"
      if [[ -z "$existing_index" ]]; then
        if [[ "$guard_target_hash" != "$guard_source_hash" ]]; then
          echo "安全关键文件已存在且来源无法验证：$relative_path" >&2
          exit 1
        fi
      elif [[ "${file_actions[$existing_index]}" != "created" || "$guard_target_hash" != "${file_hashes[$existing_index]}" ]]; then
        echo "安全关键文件已被修改或所有权无法验证：$relative_path" >&2
        exit 1
      fi
      if [[ "$guard_target_hash" == "$guard_source_hash" ]]; then
        actions+=("[skip] ${relative_path}（安全关键文件已是当前版本）")
      elif [[ "$dry_run" -eq 1 ]]; then
        actions+=("[update] ${relative_path}（安全关键文件升级）")
      else
        cp "$source_path" "$target_path"
        actions+=("[update] ${relative_path}（安全关键文件升级）")
      fi
      set_inventory "$relative_path" "$overlay_name" "created" "$guard_source_hash"
      continue
    fi

    if [[ -f "$target_path" ]]; then
      actions+=("[skip] ${relative_path}（目标项目已有文件，不覆盖）")
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
new_capabilities_summary="${enabled_capabilities[*]-}"
manifest_changed=0
if [[
  "$existing_manifest" -eq 0 ||
  "$existing_schema_version" != "5" ||
  "$old_version" != "$workflow_version" ||
  "$old_pack_summary" != "$new_pack_summary" ||
  "$old_inventory_summary" != "$new_inventory_summary" ||
  "$old_capabilities_summary" != "$new_capabilities_summary" ||
  "$old_policy_summary" != "$new_policy_summary"
]]; then
  manifest_changed=1
fi
updated_at="$existing_updated_at"
if [[ "$manifest_changed" -eq 1 || -z "$updated_at" ]]; then
  updated_at="$now"
fi

if [[ "$manifest_changed" -eq 1 ]]; then
  if [[ "$dry_run" -eq 1 ]]; then
    actions+=("${manifest_action}（dry-run；version ${workflow_version}）")
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
    actions+=("${manifest_action}（version ${workflow_version}）")
  fi
else
  actions+=("[skip] .dev-workflow/manifest.json（已是当前版本）")
fi

if [[ "$git_exclude_available" -eq 1 ]]; then
  build_git_exclude_patterns
  warn_tracked_git_excludes
  if [[ "$dry_run" -eq 1 ]]; then
    actions+=("[git-exclude] ${git_exclude_path}（dry-run；保留用户内容并更新 dev-workflow managed block）")
  else
    write_git_exclude_block "$git_exclude_path"
    warn_ineffective_git_excludes
    actions+=("[git-exclude] ${git_exclude_path}（已更新 dev-workflow managed block）")
  fi
else
  actions+=("[git-exclude] 跳过（目标目录不在 Git 仓库中）")
  echo "警告：目标目录不在 Git 仓库中，未配置本地 info/exclude；安装仍继续。" >&2
fi

if [[ "${#selected_packs[@]}" -eq 0 ]]; then
  pack_summary="none"
else
  pack_summary="${selected_packs[*]}"
fi

if [[ "$dry_run" -eq 1 ]]; then
  echo "dev-workflow dry-run（未写入文件；packs: ${pack_summary}）"
else
  echo "dev-workflow 安装完成（packs: ${pack_summary}）"
fi
printf '%s\n' "${actions[@]+"${actions[@]}"}"
