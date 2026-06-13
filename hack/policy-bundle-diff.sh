#!/usr/bin/env bash
# policy-bundle-diff.sh — structural diff between two cerbos policy bundle directories.
#
# Usage: policy-bundle-diff.sh <baseline-dir> <new-dir> [--ignore-disabled] [--include-comments]
#
# Emits a JSON document on stdout describing the structural changes between the two
# bundles. Diagnostic messages go to stderr. Exit codes:
#   0 = no changes
#   1 = changes detected
#   2 = error (bad input, malformed YAML, etc.)
#
# Identification: a rule is identified by (policy_fqn, rule.name). The same
# (fqn, name) appearing in different files between bundles is reported as
# `moved`, not added+removed. Unnamed rules cannot be tracked across moves
# and are reported per-file as added/removed.

set -euo pipefail

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------

BASELINE=""
NEW=""
IGNORE_DISABLED=0
INCLUDE_COMMENTS=0

usage() {
  cat <<EOF
Usage: $(basename "$0") <baseline-dir> <new-dir> [options]

Options:
  --ignore-disabled    Skip rules in policies marked disabled: true
  --include-comments   Treat comment-only changes as differences (default: ignored)
  -h, --help           Show this help

Exit codes: 0 (no changes), 1 (changes), 2 (error)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ignore-disabled) IGNORE_DISABLED=1; shift ;;
    --include-comments) INCLUDE_COMMENTS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "ERROR: unknown flag: $1" >&2; exit 2 ;;
    *)
      if [[ -z "$BASELINE" ]]; then
        BASELINE="$1"
      elif [[ -z "$NEW" ]]; then
        NEW="$1"
      else
        echo "ERROR: too many positional arguments" >&2
        exit 2
      fi
      shift
      ;;
  esac
done

if [[ -z "$BASELINE" || -z "$NEW" ]]; then
  echo "ERROR: both <baseline-dir> and <new-dir> are required" >&2
  usage >&2
  exit 2
fi

[[ -d "$BASELINE" ]] || { echo "ERROR: baseline dir does not exist: $BASELINE" >&2; exit 2; }
[[ -d "$NEW" ]] || { echo "ERROR: new dir does not exist: $NEW" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Cerbos's sanitize() replaces non-alphanumeric (excluding underscore) with _.
sanitize() {
  # Replace non-alphanumeric (excluding underscore) with _, matching cerbos's
  # internal/namer.sanitize().
  printf '%s' "$1" | tr -c 'a-zA-Z0-9_' '_'
}

# extract_comments <yaml_file>
# Returns the concatenation of all comment lines (without the leading `#`),
# stripped of surrounding whitespace, joined by literal "\n".
extract_comments() {
  local file="$1"
  awk '
    BEGIN { count = 0 }
    /^[[:space:]]*#/ {
      sub(/^[[:space:]]*#[[:space:]]*/, "")
      sub(/[[:space:]]+$/, "")
      if (count > 0) printf "\\n"
      printf "%s", $0
      count++
    }
  ' "$file"
}

# extract_policy_data <yaml_file> <relative_path>
# Outputs ONE JSON object describing the policy, or nothing on parse failure.
# Schema:
#   {
#     "fqn": "...",
#     "kind": "resource_policy|principal_policy|role_policy|derived_role",
#     "path": "<relative path>",
#     "disabled": true|false,
#     "comments": "...",
#     "schemas": {...},          // resource_policy only
#     "rules": [                  // normalised rule list with explicit names
#       {"name": "...", "data": {...}},
#       ...
#     ],
#     "unnamed_rules": [          // rules with no name field
#       {"index": 0, "data": {...}},
#       ...
#     ]
#   }
extract_policy_data() {
  local file="$1"
  local rel="$2"
  local raw

  if ! raw=$(yq -o=json '.' "$file" 2>/dev/null); then
    echo "ERROR: failed to parse $file" >&2
    return 1
  fi

  # Empty file or no recognised policy: skip silently.
  if [[ -z "$raw" || "$raw" == "null" ]]; then
    return 0
  fi

  local disabled
  disabled=$(echo "$raw" | jq -r '.disabled // false')

  local comments
  comments=$(extract_comments "$file")

  # Determine policy kind by which top-level key is present.
  if echo "$raw" | jq -e '.resourcePolicy' > /dev/null 2>&1; then
    local resource version scope fqn
    resource=$(echo "$raw" | jq -r '.resourcePolicy.resource')
    version=$(echo "$raw" | jq -r '.resourcePolicy.version // "default"')
    scope=$(echo "$raw" | jq -r '.resourcePolicy.scope // ""')
    fqn="cerbos.resource.$(sanitize "$resource").v$(sanitize "$version")"
    [[ -n "$scope" ]] && fqn="$fqn/$scope"

    echo "$raw" | jq \
      --arg fqn "$fqn" \
      --arg kind "resource_policy" \
      --arg path "$rel" \
      --arg comments "$comments" \
      --argjson disabled "$disabled" '
      {
        fqn: $fqn,
        kind: $kind,
        path: $path,
        disabled: $disabled,
        comments: $comments,
        schemas: (.resourcePolicy.schemas // {}),
        rules: [
          (.resourcePolicy.rules // [])
          | to_entries[]
          | select(.value.name != null)
          | {name: .value.name, data: .value}
        ],
        unnamed_rules: [
          (.resourcePolicy.rules // [])
          | to_entries[]
          | select(.value.name == null)
          | {index: .key, data: .value}
        ]
      }
    '
  elif echo "$raw" | jq -e '.principalPolicy' > /dev/null 2>&1; then
    local principal version scope fqn
    principal=$(echo "$raw" | jq -r '.principalPolicy.principal')
    version=$(echo "$raw" | jq -r '.principalPolicy.version // "default"')
    scope=$(echo "$raw" | jq -r '.principalPolicy.scope // ""')
    fqn="cerbos.principal.$(sanitize "$principal").v$(sanitize "$version")"
    [[ -n "$scope" ]] && fqn="$fqn/$scope"

    # Principal policy rules are {resource, actions:[{name, action, effect, condition}]}.
    # We flatten to actions across all rules; each action's `name` is the rule identifier.
    echo "$raw" | jq \
      --arg fqn "$fqn" \
      --arg kind "principal_policy" \
      --arg path "$rel" \
      --arg comments "$comments" \
      --argjson disabled "$disabled" '
      {
        fqn: $fqn,
        kind: $kind,
        path: $path,
        disabled: $disabled,
        comments: $comments,
        schemas: {},
        rules: [
          (.principalPolicy.rules // [])[]
          | .resource as $res
          | (.actions // [])[]
          | select(.name != null)
          | {name: .name, data: (. + {_resource: $res})}
        ],
        unnamed_rules: [
          (.principalPolicy.rules // [])[]
          | .resource as $res
          | (.actions // [])
          | to_entries[]
          | select(.value.name == null)
          | {index: .key, data: (.value + {_resource: $res})}
        ]
      }
    '
  elif echo "$raw" | jq -e '.rolePolicy' > /dev/null 2>&1; then
    local role version scope fqn
    role=$(echo "$raw" | jq -r '.rolePolicy.role')
    version=$(echo "$raw" | jq -r '.rolePolicy.version // "default"')
    scope=$(echo "$raw" | jq -r '.rolePolicy.scope // ""')
    fqn="cerbos.role.$(sanitize "$role").v$(sanitize "$version")"
    [[ -n "$scope" ]] && fqn="$fqn/$scope"

    echo "$raw" | jq \
      --arg fqn "$fqn" \
      --arg kind "role_policy" \
      --arg path "$rel" \
      --arg comments "$comments" \
      --argjson disabled "$disabled" '
      {
        fqn: $fqn,
        kind: $kind,
        path: $path,
        disabled: $disabled,
        comments: $comments,
        schemas: {},
        rules: [
          (.rolePolicy.rules // [])
          | to_entries[]
          | select(.value.name != null)
          | {name: .value.name, data: .value}
        ],
        unnamed_rules: [
          (.rolePolicy.rules // [])
          | to_entries[]
          | select(.value.name == null)
          | {index: .key, data: .value}
        ]
      }
    '
  elif echo "$raw" | jq -e '.derivedRoles' > /dev/null 2>&1; then
    local name fqn
    name=$(echo "$raw" | jq -r '.derivedRoles.name')
    fqn="cerbos.derived_roles.$(sanitize "$name")"

    echo "$raw" | jq \
      --arg fqn "$fqn" \
      --arg kind "derived_role" \
      --arg path "$rel" \
      --arg comments "$comments" \
      --argjson disabled "$disabled" '
      {
        fqn: $fqn,
        kind: $kind,
        path: $path,
        disabled: $disabled,
        comments: $comments,
        schemas: {},
        rules: [
          (.derivedRoles.definitions // [])
          | to_entries[]
          | select(.value.name != null)
          | {name: .value.name, data: .value}
        ],
        unnamed_rules: []
      }
    '
  fi
}

# extract_all <dir>
# Outputs a JSON array of policy descriptors for every YAML in the dir.
extract_all() {
  local dir="$1"
  local entries=()
  local f rel desc
  while IFS= read -r f; do
    rel="${f#"$dir"/}"
    desc=$(extract_policy_data "$f" "$rel") || return 2
    if [[ -n "$desc" ]]; then
      entries+=("$desc")
    fi
  done < <(find "$dir" -type f \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | sort)

  if [[ ${#entries[@]} -eq 0 ]]; then
    echo "[]"
  else
    printf '%s\n' "${entries[@]}" | jq -s '.'
  fi
}

# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------

# first_diff_field <before_json> <after_json>
# Walks two JSON values and returns "<jq_path>\t<before_json>\t<after_json>"
# for the first differing leaf. Returns empty if no diff.
# We prefer well-known cerbos rule fields in priority order to produce a
# stable `field_path` for `details`.
first_diff_field() {
  local before="$1"
  local after="$2"
  local priority=(
    "condition.match.expr"
    "condition.match.all"
    "condition.match.any"
    "condition.match.none"
    "condition"
    "actions"
    "allowActions"
    "effect"
    "roles"
    "derivedRoles"
    "parentRoles"
    "schemas.resourceSchema.ref"
    "schemas.principalSchema.ref"
    "schemas"
    "output"
  )
  for path in "${priority[@]}"; do
    # jq path: convert dots to bracket-style for safety, but our fields don't
    # have dots in keys so simple dot-notation works.
    local bval aval
    bval=$(echo "$before" | jq -c "try .$path catch null")
    aval=$(echo "$after"  | jq -c "try .$path catch null")
    if [[ "$bval" != "$aval" ]]; then
      # Element-wise drill: if both sides are arrays, walk to find the first
      # differing index and emit `<path>.<index>` with that element's
      # before/after (null when added/removed). Matches the spec's
      # "deepest leaf where the actual difference is" rule.
      local btype atype
      btype=$(echo "$bval" | jq -r 'type' 2>/dev/null || echo "")
      atype=$(echo "$aval" | jq -r 'type' 2>/dev/null || echo "")
      if [[ "$btype" == "array" && "$atype" == "array" ]]; then
        local blen alen maxlen i belem aelem
        blen=$(echo "$bval" | jq 'length')
        alen=$(echo "$aval" | jq 'length')
        maxlen=$(( blen > alen ? blen : alen ))
        for ((i = 0; i < maxlen; i++)); do
          if (( i < blen )); then
            belem=$(echo "$bval" | jq -c ".[$i]")
          else
            belem="null"
          fi
          if (( i < alen )); then
            aelem=$(echo "$aval" | jq -c ".[$i]")
          else
            aelem="null"
          fi
          if [[ "$belem" != "$aelem" ]]; then
            printf '%s.%d\t%s\t%s' "$path" "$i" "$belem" "$aelem"
            return 0
          fi
        done
      fi
      # Not an array pair (or arrays equal element-wise but jq differs on
      # whitespace, which we already eliminated via -c). Emit whole-value.
      printf '%s\t%s\t%s' "$path" "$bval" "$aval"
      return 0
    fi
  done
  # Fallback: emit a synthetic top-level diff if structural inequality but
  # no priority field matched (rare for our policy shapes).
  if [[ "$(echo "$before" | jq -cS '.')" != "$(echo "$after" | jq -cS '.')" ]]; then
    printf '%s\t%s\t%s' "" "$before" "$after"
    return 0
  fi
}

# emit_change adds one change entry to CHANGES.
CHANGES=()
emit_change() {
  CHANGES+=("$1")
}

# compute_diff <baseline_json> <new_json>
# Builds the changes array.
compute_diff() {
  local baseline="$1"
  local new="$2"

  # If --ignore-disabled, filter out disabled policies from BOTH sides
  # before any further analysis.
  if [[ "$IGNORE_DISABLED" -eq 1 ]]; then
    baseline=$(echo "$baseline" | jq '[.[] | select(.disabled == false)]')
    new=$(echo "$new" | jq '[.[] | select(.disabled == false)]')
  fi

  # Build lookup: fqn → policy descriptor
  local baseline_fqns new_fqns all_fqns
  baseline_fqns=$(echo "$baseline" | jq -r '.[].fqn')
  new_fqns=$(echo "$new" | jq -r '.[].fqn')
  all_fqns=$(printf '%s\n%s\n' "$baseline_fqns" "$new_fqns" | sort -u)

  local fqn
  while IFS= read -r fqn; do
    [[ -z "$fqn" ]] && continue

    local bp np
    bp=$(echo "$baseline" | jq --arg fqn "$fqn" '[.[] | select(.fqn == $fqn)] | first // null')
    np=$(echo "$new"      | jq --arg fqn "$fqn" '[.[] | select(.fqn == $fqn)] | first // null')

    if [[ "$bp" == "null" && "$np" != "null" ]]; then
      diff_policy_added "$np"
    elif [[ "$np" == "null" && "$bp" != "null" ]]; then
      diff_policy_removed "$bp"
    else
      diff_policy_modified "$bp" "$np"
    fi
  done <<< "$all_fqns"
}

# diff_policy_added <policy_json>
# Policy exists in NEW only — emit added entries for every rule and unnamed rule.
diff_policy_added() {
  local p="$1"
  local fqn kind path
  fqn=$(echo "$p" | jq -r '.fqn')
  kind=$(echo "$p" | jq -r '.kind')
  path=$(echo "$p" | jq -r '.path')

  local rule_name
  while IFS= read -r rule_name; do
    [[ -z "$rule_name" ]] && continue
    emit_change "$(jq -n \
      --arg type "added" --arg kind "$kind" --arg fqn "$fqn" \
      --arg rule_name "$rule_name" --arg after_path "$path" \
      '{type: $type, kind: $kind, fqn: $fqn, rule_name: $rule_name, after_path: $after_path}'
    )"
  done < <(echo "$p" | jq -r '.rules[].name')

  # Unnamed rules: one entry per rule, no rule_name.
  local unnamed_count
  unnamed_count=$(echo "$p" | jq '.unnamed_rules | length')
  if [[ "$unnamed_count" -gt 0 ]]; then
    local i
    for ((i = 0; i < unnamed_count; i++)); do
      emit_change "$(jq -n \
        --arg type "added" --arg kind "$kind" --arg fqn "$fqn" \
        --arg after_path "$path" \
        '{type: $type, kind: $kind, fqn: $fqn, after_path: $after_path}'
      )"
    done
  fi
}

# diff_policy_removed <policy_json>
diff_policy_removed() {
  local p="$1"
  local fqn kind path
  fqn=$(echo "$p" | jq -r '.fqn')
  kind=$(echo "$p" | jq -r '.kind')
  path=$(echo "$p" | jq -r '.path')

  local rule_name
  while IFS= read -r rule_name; do
    [[ -z "$rule_name" ]] && continue
    emit_change "$(jq -n \
      --arg type "removed" --arg kind "$kind" --arg fqn "$fqn" \
      --arg rule_name "$rule_name" --arg before_path "$path" \
      '{type: $type, kind: $kind, fqn: $fqn, rule_name: $rule_name, before_path: $before_path}'
    )"
  done < <(echo "$p" | jq -r '.rules[].name')

  local unnamed_count
  unnamed_count=$(echo "$p" | jq '.unnamed_rules | length')
  if [[ "$unnamed_count" -gt 0 ]]; then
    local i
    for ((i = 0; i < unnamed_count; i++)); do
      emit_change "$(jq -n \
        --arg type "removed" --arg kind "$kind" --arg fqn "$fqn" \
        --arg before_path "$path" \
        '{type: $type, kind: $kind, fqn: $fqn, before_path: $before_path}'
      )"
    done
  fi
}

# diff_policy_modified <baseline_json> <new_json>
diff_policy_modified() {
  local bp="$1"
  local np="$2"
  local fqn kind bpath npath
  fqn=$(echo "$bp" | jq -r '.fqn')
  kind=$(echo "$bp" | jq -r '.kind')
  bpath=$(echo "$bp" | jq -r '.path')
  npath=$(echo "$np" | jq -r '.path')

  # 1) Schemas — emit schema-kind entries (resource_policy only).
  if [[ "$kind" == "resource_policy" ]]; then
    diff_schemas "$bp" "$np"
  fi

  # 2) Named rules — match by name across files.
  local rule_names_b rule_names_n all_names
  rule_names_b=$(echo "$bp" | jq -r '.rules[].name')
  rule_names_n=$(echo "$np" | jq -r '.rules[].name')
  all_names=$(printf '%s\n%s\n' "$rule_names_b" "$rule_names_n" | sort -u)

  local rule_name
  while IFS= read -r rule_name; do
    [[ -z "$rule_name" ]] && continue

    local b_rule n_rule
    b_rule=$(echo "$bp" | jq --arg n "$rule_name" '[.rules[] | select(.name == $n)] | first // null')
    n_rule=$(echo "$np" | jq --arg n "$rule_name" '[.rules[] | select(.name == $n)] | first // null')

    if [[ "$b_rule" == "null" && "$n_rule" != "null" ]]; then
      # Added in new (same policy, different rule)
      emit_change "$(jq -n \
        --arg type "added" --arg kind "$kind" --arg fqn "$fqn" \
        --arg rule_name "$rule_name" --arg after_path "$npath" \
        '{type: $type, kind: $kind, fqn: $fqn, rule_name: $rule_name, after_path: $after_path}'
      )"
    elif [[ "$n_rule" == "null" && "$b_rule" != "null" ]]; then
      emit_change "$(jq -n \
        --arg type "removed" --arg kind "$kind" --arg fqn "$fqn" \
        --arg rule_name "$rule_name" --arg before_path "$bpath" \
        '{type: $type, kind: $kind, fqn: $fqn, rule_name: $rule_name, before_path: $before_path}'
      )"
    else
      # Rule exists in both. Compare paths and content.
      local b_data n_data
      b_data=$(echo "$b_rule" | jq -c '.data')
      n_data=$(echo "$n_rule" | jq -c '.data')

      if [[ "$bpath" != "$npath" ]]; then
        # Moved (regardless of whether content changed; spec says moved).
        emit_change "$(jq -n \
          --arg type "moved" --arg kind "$kind" --arg fqn "$fqn" \
          --arg rule_name "$rule_name" --arg before_path "$bpath" --arg after_path "$npath" \
          '{type: $type, kind: $kind, fqn: $fqn, rule_name: $rule_name, before_path: $before_path, after_path: $after_path}'
        )"
      elif [[ "$b_data" != "$n_data" ]]; then
        # Modified — find first differing field path.
        local diff_line field_path before_val after_val
        diff_line=$(first_diff_field "$b_data" "$n_data" || true)
        if [[ -n "$diff_line" ]]; then
          field_path=$(echo -e "$diff_line" | cut -f1)
          before_val=$(echo -e "$diff_line" | cut -f2)
          after_val=$(echo -e "$diff_line" | cut -f3)
          emit_change "$(jq -n \
            --arg type "modified" --arg kind "$kind" --arg fqn "$fqn" \
            --arg rule_name "$rule_name" --arg before_path "$bpath" --arg after_path "$npath" \
            --arg field_path "$field_path" \
            --argjson before "$before_val" --argjson after "$after_val" '
            {
              type: $type,
              kind: $kind,
              fqn: $fqn,
              rule_name: $rule_name,
              before_path: $before_path,
              after_path: $after_path,
              details: {field_path: $field_path, before: $before, after: $after}
            }'
          )"
        fi
      fi
    fi
  done <<< "$all_names"

  # 3) Unnamed rules — track per-file; only emit if paths differ.
  local b_unnamed_count n_unnamed_count
  b_unnamed_count=$(echo "$bp" | jq '.unnamed_rules | length')
  n_unnamed_count=$(echo "$np" | jq '.unnamed_rules | length')
  if [[ "$bpath" != "$npath" ]]; then
    # File renamed: emit removed for each baseline unnamed rule and added
    # for each new unnamed rule.
    local i
    for ((i = 0; i < b_unnamed_count; i++)); do
      emit_change "$(jq -n \
        --arg type "removed" --arg kind "$kind" --arg fqn "$fqn" --arg before_path "$bpath" \
        '{type: $type, kind: $kind, fqn: $fqn, before_path: $before_path}'
      )"
    done
    for ((i = 0; i < n_unnamed_count; i++)); do
      emit_change "$(jq -n \
        --arg type "added" --arg kind "$kind" --arg fqn "$fqn" --arg after_path "$npath" \
        '{type: $type, kind: $kind, fqn: $fqn, after_path: $after_path}'
      )"
    done
  fi
  # NOTE: unnamed-rule content-change detection (same file, different content)
  # is intentionally not implemented — the test surface only covers rename.

  # 4) Comments — only when --include-comments.
  if [[ "$INCLUDE_COMMENTS" -eq 1 ]]; then
    local b_comments n_comments
    b_comments=$(echo "$bp" | jq -r '.comments')
    n_comments=$(echo "$np" | jq -r '.comments')
    if [[ "$b_comments" != "$n_comments" ]]; then
      emit_change "$(jq -n \
        --arg type "modified" --arg kind "$kind" --arg fqn "$fqn" \
        --arg before_path "$bpath" --arg after_path "$npath" \
        --arg field_path "_comments" \
        --arg before "$b_comments" --arg after "$n_comments" '
        {
          type: $type,
          kind: $kind,
          fqn: $fqn,
          before_path: $before_path,
          after_path: $after_path,
          details: {field_path: $field_path, before: $before, after: $after}
        }'
      )"
    fi
  fi
}

# diff_schemas <baseline_policy> <new_policy>
# Emits one kind=schema entry per changed schema ref.
diff_schemas() {
  local bp="$1"
  local np="$2"
  local fqn bpath npath
  fqn=$(echo "$bp" | jq -r '.fqn')
  bpath=$(echo "$bp" | jq -r '.path')
  npath=$(echo "$np" | jq -r '.path')

  for key in "resourceSchema" "principalSchema"; do
    local b_ref n_ref
    b_ref=$(echo "$bp" | jq -r --arg k "$key" '.schemas[$k].ref // empty')
    n_ref=$(echo "$np" | jq -r --arg k "$key" '.schemas[$k].ref // empty')
    if [[ "$b_ref" != "$n_ref" ]]; then
      emit_change "$(jq -n \
        --arg type "modified" --arg kind "schema" --arg fqn "$fqn" \
        --arg before_path "$bpath" --arg after_path "$npath" \
        --arg field_path "schemas.${key}.ref" \
        --arg before "$b_ref" --arg after "$n_ref" '
        {
          type: $type,
          kind: $kind,
          fqn: $fqn,
          before_path: $before_path,
          after_path: $after_path,
          details: {field_path: $field_path, before: $before, after: $after}
        }'
      )"
    fi
  done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo "Scanning baseline: $BASELINE" >&2
baseline_data=$(extract_all "$BASELINE") || exit 2
echo "Scanning new: $NEW" >&2
new_data=$(extract_all "$NEW") || exit 2

compute_diff "$baseline_data" "$new_data"

# Assemble output. CHANGES is an array of JSON object strings.
if [[ ${#CHANGES[@]} -eq 0 ]]; then
  echo '{"schema_version":"1","changes":[]}'
  exit 0
fi

changes_json=$(printf '%s\n' "${CHANGES[@]}" | jq -s '.')
echo "{\"schema_version\":\"1\",\"changes\":$changes_json}"

exit 1
