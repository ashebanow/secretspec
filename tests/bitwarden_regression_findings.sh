#!/bin/bash
# Regression tests for the PR #166 review findings that are reproducible
# against a live vault (designed for the disposable-Vaultwarden harness, but
# any unlocked vault works). Each test prints:
#   REPRODUCED — the bug is present (expected before the fix)
#   FIXED      — the documented behavior is correct
# Exit 0 iff all findings are FIXED, so this script goes green as the review
# is addressed. Run via: RUN_REGRESSIONS=1 tests/vaultwarden_harness.sh
#
# Covered findings (bw.rs review, 2026-07-23):
#   R1  P1  linked custom field (type 3) anywhere in the vault aborts writes
#   R2  P1  named custom field lost when creating a new item (field=api_key)
#   R3  P1  updates to non-login items write `password` while reads use the
#           type-specific default (set succeeds, get returns the old value)
#   R4  P2  update matches field names case-sensitively while reads are
#           case-insensitive (duplicate field, stale reads)
#
# Covered findings (second review, 2026-07-30):
#   R5  P1  get reads a different, substring-matched item when no exact
#           item of the requested name exists
#   R6  P1  set updates a substring-matched item instead of creating the
#           exactly-named one (silently corrupts an unrelated secret)
#   R7  P1  an explicit secure-note field that is absent falls back to the
#           legacy `value` field / note body instead of erroring
#   R8  P1  built-in typed fields (card exp_month etc.) are written as
#           custom fields on create, so an immediate get returns nothing
#   R9  P2  an unsupported ?type= value is silently ignored and defaults
#           to Login instead of being rejected
set -uo pipefail

# See bitwarden_integration.sh: without a reason, `[project].require_reason`
# ("agents" by default) denies every get/set under a coding agent, and each
# finding below reports itself REPRODUCED on the strength of the denial alone.
export SECRETSPEC_REASON="${SECRETSPEC_REASON:-bw provider regression checks}"

: "${BW_SESSION:?BW_SESSION required (unlocked vault)}"
export BW_SESSION

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$REPO_ROOT/target/debug/secretspec"
[ -x "$BIN" ] || { echo "Build first: cargo build --bin secretspec" >&2; exit 2; }

WORKDIR=$(mktemp -d)
CREATED_IDS=()
FIXED=0; REPRODUCED=0

cleanup() {
  for id in ${CREATED_IDS[@]+"${CREATED_IDS[@]}"}; do
    bw delete item "$id" >/dev/null 2>&1 || true
  done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

mk_item() { # mk_item <json> -> echoes id, tracks for cleanup
  local id
  id=$(printf '%s' "$1" | bw encode | bw create item | jq -r '.id')
  [ -n "$id" ] && [ "$id" != "null" ] || { echo "item creation failed" >&2; return 1; }
  CREATED_IDS+=("$id")
  echo "$id"
}

item_json() { # item_json <name> <type:1 login|2 note> [fields-json]
  jq -n --arg name "$1" --argjson type "$2" --argjson fields "${3:-[]}" '
    {organizationId: null, collectionIds: null, folderId: null, type: $type,
     name: $name, notes: (if $type == 2 then "old-note-value" else null end),
     favorite: false, fields: $fields,
     login: (if $type == 1 then {username: null, password: "unused", totp: null} else null end),
     secureNote: (if $type == 2 then {type: 0} else null end)}'
}

report() { # report <id> <desc> <fixed:0|1> [detail]
  if [ "$3" = "1" ]; then
    FIXED=$((FIXED+1));      printf '  \033[0;32mFIXED\033[0m      %s — %s\n' "$1" "$2"
  else
    REPRODUCED=$((REPRODUCED+1)); printf '  \033[0;31mREPRODUCED\033[0m %s — %s%s\n' "$1" "$2" "${4:+ ($4)}"
  fi
}

cat > "$WORKDIR/secretspec.toml" <<'EOF'
[project]
name = "bw-regression"
revision = "1.0"

[profiles.default]
regr_canary = { required = false, description = "R1 canary write", ref = { item = "Regr Canary Login" } }
regr_new_api_key = { required = false, description = "R2 named field on create", ref = { item = "Regr New Login", field = "api_key" } }
regr_note = { required = false, description = "R3 secure note default", ref = { item = "Regr Note" } }
regr_case = { required = false, description = "R4 case-insensitive update", ref = { item = "Regr Case Item", field = "api_key" } }
regr_exact5 = { required = false, description = "R5 substring get", ref = { item = "Regr Exact Five" } }
regr_target6 = { required = false, description = "R6 substring update", ref = { item = "Regr Target Six" } }
regr_note7 = { required = false, description = "R7 explicit note field", ref = { item = "Regr Note Seven", field = "config_value" } }
regr_card8 = { required = false, description = "R8 card builtin on create", ref = { item = "Regr Card Eight", field = "exp_month" } }
regr_type9 = { required = false, description = "R9 invalid type rejected", ref = { item = "Regr Type Nine" } }
EOF
cd "$WORKDIR" || exit 2

SS() { "$BIN" "$@" --provider bw:// 2>&1; }

echo "── R1: linked custom field (type 3) poisons unrelated writes ──"
LINKED_ID=$(mk_item "$(item_json "Regr Linked Item" 1 '[{"name":"linked_username","value":null,"type":3,"linkedId":100}]')")
OUT=$(SS set regr_canary canary-value); RC=$?
if [ $RC -eq 0 ] && ! grep -qi "unknown field type" <<<"$OUT"; then
  report R1 "write succeeds with a linked field present in the vault" 1
else
  report R1 "any write aborts while a linked field exists" 0 "$(grep -oi 'unknown field type[^\"]*' <<<"$OUT" | head -1)"
fi
bw delete item "$LINKED_ID" >/dev/null 2>&1 && CREATED_IDS=(${CREATED_IDS[@]+"${CREATED_IDS[@]/$LINKED_ID}"})
bw sync >/dev/null 2>&1

echo "── R2: named custom field preserved when creating a new item ──"
SS set regr_new_api_key sk_regr_12345 >/dev/null
NEW_ID=$(bw get item "Regr New Login" 2>/dev/null | jq -r '.id' || true)
[ -n "$NEW_ID" ] && [ "$NEW_ID" != "null" ] && CREATED_IDS+=("$NEW_ID")
GOT=$(SS get regr_new_api_key) || true
if [ "$GOT" = "sk_regr_12345" ]; then
  report R2 "get returns the value through the declared custom field" 1
else
  report R2 "value not readable via field=api_key after create" 0 "stored in login.password instead"
fi

echo "── R3: type-specific default on update (secure note) ──"
mk_item "$(item_json "Regr Note" 2)" >/dev/null
GOT=$(SS get regr_note) || true
[ "$GOT" = "old-note-value" ] || echo "  (pre-check unexpected: get returned '$GOT')"
SS set regr_note new-note-value >/dev/null
GOT=$(SS get regr_note) || true
if [ "$GOT" = "new-note-value" ]; then
  report R3 "set targets the same default field the getter reads" 1
else
  report R3 "set wrote a password field; get still returns '$GOT'" 0
fi

echo "── R4: case-insensitive field matching on update ──"
mk_item "$(item_json "Regr Case Item" 1 '[{"name":"API_KEY","value":"old-value","type":1}]')" >/dev/null
GOT=$(SS get regr_case) || true
[ "$GOT" = "old-value" ] || echo "  (pre-check unexpected: get returned '$GOT')"
SS set regr_case new-value >/dev/null
GOT=$(SS get regr_case) || true
if [ "$GOT" = "new-value" ]; then
  report R4 "update matched the existing field case-insensitively" 1
else
  report R4 "update added a duplicate field; get still returns '$GOT'" 0
fi

echo "── R5: get must not read a substring-matched item ──"
mk_item "$(item_json "Regr Exact Five Legacy" 1 '[]' | jq '.login.password = "legacy-secret-5"')" >/dev/null
bw sync >/dev/null 2>&1
GOT=$(SS get regr_exact5); RC=$?
if [ $RC -ne 0 ] || grep -qi "not found" <<<"$GOT"; then
  report R5 "no exact item: substring match is not read" 1
else
  report R5 "get returned another item's secret via substring search" 0 "got '$GOT'"
fi

echo "── R6: set must not update a substring-matched item ──"
mk_item "$(item_json "Old Regr Target Six" 1 '[]' | jq '.login.password = "old-password-6"')" >/dev/null
bw sync >/dev/null 2>&1
SS set regr_target6 new-secret-6 >/dev/null
bw sync >/dev/null 2>&1
EXACT_ID=$(bw list items --search "Regr Target Six" 2>/dev/null | jq -r '[.[] | select(.name == "Regr Target Six")][0].id // empty')
[ -n "$EXACT_ID" ] && CREATED_IDS+=("$EXACT_ID")
OLD_PW=$(bw list items --search "Old Regr Target Six" 2>/dev/null | jq -r '[.[] | select(.name == "Old Regr Target Six")][0].login.password')
if [ -n "$EXACT_ID" ] && [ "$OLD_PW" = "old-password-6" ]; then
  report R6 "set created the exact item; the substring match is untouched" 1
else
  report R6 "set overwrote the substring-matched item instead of creating one" 0 "old item password is now '$OLD_PW'"
fi

echo "── R7: absent explicit note field must not fall back ──"
mk_item "$(item_json "Regr Note Seven" 2 '[{"name":"value","value":"other-secret-7","type":1}]')" >/dev/null
bw sync >/dev/null 2>&1
GOT=$(SS get regr_note7) || true
if grep -qi "not found" <<<"$GOT"; then
  report R7 "missing field=config_value reads as not-found" 1
else
  report R7 "explicit field=config_value returned a different field" 0 "got '$GOT'"
fi

echo "── R8: built-in card fields must survive create ──"
"$BIN" set regr_card8 12 --provider 'bw://?type=card' >/dev/null 2>&1
bw sync >/dev/null 2>&1
CARD_ID=$(bw list items --search "Regr Card Eight" 2>/dev/null | jq -r '[.[] | select(.name == "Regr Card Eight")][0].id // empty')
[ -n "$CARD_ID" ] && CREATED_IDS+=("$CARD_ID")
GOT=$("$BIN" get regr_card8 --provider 'bw://?type=card' 2>&1) || true
if [ "$GOT" = "12" ]; then
  report R8 "exp_month readable right after create" 1
else
  report R8 "set stored exp_month as a custom field; get reads the null card.expMonth" 0 "got '$GOT'"
fi

echo "── R9: unsupported ?type= must be rejected, not defaulted ──"
OUT=$("$BIN" get regr_type9 --provider 'bw://?type=sshkee' 2>&1) || true
if grep -qi "sshkee" <<<"$OUT"; then
  report R9 "typo'd type= is reported as a configuration error" 1
else
  report R9 "type=sshkee silently ignored (falls back to Login)" 0
fi

echo
echo "Findings fixed: $FIXED · reproduced: $REPRODUCED"
[ "$REPRODUCED" -eq 0 ]
