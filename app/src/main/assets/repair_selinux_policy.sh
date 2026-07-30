#!/system/bin/sh
# Repair Android netlink policy capabilities in a private copy, then load it.
# This never writes to /sys/fs/selinux/policy directly.

set -eu

readonly policy_source=/sys/fs/selinux/policy
readonly state_dir=/data/adb/anchor
readonly identifier_max=256
readonly config_mask=3221225472 # 0xc0000000
readonly run_log="$state_dir/policy-repair.log"
readonly state_file="$state_dir/policy-repair.state"
stage="${ANCHOR_POLICY_REPAIR_STAGE:-manual}"
original_config=unknown
fixed_config=unknown
load_policy_rc=not-run
failure_reason=

fail() {
    failure_reason="$*"
    echo "policy repair: $*" >&2
    exit 1
}

read_le32() {
    od -An -tu4 -j "$1" -N 4 "$2" | tr -d '[:space:]'
}

write_le32() {
    value="$1"
    offset="$2"
    target="$3"
    b0=$((value & 255))
    b1=$(((value >> 8) & 255))
    b2=$(((value >> 16) & 255))
    b3=$(((value >> 24) & 255))
    encoded=$(printf '\\%03o\\%03o\\%03o\\%03o' "$b0" "$b1" "$b2" "$b3")
    printf '%b' "$encoded" |
        dd of="$target" bs=1 seek="$offset" conv=notrunc status=none || return 1
}

umask 077
mkdir -p "$state_dir" || fail "cannot create state directory"
chmod 700 "$state_dir" || fail "cannot secure state directory"
touch "$run_log" || fail "cannot create run log"
chmod 600 "$run_log" || fail "cannot secure run log"
exec >>"$run_log" 2>&1
printf '\n===== policy repair started: %s pid=%s =====\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$$"
policy_temp=$(mktemp "$state_dir/selinux-policy.XXXXXX") || fail "cannot create temporary policy"
finish() {
    status=$?
    rm -f "$policy_temp"
    state_temp=$(mktemp "$state_dir/policy-repair.state.XXXXXX") || exit "$status"
    if [ "$status" -eq 0 ]; then result=success; else result=failed; fi
    {
        printf 'result=%s\n' "$result"
        printf 'stage=%s\n' "$stage"
        printf 'original_config=0x%08x\n' "$original_config" 2>/dev/null || printf 'original_config=%s\n' "$original_config"
        printf 'fixed_config=0x%08x\n' "$fixed_config" 2>/dev/null || printf 'fixed_config=%s\n' "$fixed_config"
        printf 'load_policy_rc=%s\n' "$load_policy_rc"
        [ -z "$failure_reason" ] || printf 'reason=%s\n' "$failure_reason"
        printf 'selinux=%s\n' "$(getenforce 2>/dev/null || echo unknown)"
        printf 'timestamp=%s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    } >"$state_temp"
    chown 0:0 "$state_temp" 2>/dev/null || true
    chmod 600 "$state_temp" && mv -f "$state_temp" "$state_file"
    printf '===== policy repair finished: status=%s =====\n' "$status"
    trap - EXIT
    exit "$status"
}
trap finish EXIT

cat "$policy_source" > "$policy_temp" || fail "cannot copy source policy"
[ -s "$policy_temp" ] || fail "copied policy is empty"
size_before=$(stat -c %s "$policy_temp") || fail "cannot read original policy size"
identifier_length=$(read_le32 4 "$policy_temp") || fail "cannot read identifier length"
[ "$identifier_length" -gt 0 ] && [ "$identifier_length" -le "$identifier_max" ] ||
    fail "invalid identifier length: $identifier_length"

identifier=$(dd if="$policy_temp" bs=1 skip=8 count="$identifier_length" status=none) ||
    fail "cannot read policy identifier"
[ "$identifier" = "SE Linux" ] || fail "unexpected policy identifier"

config_offset=$((12 + identifier_length))
original_config=$(read_le32 "$config_offset" "$policy_temp") || fail "cannot read policy config"
fixed_config=$((original_config | config_mask))
non_target_before=$((original_config & ~config_mask))
non_target_after=$((fixed_config & ~config_mask))
[ "$non_target_before" -eq "$non_target_after" ] || fail "non-target policy config bits changed"
write_le32 "$fixed_config" "$config_offset" "$policy_temp" || fail "cannot patch policy config"
size_after=$(stat -c %s "$policy_temp") || fail "cannot read patched policy size"
[ "$size_before" -eq "$size_after" ] || fail "policy size changed during patch"
verified_config=$(read_le32 "$config_offset" "$policy_temp") || fail "cannot verify policy config"
[ "$verified_config" -eq "$fixed_config" ] ||
    fail "policy config verification failed: expected $fixed_config, got $verified_config"

printf 'policy repair: config 0x%08x -> 0x%08x (verified)\n' "$original_config" "$verified_config"
policy_version=$(read_le32 "$((config_offset + 4))" "$policy_temp" || true)
printf 'policy repair: version=%s stage=%s\n' "${policy_version:-unknown}" "$stage"
if load_policy "$policy_temp"; then
    load_policy_rc=0
else
    load_policy_rc=$?
    fail "load_policy failed rc=$load_policy_rc"
fi
