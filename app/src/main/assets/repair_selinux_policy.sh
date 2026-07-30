#!/system/bin/sh
# Repair Android netlink policy capabilities in a private copy, then load it.
# This never writes to /sys/fs/selinux/policy directly.

set -eu

readonly policy_source=/sys/fs/selinux/policy
readonly state_dir=/data/adb/anchor
readonly identifier_max=256
readonly config_mask=3221225472 # 0xc0000000
readonly run_log="$state_dir/policy-repair.log"

fail() {
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
    printf '===== policy repair finished: status=%s =====\n' "$status"
    trap - EXIT
    exit "$status"
}
trap finish EXIT

cat "$policy_source" > "$policy_temp" || fail "cannot copy source policy"
identifier_length=$(read_le32 4 "$policy_temp") || fail "cannot read identifier length"
[ "$identifier_length" -gt 0 ] && [ "$identifier_length" -le "$identifier_max" ] ||
    fail "invalid identifier length: $identifier_length"

identifier=$(dd if="$policy_temp" bs=1 skip=8 count="$identifier_length" status=none) ||
    fail "cannot read policy identifier"
[ "$identifier" = "SE Linux" ] || fail "unexpected policy identifier"

config_offset=$((12 + identifier_length))
original_config=$(read_le32 "$config_offset" "$policy_temp") || fail "cannot read policy config"
fixed_config=$((original_config | config_mask))
write_le32 "$fixed_config" "$config_offset" "$policy_temp" || fail "cannot patch policy config"
verified_config=$(read_le32 "$config_offset" "$policy_temp") || fail "cannot verify policy config"
[ "$verified_config" -eq "$fixed_config" ] ||
    fail "policy config verification failed: expected $fixed_config, got $verified_config"

printf 'policy repair: config 0x%08x -> 0x%08x (verified)\n' "$original_config" "$verified_config"
load_policy "$policy_temp"
