#!/usr/bin/env bash
# End-to-end test: a CANISTER as the guard's owner, on a LOCAL icp network.
#
#   icp network start -d     # once
#   scripts/e2e-owner-canister.sh
#
# Measures the two-step owner handover with a canister as the new owner: the
# owner proposes the test canister `test-canisters/owner-probe` (test only,
# not part of Unheld), the probe accepts through an inter-canister call and
# then sets the policy the same way. Afterwards the previous owner has no
# rights, and agent and signing still work under the new owner's policy.
#
# Reinstalls the `guard` canister in the local environment (its state is
# wiped) and creates one new probe canister per run, detached from icp.yaml.
# Nothing is sent to NEAR: the one signed transfer uses a fake block hash.
#
# Identities: the owner is your current icp identity (or $OWNER_IDENTITY).
# `e2e-agent` and `e2e-stranger` are created if missing, with plaintext storage
# (local testing only); their seed phrases are discarded, never printed.
set -euo pipefail

cd "$(dirname "$0")/.."
export DO_NOT_TRACK=1

for v in ICP_ENVIRONMENT ICP_ENV ICP_NETWORK; do
  if [[ -n "${!v:-}" && "${!v}" != "local" ]]; then
    echo "refusing: $v=${!v}. This script reinstalls the canister and runs only against the local network" >&2
    exit 2
  fi
  unset "$v"
done
E=(-e local) # every icp call names the environment itself

OWNER="${OWNER_IDENTITY:-$(icp identity default)}"
AGENT=e2e-agent
STRANGER=e2e-stranger
identities=$(icp identity list 2>/dev/null || true)
for id in "$AGENT" "$STRANGER"; do
  if ! grep -Eq "(^|[[:space:]])${id}([[:space:]]|\$)" <<<"$identities"; then
    icp identity new "$id" --storage plaintext --quiet >/dev/null # stdout is the seed: discarded
  fi
done
principal() { icp identity principal --identity "$1"; }
OWNER_P=$(principal "$OWNER")
AGENT_P=$(principal "$AGENT")
STRANGER_P=$(principal "$STRANGER")
[[ "$OWNER_P" != "2vxsx-fae" ]] || { echo "refusing: the owner identity is anonymous" >&2; exit 2; }

# yoctoNEAR as decimal strings (u128 does not fit the shell's integers).
Y_0_1=100000000000000000000000
Y_0_2=200000000000000000000000
Y_0_3=300000000000000000000000
Y_0_5=500000000000000000000000
Y_0_8=800000000000000000000000
FAKE_BLOCK=11111111111111111111111111111111

pass=0
fail=0
ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; echo "$2" | sed 's/^/        /'; fail=$((fail + 1)); }

call() { # identity canister method arg
  icp canister call "$2" "$3" "$4" "${E[@]}" --identity "$1" 2>&1 || true
}
expect_ok() { # label identity canister method arg
  local out; out=$(call "$2" "$3" "$4" "$5")
  if grep -q 'Ok' <<<"$out" && ! grep -q 'Err' <<<"$out"; then ok "$1"; else bad "$1" "$out"; fi
  LAST="$out"
}
expect_err() { # label substring identity canister method arg
  local out; out=$(call "$3" "$4" "$5" "$6")
  if grep -q 'Err' <<<"$out" && grep -qF -- "$2" <<<"$out"; then ok "$1  →  Err: $2"; else bad "$1 (wanted Err containing: $2)" "$out"; fi
}
# icp prints records on one line or several, and fields in its own order:
# compare field by field (`name = value`), without whitespace.
flat() { tr -d ' \n'; }
has() { # label text field...: every field occurs in text
  local label=$1 raw=$2 text f; text=$(flat <<<"$raw"); shift 2
  for f in "$@"; do
    if ! grep -qF -- "$(flat <<<"$f")" <<<"$text"; then bad "$label (missing: $f)" "$raw"; return; fi
  done
  ok "$label"
}
entry_has() { # label audit-log field...: one entry has every field
  local label=$1 raw=$2 e f hit; shift 2
  while IFS= read -r e; do
    hit=1
    for f in "$@"; do
      if ! grep -qF -- "$(flat <<<"$f")" <<<"$e"; then hit=0; break; fi
    done
    if [[ "$hit" == 1 ]]; then ok "$label"; return; fi
  done < <(flat <<<"$raw" | sed 's/record{seq=/\n&/g')
  bad "$label (no entry with: $*)" "$raw"
}
policy() { # per_tx daily receiver
  echo "record { per_tx_limit_yocto = \"$1\"; daily_limit_yocto = \"$2\"; allowlist = vec { \"$3\" }; nep413_recipients = null }"
}
req() { # receiver yocto
  echo "(record { receiver_id = \"$1\"; yocto = \"$2\"; nonce = 1 : nat64; block_hash = \"$FAKE_BLOCK\" })"
}

echo "== build the test canister (test-canisters/owner-probe)"
cargo build --locked --quiet --target wasm32-unknown-unknown --release -p owner-probe
PROBE_WASM=target/owner-probe.wasm
ic-wasm target/wasm32-unknown-unknown/release/owner_probe.wasm -o "$PROBE_WASM" \
  metadata candid:service -f test-canisters/owner-probe/owner-probe.did -v public
echo "  $PROBE_WASM"

echo "== reinstall guard as owner (fresh state), create and install the probe"
icp deploy guard "${E[@]}" --mode reinstall -y --identity "$OWNER" >/dev/null 2>&1 || { echo "deploy failed"; icp deploy guard "${E[@]}" --mode reinstall -y --identity "$OWNER"; exit 1; }
GUARD=$(icp canister status guard "${E[@]}" --identity "$OWNER" --id-only 2>/dev/null || true)
[[ -n "$GUARD" ]] || { echo "cannot find the guard's canister id"; exit 1; }
PROBE=$(icp canister create --detached -q "${E[@]}" --identity "$OWNER")
icp canister install "$PROBE" --wasm "$PROBE_WASM" "${E[@]}" -y --identity "$OWNER" >/dev/null
call "$OWNER" guard account '()' >/dev/null # the guard needs its key once before it signs

echo "owner    $OWNER  $OWNER_P"
echo "agent    $AGENT  $AGENT_P"
echo "stranger $STRANGER  $STRANGER_P"
echo "guard    $GUARD"
echo "probe    $PROBE  (canister; its controller is the owner identity)"
echo

echo "== setup by the owner"
expect_ok  "owner sets the agent" "$OWNER" guard set_agent "(opt principal \"$AGENT_P\")"
expect_ok  "owner sets policy P1 (0.5/tx, 0.8/day, alice.testnet)" "$OWNER" guard set_policy "($(policy $Y_0_5 $Y_0_8 alice.testnet))"

echo "== step 1: propose"
expect_err "probe accepts before any proposal" "only the proposed owner may accept ownership" "$OWNER" "$PROBE" accept_owner "(principal \"$GUARD\")"
expect_err "stranger proposes the probe" "only the owner may do this" "$STRANGER" guard propose_owner "(opt principal \"$PROBE\")"
expect_err "agent proposes itself" "only the owner may do this" "$AGENT" guard propose_owner "(opt principal \"$AGENT_P\")"
expect_err "owner proposes the agent" "the agent cannot become the owner" "$OWNER" guard propose_owner "(opt principal \"$AGENT_P\")"
expect_err "owner proposes anonymous" "anonymous principal cannot be the owner" "$OWNER" guard propose_owner '(opt principal "2vxsx-fae")'
expect_ok  "owner proposes $STRANGER (stands in for a typo)" "$OWNER" guard propose_owner "(opt principal \"$STRANGER_P\")"
expect_ok  "owner replaces the proposal with the probe" "$OWNER" guard propose_owner "(opt principal \"$PROBE\")"
has "get_config: pending_owner = probe, owner unchanged" "$(call "$OWNER" guard get_config '()')" \
  "owner = principal \"$OWNER_P\"" "pending_owner = opt principal \"$PROBE\""
expect_err "replaced candidate ($STRANGER) accepts" "only the proposed owner may accept ownership" "$STRANGER" guard accept_owner '()'
expect_err "owner sets the proposed probe as agent" "is the proposed owner and cannot be the agent" "$OWNER" guard set_agent "(opt principal \"$PROBE\")"
expect_err "probe sets the policy before accepting" "only the owner may do this" "$OWNER" "$PROBE" set_policy "(principal \"$GUARD\", $(policy $Y_0_2 $Y_0_3 bob.testnet))"
expect_err "stranger drives the probe" "only a controller of this probe" "$STRANGER" "$PROBE" accept_owner "(principal \"$GUARD\")"

echo "== step 2: the probe canister accepts (inter-canister call)"
expect_ok  "probe → guard.accept_owner()" "$OWNER" "$PROBE" accept_owner "(principal \"$GUARD\")"
CONFIG=$(call "$AGENT" guard get_config '()')
has "get_config (agent): owner = probe, nothing pending" "$CONFIG" "owner = principal \"$PROBE\"" "pending_owner = null"
has "get_config (agent): agent unchanged" "$CONFIG" "agent = opt principal \"$AGENT_P\""
has "get_config (agent): policy P1 unchanged" "$CONFIG" \
  "per_tx_limit_yocto = \"$Y_0_5\"" "daily_limit_yocto = \"$Y_0_8\"" "allowlist = vec { \"alice.testnet\" }"

echo "== the probe canister sets the policy (inter-canister call)"
expect_ok  "probe → guard.set_policy(P2: 0.2/tx, 0.3/day, bob.testnet)" "$OWNER" "$PROBE" set_policy "(principal \"$GUARD\", $(policy $Y_0_2 $Y_0_3 bob.testnet))"
has "get_config (agent): policy P2" "$(call "$AGENT" guard get_config '()')" \
  "per_tx_limit_yocto = \"$Y_0_2\"" "daily_limit_yocto = \"$Y_0_3\"" "allowlist = vec { \"bob.testnet\" }"

echo "== the previous owner has no rights"
expect_err "old owner sets the policy" "only the owner may do this" "$OWNER" guard set_policy "($(policy $Y_0_5 $Y_0_8 alice.testnet))"
expect_err "old owner replaces the agent" "only the owner may do this" "$OWNER" guard set_agent "(opt principal \"$STRANGER_P\")"
expect_err "old owner removes the agent" "only the owner may do this" "$OWNER" guard set_agent '(null)'
expect_err "old owner proposes itself back" "only the owner may do this" "$OWNER" guard propose_owner "(opt principal \"$OWNER_P\")"
expect_err "old owner accepts" "only the proposed owner may accept ownership" "$OWNER" guard accept_owner '()'
expect_err "old owner reads the config" "only the owner or the agent" "$OWNER" guard get_config '()'
expect_err "old owner reads the audit log" "only the owner or the agent" "$OWNER" guard audit_log '()'
has "policy still P2 after the refusals" "$(call "$AGENT" guard get_config '()')" \
  "per_tx_limit_yocto = \"$Y_0_2\"" "allowlist = vec { \"bob.testnet\" }" "owner = principal \"$PROBE\""

echo "== the agent signs under the new owner's policy"
expect_ok  "agent: 0.1 NEAR to bob.testnet" "$AGENT" guard sign_transfer "$(req bob.testnet $Y_0_1)"
expect_err "agent: 0.1 NEAR to alice.testnet (only on P1)" "not on the allowlist" "$AGENT" guard sign_transfer "$(req alice.testnet $Y_0_1)"
expect_err "agent: 0.3 NEAR to bob.testnet (over P2's 0.2/tx)" "exceeds the per-transaction limit" "$AGENT" guard sign_transfer "$(req bob.testnet $Y_0_3)"

echo "== audit log (read by the agent)"
LOG=$(call "$AGENT" guard audit_log '()')
entry_has "logged: owner proposed $STRANGER" "$LOG" \
  "caller = principal \"$OWNER_P\"" "OwnerProposed = record { candidate = principal \"$STRANGER_P\"" 'receiver_id = ""' 'yocto = ""'
entry_has "logged: owner proposed the probe" "$LOG" \
  "caller = principal \"$OWNER_P\"" "OwnerProposed = record { candidate = principal \"$PROBE\""
entry_has "logged: the probe accepted, previous owner named" "$LOG" \
  "caller = principal \"$PROBE\"" "OwnerAccepted = record { previous_owner = principal \"$OWNER_P\"" 'receiver_id = ""' 'yocto = ""'
entry_has "logged: the agent's signature under P2" "$LOG" \
  "caller = principal \"$AGENT_P\"" 'receiver_id = "bob.testnet"' "Signed = record"
n=$( (grep -o 'seq = ' <<<"$LOG" || true) | wc -l)
# 2 proposals + 1 acceptance + 3 sign requests; refused handover calls are not logged.
[[ "$n" == 6 ]] && ok "audit log has 6 entries (3 handover steps, 3 sign requests)" || bad "audit log has $n entries, want 6" "$LOG"

echo
echo "e2e owner canister: $pass passed, $fail failed"
[[ "$fail" == 0 ]]
