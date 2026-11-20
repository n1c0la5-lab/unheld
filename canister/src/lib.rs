//! An ICP canister that owns a NEAR account through a threshold Ed25519 key
//! and signs NEAR transfers for an AI agent, but only within the owner's
//! policy. No single machine ever holds the key.
//!
//! The NEAR account is the *implicit* account of the canister's public key
//! (`hex(public_key)`): funding it creates it, with that key as its only
//! full-access key.
//!
//! Roles and rules live in [`policy`] as pure code; this file is the IC glue.

pub mod near_tx;
pub mod nep413;
pub mod policy;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use candid::{CandidType, Deserialize, Principal};
use ed25519_dalek::{Signature, VerifyingKey};
use ic_cdk::api::{msg_caller, time};
use ic_cdk_management_canister::{
    schnorr_public_key, sign_with_schnorr, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs,
    SignWithSchnorrArgs,
};
use near_tx::{decode_block_hash, implicit_account_id, validate_account_id, Transfer};
use nep413::Payload;
use policy::{parse_yocto, AuditEntry, Config, Guard, Policy};
use std::cell::RefCell;

/// Every key this canister derives lives under this path. Changing it changes
/// the NEAR account. It keeps the project's former name (near-icp-guard) on
/// purpose: the deployed canister's NEAR account depends on it.
const DERIVATION_PATH: &[u8] = b"near-icp-guard/agent/0";
/// `test_key_1` exists on mainnet (cheaper, for testing) and — per the icp-cli
/// examples — on the local network. Production is `key_1`.
const DEFAULT_KEY_NAME: &str = "test_key_1";

#[derive(CandidType, Deserialize)]
pub struct InitArgs {
    pub key_name: Option<String>,
}

#[derive(CandidType, Deserialize, Clone)]
pub struct Account {
    pub public_key_hex: String,
    /// NEAR's `ed25519:<base58>` notation, as `near-cli` and RPC print it.
    pub public_key_near: String,
    pub account_id: String,
}

#[derive(CandidType, Deserialize)]
pub struct TransferRequest {
    pub receiver_id: String,
    /// Amount in yoctoNEAR as a decimal string (u128 does not fit candid's nat64).
    pub yocto: String,
    /// Access-key nonce + 1. Untrusted: a wrong value only makes NEAR reject the tx.
    pub nonce: u64,
    /// Hash of a recent block, base58 as NEAR RPC prints it. Untrusted too.
    pub block_hash: String,
}

#[derive(CandidType, Deserialize)]
pub struct SignedTransfer {
    /// Borsh `SignedTransaction`, base64 — exactly what RPC `send_tx` takes.
    pub signed_tx_base64: String,
    /// Base58 of the signing hash — NEAR's transaction id.
    pub tx_hash: String,
}

/// A NEP-413 message to sign (fields as in NEP-413's `signMessage`).
#[derive(CandidType, Deserialize)]
pub struct Nep413Request {
    pub message: String,
    /// Exactly 32 bytes.
    pub nonce: Vec<u8>,
    pub recipient: String,
    pub callback_url: Option<String>,
}

/// NEP-413's `SignedMessage`.
#[derive(CandidType, Deserialize)]
pub struct SignedMessage {
    /// The canister's implicit account.
    pub account_id: String,
    /// `ed25519:<base58>`.
    pub public_key: String,
    /// Base64 of the 64-byte Ed25519 signature over
    /// `sha256(u32 2^31+413 || borsh(payload))`, as NEP-413 returns it.
    pub signature: String,
}

struct State {
    guard: Guard,
    key_name: String,
    public_key: Option<[u8; 32]>,
}

/// What survives an upgrade. The public key is not stored: it is cheap to
/// fetch again and derives the same NEAR account.
#[derive(CandidType, Deserialize)]
struct StableState {
    guard: Guard,
    key_name: String,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(s.borrow_mut().as_mut().expect("canister not initialised")))
}

fn key_id() -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: with_state(|s| s.key_name.clone()),
    }
}

fn account_of(pk: &[u8; 32]) -> Account {
    Account {
        public_key_hex: hex::encode(pk),
        public_key_near: format!("ed25519:{}", bs58::encode(pk).into_string()),
        account_id: implicit_account_id(pk),
    }
}

/// The installer becomes the owner. An anonymous installer is refused: the
/// install traps and nothing is installed.
#[ic_cdk::init]
fn init(args: Option<InitArgs>) {
    let guard = Guard::new(msg_caller()).unwrap_or_else(|e| ic_cdk::trap(e.to_string()));
    let key_name = args
        .and_then(|a| a.key_name)
        .unwrap_or_else(|| DEFAULT_KEY_NAME.to_string());
    STATE.with(|s| {
        *s.borrow_mut() = Some(State {
            guard,
            key_name,
            public_key: None,
        })
    });
}

// Owner, pending owner, agent, policy, today's spent total and the audit log
// survive upgrades.
#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    let stable = with_state(|s| StableState {
        guard: s.guard.clone(),
        key_name: s.key_name.clone(),
    });
    ic_cdk::storage::stable_save((stable,)).expect("saving state failed");
}

/// A layout this code does not know (e.g. the spike's) traps, which rolls the
/// upgrade back; reinstall instead.
#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let (stable,): (StableState,) = ic_cdk::storage::stable_restore()
        .unwrap_or_else(|e| ic_cdk::trap(format!("restoring state failed: {e}")));
    STATE.with(|s| {
        *s.borrow_mut() = Some(State {
            guard: stable.guard,
            key_name: stable.key_name,
            public_key: None,
        })
    });
    // A visible marker that an upgrade really ran (`icp canister logs guard`).
    ic_cdk::println!("post_upgrade: state restored");
}

/// Fetches (once) and returns the canister's NEAR account. Update call, because
/// it asks the management canister.
#[ic_cdk::update]
async fn account() -> Result<Account, String> {
    if let Some(pk) = with_state(|s| s.public_key) {
        return Ok(account_of(&pk));
    }
    let res = schnorr_public_key(&SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path: vec![DERIVATION_PATH.to_vec()],
        key_id: key_id(),
    })
    .await
    .map_err(|e| format!("schnorr_public_key failed: {e:?}"))?;
    let pk: [u8; 32] = res
        .public_key
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32-byte ed25519 key, got {} bytes", v.len()))?;
    with_state(|s| s.public_key = Some(pk));
    Ok(account_of(&pk))
}

fn build(req: &TransferRequest, yocto: u128) -> Result<Transfer, String> {
    let pk = with_state(|s| s.public_key).ok_or("call `account` once first")?;
    validate_account_id(&req.receiver_id).map_err(|e| format!("receiver_id invalid: {e:?}"))?;
    let block_hash = decode_block_hash(&req.block_hash)?;
    Ok(Transfer {
        signer_id: implicit_account_id(&pk),
        public_key: pk,
        nonce: req.nonce,
        receiver_id: req.receiver_id.clone(),
        block_hash,
        yocto,
    })
}

/// The exact unsigned bytes `sign_transfer` would sign, as hex. Lets the script
/// compare them with what `@near-js/transactions` builds for the same input.
/// Signs nothing and checks no policy.
#[ic_cdk::query]
fn preview_transfer(req: TransferRequest) -> Result<String, String> {
    let yocto = parse_yocto(&req.yocto).map_err(|e| e.to_string())?;
    Ok(hex::encode(build(&req, yocto)?.encode()))
}

/// Threshold-signs a 32-byte hash and verifies the signature against `pk`
/// before returning it: if ICP signed something other than what NEAR will
/// check (e.g. a pre-hashed variant), this fails with a clear message instead
/// of an opaque "InvalidSignature" later.
async fn threshold_sign(hash: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 64], String> {
    let res = sign_with_schnorr(&SignWithSchnorrArgs {
        message: hash.to_vec(),
        derivation_path: vec![DERIVATION_PATH.to_vec()],
        key_id: key_id(),
        aux: None,
    })
    .await
    .map_err(|e| format!("sign_with_schnorr failed: {e:?}"))?;
    let sig: [u8; 64] = res
        .signature
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 64-byte signature, got {} bytes", v.len()))?;
    let vk = VerifyingKey::from_bytes(pk).map_err(|e| format!("bad key: {e}"))?;
    vk.verify_strict(hash, &Signature::from_bytes(&sig))
        .map_err(|e| format!("threshold signature does not verify over the NEAR hash: {e}"))?;
    Ok(sig)
}

/// Builds, signs and verifies. Only called after the policy admitted the request.
async fn sign(req: &TransferRequest, yocto: u128) -> Result<SignedTransfer, String> {
    let tx = build(req, yocto)?;
    let hash = tx.signing_hash();
    let sig = threshold_sign(&hash, &tx.public_key).await?;

    Ok(SignedTransfer {
        signed_tx_base64: BASE64.encode(tx.encode_signed(&sig)),
        tx_hash: bs58::encode(hash).into_string(),
    })
}

/// Agent only. Checked against the policy before anything is signed.
#[ic_cdk::update]
async fn sign_transfer(req: TransferRequest) -> Result<SignedTransfer, String> {
    let caller = msg_caller();
    let now = time();
    // Check every rule and reserve the amount in one synchronous step, before
    // the await below: requests that run during that await see the reservation.
    let ticket = with_state(|s| s.guard.begin_sign(caller, &req.receiver_id, &req.yocto, now))
        .map_err(|r| r.to_string())?;
    let result = sign(&req, ticket.amount()).await;
    // Keeps the reservation on success, releases it on failure, logs the outcome.
    let logged = match &result {
        Ok(s) => Ok(s.tx_hash.clone()),
        Err(e) => Err(e.clone()),
    };
    with_state(|s| s.guard.finish_sign(ticket, logged));
    result
}

/// Agent only. Signs a NEP-413 message if its recipient is on the owner's
/// NEP-413 allowlist (never for `policy::FORBIDDEN_NEP413_RECIPIENTS`).
/// Every request from owner or agent is logged with recipient, message length
/// and hash, nonce and outcome.
#[ic_cdk::update]
async fn sign_message(req: Nep413Request) -> Result<SignedMessage, String> {
    let caller = msg_caller();
    let now = time();
    let ticket = with_state(|s| {
        s.guard.begin_message(
            caller,
            &req.message,
            &req.nonce,
            &req.recipient,
            req.callback_url.as_deref(),
            now,
        )
    })
    .map_err(|r| r.to_string())?;
    let result = async {
        let pk = with_state(|s| s.public_key).ok_or("call `account` once first")?;
        let hash = Payload {
            message: &req.message,
            nonce: ticket.nonce(),
            recipient: &req.recipient,
            callback_url: req.callback_url.as_deref(),
        }
        .signing_hash();
        let sig = threshold_sign(&hash, &pk).await?;
        let account = account_of(&pk);
        Ok::<_, String>((
            SignedMessage {
                account_id: account.account_id,
                public_key: account.public_key_near,
                signature: BASE64.encode(sig),
            },
            bs58::encode(hash).into_string(),
        ))
    }
    .await;
    let logged = match &result {
        Ok((_, hash)) => Ok(hash.clone()),
        Err(e) => Err(e.clone()),
    };
    with_state(|s| s.guard.finish_message(ticket, logged));
    result.map(|(signed, _)| signed)
}

/// Owner only. `null` removes the agent.
#[ic_cdk::update]
fn set_agent(agent: Option<Principal>) -> Result<(), String> {
    with_state(|s| s.guard.set_agent(msg_caller(), agent)).map_err(|e| e.to_string())
}

/// Owner only. Replaces all three rules and the NEP-413 recipient list at once.
#[ic_cdk::update]
fn set_policy(policy: Policy) -> Result<(), String> {
    with_state(|s| s.guard.set_policy(msg_caller(), &policy)).map_err(|e| e.to_string())
}

/// Owner only. Step 1 of an owner handover: `opt p` proposes `p` (replacing an
/// earlier proposal), `null` withdraws it. Changes nothing else.
#[ic_cdk::update]
fn propose_owner(candidate: Option<Principal>) -> Result<(), String> {
    with_state(|s| s.guard.propose_owner(msg_caller(), candidate, time())).map_err(|e| e.to_string())
}

/// Only the proposed owner. Step 2: the caller becomes the owner, the previous
/// owner loses every right. Agent, policy and spent total stay.
#[ic_cdk::update]
fn accept_owner() -> Result<(), String> {
    with_state(|s| s.guard.accept_owner(msg_caller(), time())).map_err(|e| e.to_string())
}

/// Owner or agent.
#[ic_cdk::query]
fn get_config() -> Result<Config, String> {
    with_state(|s| s.guard.config(msg_caller(), time())).map_err(|e| e.to_string())
}

/// Owner or agent. Oldest first, at most `policy::AUDIT_LOG_CAPACITY` entries.
#[ic_cdk::query]
fn audit_log() -> Result<Vec<AuditEntry>, String> {
    with_state(|s| s.guard.audit_log(msg_caller())).map_err(|e| e.to_string())
}

ic_cdk::export_candid!();

#[cfg(test)]
mod candid_tests {
    /// The checked-in `guard.did` must describe exactly what the Rust code exports.
    #[test]
    fn did_file_matches_code() {
        use candid_parser::utils::{service_equal, CandidSource};
        let code = super::__export_service();
        service_equal(
            CandidSource::Text(&code),
            CandidSource::Text(include_str!("../guard.did")),
        )
        .unwrap_or_else(|e| panic!("guard.did is out of date:\n{e}\n\ngenerated:\n{code}"));
    }
}

#[cfg(test)]
mod upgrade_tests {
    use super::StableState;
    use crate::policy::{DailySpend, Outcome, Refusal};
    use candid::{CandidType, Principal};

    // The stable layout exactly as the version before owner handover writes
    // it (main at 39f12b6; the canister code of the deployed 1f2ccd2 differs
    // from it in one comment only): `Guard` without `pending_owner`,
    // `Outcome` without the handover variants.
    #[derive(CandidType)]
    struct OldRules {
        per_tx_limit: u128,
        daily_limit: u128,
        allowlist: Vec<String>,
        nep413_recipients: Option<Vec<String>>,
    }
    #[derive(CandidType)]
    enum OldOutcome {
        Pending,
        Signed { tx_hash: String },
        MessageSigned { payload_hash: String },
        Rejected { reason: String },
    }
    #[derive(CandidType)]
    struct OldMessageInfo {
        message_bytes: u64,
        message_sha256: String,
        nonce_hex: String,
        callback_url: Option<String>,
    }
    #[derive(CandidType)]
    struct OldEntry {
        seq: u64,
        time_ns: u64,
        caller: Principal,
        receiver_id: String,
        yocto: String,
        outcome: OldOutcome,
        message: Option<OldMessageInfo>,
    }
    #[derive(CandidType)]
    struct OldGuard {
        owner: Principal,
        agent: Option<Principal>,
        rules: OldRules,
        spend: DailySpend,
        log: Vec<OldEntry>,
        next_seq: u64,
        rejected_unauthorized: u64,
    }
    #[derive(CandidType)]
    struct OldStableState {
        guard: OldGuard,
        key_name: String,
    }

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n; 29])
    }

    /// What the deployed version's `pre_upgrade` writes must restore in this
    /// version's `post_upgrade` (same call: a one-element argument tuple),
    /// with no owner proposal and every old entry intact.
    #[test]
    fn state_from_before_owner_handover_restores() {
        let entry = |seq, outcome, message| OldEntry {
            seq,
            time_ns: 100 + seq,
            caller: p(2),
            receiver_id: "alice.testnet".into(),
            yocto: "3".into(),
            outcome,
            message,
        };
        let old = OldStableState {
            guard: OldGuard {
                owner: p(1),
                agent: Some(p(2)),
                rules: OldRules {
                    per_tx_limit: 5,
                    daily_limit: 8,
                    allowlist: vec!["alice.testnet".into()],
                    nep413_recipients: Some(vec!["login.example".into()]),
                },
                spend: DailySpend { day: 20_759, spent: 3 },
                log: vec![
                    entry(0, OldOutcome::Signed { tx_hash: "T".into() }, None),
                    entry(1, OldOutcome::Rejected { reason: "r".into() }, None),
                    entry(2, OldOutcome::Pending, None),
                    entry(
                        3,
                        OldOutcome::MessageSigned { payload_hash: "H".into() },
                        Some(OldMessageInfo {
                            message_bytes: 5,
                            message_sha256: "ab".into(),
                            nonce_hex: "09".into(),
                            callback_url: None,
                        }),
                    ),
                ],
                next_seq: 4,
                rejected_unauthorized: 7,
            },
            key_name: "key_1".into(),
        };
        // Exactly what `stable_save((stable,))` / `stable_restore()` do.
        let bytes = candid::encode_args((old,)).unwrap();
        let (mut new,): (StableState,) = candid::decode_args(&bytes).unwrap();

        assert_eq!(new.key_name, "key_1");
        let g = &mut new.guard;
        let c = g.config(p(1), 20_759 * crate::policy::NANOS_PER_DAY).unwrap();
        assert_eq!((c.owner, c.pending_owner, c.agent), (p(1), None, Some(p(2))));
        assert_eq!((c.policy.per_tx_limit_yocto.as_str(), c.policy.daily_limit_yocto.as_str()), ("5", "8"));
        assert_eq!(c.policy.allowlist, ["alice.testnet"]);
        assert_eq!(c.policy.nep413_recipients, Some(vec!["login.example".to_string()]));
        assert_eq!((c.spent_today_yocto.as_str(), c.rejected_unauthorized), ("3", 7));
        let log = g.audit_log(p(1)).unwrap();
        assert_eq!(log.iter().map(|e| e.seq).collect::<Vec<_>>(), [0, 1, 2, 3]);
        assert_eq!(log[0].outcome, Outcome::Signed { tx_hash: "T".into() });
        assert_eq!(log[1].outcome, Outcome::Rejected { reason: "r".into() });
        assert_eq!(log[2].outcome, Outcome::Pending);
        assert_eq!(log[3].outcome, Outcome::MessageSigned { payload_hash: "H".into() });
        assert_eq!(log[3].message.as_ref().unwrap().message_sha256, "ab");

        // The restored guard takes a handover; the log continues at seq 4.
        assert_eq!(g.accept_owner(p(5), 1), Err(Refusal::NotPendingOwner));
        g.propose_owner(p(1), Some(p(5)), 1).unwrap();
        g.accept_owner(p(5), 2).unwrap();
        let log = g.audit_log(p(5)).unwrap();
        assert_eq!(log.last().map(|e| (e.seq, e.outcome.clone())), Some((5, Outcome::OwnerAccepted { previous_owner: p(1) })));
    }
}
