//! TEST ONLY, not part of Unheld: the smallest canister that can own the
//! guard. It forwards two owner calls to the guard as inter-canister calls,
//! so the guard sees this canister's principal as the caller. Used by
//! `scripts/e2e-owner-canister.sh` to measure that a canister (not only a
//! person) can accept ownership and then set the policy.
//!
//! Only this canister's controllers may call it; a real owner canister
//! (e.g. a multi-approval wallet) would put its own approval rules here.

use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::{is_controller, msg_caller};
use ic_cdk::call::Call;

/// Same fields as the guard's `Policy`.
#[derive(CandidType, Deserialize)]
pub struct Policy {
    pub per_tx_limit_yocto: String,
    pub daily_limit_yocto: String,
    pub allowlist: Vec<String>,
    pub nep413_recipients: Option<Vec<String>>,
}

fn only_controllers() -> Result<(), String> {
    if is_controller(&msg_caller()) {
        Ok(())
    } else {
        Err("only a controller of this probe may call it".into())
    }
}

/// The guard's answer, or why the call itself failed.
async fn forward(call: Call<'_, '_>) -> Result<(), String> {
    let response = call.await.map_err(|e| format!("call to the guard failed: {e}"))?;
    response
        .candid::<Result<(), String>>()
        .map_err(|e| format!("unexpected answer from the guard: {e}"))?
}

#[ic_cdk::update]
async fn accept_owner(guard: Principal) -> Result<(), String> {
    only_controllers()?;
    forward(Call::unbounded_wait(guard, "accept_owner")).await
}

#[ic_cdk::update]
async fn set_policy(guard: Principal, policy: Policy) -> Result<(), String> {
    only_controllers()?;
    forward(Call::unbounded_wait(guard, "set_policy").with_arg(policy)).await
}

ic_cdk::export_candid!();

#[cfg(test)]
mod tests {
    /// The checked-in `owner-probe.did` must describe what the code exports.
    #[test]
    fn did_file_matches_code() {
        use candid_parser::utils::{service_equal, CandidSource};
        let code = super::__export_service();
        service_equal(
            CandidSource::Text(&code),
            CandidSource::Text(include_str!("../owner-probe.did")),
        )
        .unwrap_or_else(|e| panic!("owner-probe.did is out of date:\n{e}\n\ngenerated:\n{code}"));
    }
}
