use curve25519_dalek::ristretto::RistrettoPoint;
use crate::core::oomproof::OOMVerify;
use crate::core::rangeproof::RangeVerify;
use crate::core::setup::{EvaluateCircuitP, crs};
use crate::core::signer::signature;
use crate::core::simulation::{ComputeORChallenge, RelationVerify};

// -----------------------------------------------------------------------------
// Verify
// -----------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct verifyReport {
    pub challenge: bool,
    pub oom: bool,
    pub range1: bool,
    pub range2: bool,
    pub proof0: bool,
    pub proof1: bool,
    pub ok: bool,
}

pub fn VerifyFull(crs: &crs, sig: &signature, R: &[RistrettoPoint]) -> verifyReport {
    let P_result = EvaluateCircuitP(&crs.Opk, &sig.msg, R);

    let expected_options = if !P_result { (0usize, 2usize) } else { (1usize, 3usize) };
    let option_ok = sig.or_proof.P_result == P_result && sig.or_proof.proof0.option == expected_options.0 && sig.or_proof.proof1.option == expected_options.1;

    let total_chall = ComputeORChallenge(
        &sig.msg,
        R,
        &sig.v,
        &sig.vprime,
        &sig.d,
        &sig.c0,
        &sig.c1,
        &sig.or_proof.proof0,
        &sig.or_proof.proof1,
        P_result,
    );
    let challenge = option_ok && (sig.or_proof.proof0.chall + sig.or_proof.proof1.chall == total_chall);

    let oom = OOMVerify(crs, &sig.oom_proof, R, &sig.d, &sig.msg);
    let range1 = RangeVerify(crs, &sig.range_w, &sig.v, b"OARS-Ristretto-range-w");
    let range2 = RangeVerify(crs, &sig.range_wprime, &sig.vprime, b"OARS-Ristretto-range-wprime");
    let proof0 = RelationVerify(crs, &sig.or_proof.proof0, &sig.v, &sig.vprime, &sig.d, &sig.c0, &sig.c1);
    let proof1 = RelationVerify(crs, &sig.or_proof.proof1, &sig.v, &sig.vprime, &sig.d, &sig.c0, &sig.c1);
    let ok = challenge && oom && range1 && range2 && proof0 && proof1;
    verifyReport { challenge, oom, range1, range2, proof0, proof1, ok }
}

pub fn Verify(crs: &crs, sig: &signature, R: &[RistrettoPoint]) -> bool {
    VerifyFull(crs, sig, R).ok
}


pub fn SignatureSize(sig: &signature) -> usize {
    // Actual byte-oriented estimate with compressed Ristretto points and serialized Bulletproofs.
    let point = 32usize;
    let scalar = 32usize;
    let ct = 2 * point;
    let mut total = 0usize;
    total += 2 * point; // V, Vprime
    total += ct; // d
    total += 4 * ct; // C0,C1
    total += ct + 4 * point + 7 * scalar; // OOM fixed
    total += sig.oom_proof.gs.len() * ct + sig.oom_proof.fs.len() * scalar;
    total += sig.range_w.proof.to_bytes().len() + sig.range_w.commitments.len() * point;
    total += sig.range_wprime.proof.to_bytes().len() + sig.range_wprime.commitments.len() * point;
    // OR proof: two relation proofs. Count all first messages and scalar responses.
    total += 2 * (3 * point + ct + 4 * ct + 11 * scalar);
    total
}

