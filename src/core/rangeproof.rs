use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::Scalar;
use merlin::Transcript;

use crate::core::setup::crs;
use crate::crypto::*;

// -----------------------------------------------------------------------------
// Bulletproof range proof with u128 limb support and binding to external V
// -----------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct RangeBundle {
    pub k: usize,
    pub rangeBits: usize,
    pub commitments: Vec<CompressedRistretto>,
    pub proof: RangeProof,
}

pub fn Decompose(x: u128, limbs: usize) -> Vec<u64> {
    (0..limbs)
        .map(|i| ((x >> (64 * i)) & ((1u128 << 64) - 1)) as u64)
        .collect()
}

pub fn RangeProve(crs: &crs, x: u128, total_blind: Scalar, public_v: &RistrettoPoint, label: &'static [u8]) -> RangeBundle {
    let limbs = ((crs.k + 63) / 64).max(1);
    let rangeBits = crs.rangeBits;
    let values = Decompose(x, limbs);

    let mut blindings = vec![Scalar::ZERO; limbs];
    for i in 1..limbs {
        blindings[i] = RandomScalar();
    }
    let mut acc = Scalar::ZERO;
    for i in 1..limbs {
        acc += Pow2Scalar(64 * i) * blindings[i];
    }
    blindings[0] = total_blind - acc;

    let mut transcript = Transcript::new(label);
    let (proof, commitments) = RangeProof::prove_multiple(
        &crs.bp_gens,
        &crs.comkey.pc_gens,
        &mut transcript,
        &values,
        &blindings,
        rangeBits,
    )
    .expect("range proof generation failed");

    // Internal sanity check: sum_i 2^(64i) C_i must equal the external OARS commitment V.
    let recomposed = RecomposeCommitments(&commitments);
    assert!(PointEqual(&recomposed, public_v), "range-proof limb commitment does not bind to V");

    RangeBundle { k: crs.k, rangeBits, commitments, proof }
}

pub fn RecomposeCommitments(commitments: &[CompressedRistretto]) -> RistrettoPoint {
    let mut acc = RistrettoPoint::default();
    for (i, c) in commitments.iter().enumerate() {
        let p = c.decompress().expect("invalid limb commitment");
        acc += p * Pow2Scalar(64 * i);
    }
    acc
}

pub fn RangeVerify(crs: &crs, bundle: &RangeBundle, public_v: &RistrettoPoint, label: &'static [u8]) -> bool {
    if bundle.k != crs.k || bundle.rangeBits != crs.rangeBits {
        return false;
    }
    let recomposed = RecomposeCommitments(&bundle.commitments);
    if !PointEqual(&recomposed, public_v) {
        return false;
    }
    let mut transcript = Transcript::new(label);
    bundle
        .proof
        .verify_multiple(
            &crs.bp_gens,
            &crs.comkey.pc_gens,
            &mut transcript,
            &bundle.commitments,
            bundle.rangeBits,
        )
        .is_ok()
}

