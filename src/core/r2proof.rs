use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::core::simulation::{RealFirstMessage, SimulateRelationProof, RealRelationState, RelationProof};
use crate::core::setup::crs;
use crate::crypto::Ciphertext;

#[allow(non_camel_case_types)]
pub type r2Proof = RelationProof;
#[allow(non_camel_case_types)]
pub type r2State = RealRelationState;

// R^(10)_OARS: w >= B and P(opk, M, R) = 0.
pub fn r2Prove1st(crs: &crs) -> (r2Proof, r2State) {
    RealFirstMessage(crs, 2)
}

pub fn r2Simulate(crs: &crs, chall: Scalar, V: &RistrettoPoint, Vprime: &RistrettoPoint, d: &Ciphertext, C_0: &[Ciphertext; 2], C_1: &[Ciphertext; 2]) -> r2Proof {
    SimulateRelationProof(crs, 2, chall, V, Vprime, d, C_0, C_1)
}
