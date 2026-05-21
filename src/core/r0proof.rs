use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::core::simulation::{RealFirstMessage, SimulateRelationProof, RealRelationState, RelationProof};
use crate::core::setup::crs;
use crate::crypto::Ciphertext;

#[allow(non_camel_case_types)]
pub type r0Proof = RelationProof;
#[allow(non_camel_case_types)]
pub type r0State = RealRelationState;

// R^(00)_OARS: w < B and P(opk, M, R) = 0.
pub fn r0Prove1st(crs: &crs) -> (r0Proof, r0State) {
    RealFirstMessage(crs, 0)
}

pub fn r0Simulate(crs: &crs, chall: Scalar, V: &RistrettoPoint, Vprime: &RistrettoPoint, d: &Ciphertext, C_0: &[Ciphertext; 2], C_1: &[Ciphertext; 2]) -> r0Proof {
    SimulateRelationProof(crs, 0, chall, V, Vprime, d, C_0, C_1)
}
