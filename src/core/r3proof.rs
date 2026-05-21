use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::core::simulation::{RealFirstMessage, SimulateRelationProof, RealRelationState, RelationProof};
use crate::core::setup::crs;
use crate::crypto::Ciphertext;

#[allow(non_camel_case_types)]
pub type r3Proof = RelationProof;
#[allow(non_camel_case_types)]
pub type r3State = RealRelationState;

// R^(11)_OARS: w >= B and P(opk, M, R) = 1.
pub fn r3Prove1st(crs: &crs) -> (r3Proof, r3State) {
    RealFirstMessage(crs, 3)
}

pub fn r3Simulate(crs: &crs, chall: Scalar, V: &RistrettoPoint, Vprime: &RistrettoPoint, d: &Ciphertext, C_0: &[Ciphertext; 2], C_1: &[Ciphertext; 2]) -> r3Proof {
    SimulateRelationProof(crs, 3, chall, V, Vprime, d, C_0, C_1)
}
