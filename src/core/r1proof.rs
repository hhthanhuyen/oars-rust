use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::core::simulation::{RealFirstMessage, SimulateRelationProof, RealRelationState, RelationProof};
use crate::core::setup::crs;
use crate::crypto::Ciphertext;

#[allow(non_camel_case_types)]
pub type r1Proof = RelationProof;
#[allow(non_camel_case_types)]
pub type r1State = RealRelationState;

// R^(01)_OARS: w < B and P(opk, M, R) = 1.
pub fn r1Prove1st(crs: &crs) -> (r1Proof, r1State) {
    RealFirstMessage(crs, 1)
}

pub fn r1Simulate(crs: &crs, chall: Scalar, V: &RistrettoPoint, Vprime: &RistrettoPoint, d: &Ciphertext, C_0: &[Ciphertext; 2], C_1: &[Ciphertext; 2]) -> r1Proof {
    SimulateRelationProof(crs, 1, chall, V, Vprime, d, C_0, C_1)
}
