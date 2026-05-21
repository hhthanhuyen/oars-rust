use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::core::setup::crs;
use crate::core::signer::signature;
use crate::crypto::*;

// -----------------------------------------------------------------------------
// Open
// -----------------------------------------------------------------------------

pub fn OpenWitness(osk: &Scalar, sig: &signature, table: &DecodeBSGSTable) -> Option<u64> {
    let m0 = Decrypt(&sig.c0[0], osk);
    if PointEqual(&m0, &RistrettoPoint::default()) {
        None
    } else {
        DecodeToIntBSGS(&m0, table)
    }
}

pub fn OpenUserKey(osk: &Scalar, sig: &signature) -> Option<RistrettoPoint> {
    let m1 = Decrypt(&sig.c1[0], osk);
    if PointEqual(&m1, &RistrettoPoint::default()) {
        None
    } else {
        Some(m1)
    }
}

pub fn Open(_crs: &crs, osk: &Scalar, sig: &signature, table: &DecodeBSGSTable) -> (Option<u64>, Option<RistrettoPoint>) {
    let witness = OpenWitness(osk, sig, table);
    let user_key = OpenUserKey(osk, sig);
    (witness, user_key)
}
