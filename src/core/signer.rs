use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::core::oomproof::{GetIndex, OOMProve, OomProof, OomState};
use crate::core::simulation::{ORProve, OrProof};
use crate::core::setup::{EvaluateCircuitP, crs, usk};
use crate::core::rangeproof::{RangeProve, RangeBundle};
use crate::crypto::*;

// -----------------------------------------------------------------------------
// Signatures and Sign
// -----------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct signature {
    pub msg: Vec<u8>,
    pub v: RistrettoPoint,
    pub vprime: RistrettoPoint,
    pub d: Ciphertext,
    pub c0: [Ciphertext; 2],
    pub c1: [Ciphertext; 2],
    pub oom_proof: OomProof,
    pub range_w: RangeBundle,
    pub range_wprime: RangeBundle,
    pub or_proof: OrProof,
}

pub fn Sign(crs: &crs, opk: &[RistrettoPoint; 2], upk: &RistrettoPoint, usk: &usk, M: &[u8], R: &[RistrettoPoint]) -> signature {
    let b_bound = crs.B;
    let P_result = EvaluateCircuitP(opk, M, R);
    let (wprime, option) = if usk.w < b_bound {
        let wp = (b_bound - 1) - usk.w;
        (wp, if P_result { 1 } else { 0 })
    } else {
        let wp = usk.w - b_bound;
        (wp, if P_result { 3 } else { 2 })
    };

    let r_v = RandomScalar();
    let r_vprime = RandomScalar();
    let v = CommitSingleInt(&crs.comkey, usk.w, r_v);
    let vprime = CommitSingleInt(&crs.comkey, wprime, r_vprime);

    let r_oom = RandomScalar();
    let d = Encrypt(upk, &crs.enckey.public, &r_oom);

    let m0 = match option {
        0 | 1 => RistrettoPoint::default(),
        2 | 3 => EncodeToPoint(usk.w),
        _ => unreachable!(),
    };
    let m1 = match option {
        0 | 2 => RistrettoPoint::default(),
        1 | 3 => *upk,
        _ => unreachable!(),
    };

    let mut r0 = [Scalar::ZERO; 2];
    let mut r1 = [Scalar::ZERO; 2];
    let mut c0 = [Ciphertext::zero(); 2];
    let mut c1 = [Ciphertext::zero(); 2];
    for i in 0..2 {
        r0[i] = RandomScalar();
        r1[i] = RandomScalar();
        c0[i] = Encrypt(&m0, &opk[i], &r0[i]);
        c1[i] = Encrypt(&m1, &opk[i], &r1[i]);
    }

    let oom_state = OomState {
        ell: GetIndex(upk, R),
        w: usk.w,
        v: usk.v,
        r: r_oom,
        upk: *upk,
    };
    let oom_proof = OOMProve(crs, &oom_state, R, &d, M);

    let range_w = RangeProve(crs, usk.w, r_v, &v, b"OARS-Ristretto-range-w");
    let range_wprime = RangeProve(crs, wprime, r_vprime, &vprime, b"OARS-Ristretto-range-wprime");

    let or_proof = ORProve(
        crs,
        option,
        usk,
        wprime,
        r_v,
        r_vprime,
        r_oom,
        &v,
        &vprime,
        &d,
        &c0,
        &c1,
        r0,
        r1,
        M,
        R,
    );

    signature {
        msg: M.to_vec(),
        v,
        vprime,
        d,
        c0,
        c1,
        oom_proof,
        range_w,
        range_wprime,
        or_proof,
    }
}

