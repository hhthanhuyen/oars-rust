use bulletproofs::BulletproofGens;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::crypto::*;

// -----------------------------------------------------------------------------
// CRS and keys
// -----------------------------------------------------------------------------

pub struct crs {
    pub bp_gens: BulletproofGens,
    pub enckey: EncKeyPair,
    pub comkey: ComKey,
    pub Opk: [RistrettoPoint; 2],
    pub m: usize,
    pub b: usize,
    pub k: usize,
    pub rangeBits: usize,
    pub B: u128,
}

const BP_RANGE_BITS: [usize; 4] = [8, 16, 32, 64];

pub fn PaddedRangeBits(K: usize) -> usize {
    assert!((1..=128).contains(&K), "K must be in [1,128]");

    let limbBits = K.min(64);
    BP_RANGE_BITS
        .iter()
        .copied()
        .find(|bits| limbBits <= *bits)
        .expect("BP_RANGE_BITS must contain 64")
}

pub fn CRSGen(n: usize, B: usize, K: usize, opk: [RistrettoPoint; 2]) -> crs {
    assert!(n.is_power_of_two(), "n must be a power of two");
    let limbs = ((K + 63) / 64).max(1);
    let rangeBits = PaddedRangeBits(K);
    crs {
        bp_gens: BulletproofGens::new(rangeBits, limbs),
        enckey: EncKeyGen(),
        comkey: ComKeyGen(2 * n),
        Opk: opk,
        m: n,
        b: B,
        k: K,
        rangeBits,
        B: Powerof2(B),
    }
}

#[derive(Clone, Debug)]
pub struct OKPair {
    pub Osk: Scalar,
    pub Opk: [RistrettoPoint; 2],
}

pub fn OKGen() -> OKPair {
    let tmp0 = EncKeyGen();
    let tmp1 = EncKeyGen();
    OKPair { Osk: tmp0.private, Opk: [tmp0.public, tmp1.public] }
}

#[derive(Clone, Debug)]
pub struct usk {
    pub w: u128,
    pub v: Scalar,
}

#[derive(Clone, Debug)]
pub struct UKPair {
    pub Usk: usk,
    pub Upk: RistrettoPoint,
}

pub fn UKGen(crs: &crs, w: u128, v: Scalar) -> UKPair {
    let upk = CommitSingleInt(&crs.comkey, w, v);
    UKPair { Usk: usk { w, v }, Upk: upk }
}

const MSG_STANDARD_CONTEXT: &[u8] = b"context:standard";
const MSG_AUDIT_CONTEXT: &[u8] = b"context:audit";

// EvaluateCircuitP implements the public Boolean circuit P(opk, M, R).
// In this benchmark circuit, the audit context opens the user public key;
// the ring R is part of the public statement but is not used by this simple P.
pub fn EvaluateCircuitP(_opk: &[RistrettoPoint; 2], M: &[u8], _R: &[RistrettoPoint]) -> bool {
    M == MSG_AUDIT_CONTEXT
}

pub fn MsgStandard() -> Vec<u8> {
    MSG_STANDARD_CONTEXT.to_vec()
}

pub fn MsgAudit() -> Vec<u8> {
    MSG_AUDIT_CONTEXT.to_vec()
}
