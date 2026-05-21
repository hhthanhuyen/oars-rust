use bulletproofs::PedersenGens;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;

// -----------------------------------------------------------------------------
// Low-level Ristretto/Pedersen/ElGamal utilities
// -----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub u: RistrettoPoint,
    pub v: RistrettoPoint,
}

impl Ciphertext {
    pub fn zero() -> Self {
        Self {
            u: RistrettoPoint::default(),
            v: RistrettoPoint::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncKeyPair {
    pub private: Scalar,
    pub public: RistrettoPoint,
}

pub struct ComKey {
    pub pc_gens: PedersenGens,
    pub hs: Vec<RistrettoPoint>,
}

pub fn RandomScalar() -> Scalar {
    let mut rng = OsRng;
    Scalar::random(&mut rng)
}

pub fn ScalarFromU64(x: u64) -> Scalar {
    Scalar::from(x)
}

pub fn ScalarFromU128(x: u128) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&x.to_le_bytes());
    Scalar::from_bytes_mod_order(bytes)
}

pub fn Pow2Scalar(exp: usize) -> Scalar {
    assert!(exp <= 127, "this prototype supports powers up to 2^127");
    ScalarFromU128(1u128 << exp)
}

pub fn Powerof2(k: usize) -> u128 {
    assert!(k < 128, "B=2^b must fit in u128 for this prototype");
    1u128 << k
}

pub fn PointBytes(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

pub fn HashToPoint(label: &[u8]) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(label)
}

pub fn EncKeyGen() -> EncKeyPair {
    let sk = RandomScalar();
    let pk = RISTRETTO_BASEPOINT_POINT * sk;
    EncKeyPair { private: sk, public: pk }
}

pub fn Encrypt(m: &RistrettoPoint, pk: &RistrettoPoint, r: &Scalar) -> Ciphertext {
    Ciphertext {
        u: RISTRETTO_BASEPOINT_POINT * *r,
        v: *m + (*pk * *r),
    }
}

pub fn Decrypt(ct: &Ciphertext, sk: &Scalar) -> RistrettoPoint {
    ct.v - (ct.u * *sk)
}

pub fn CiphertextAdd(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    Ciphertext { u: a.u + b.u, v: a.v + b.v }
}

pub fn CiphertextSub(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    Ciphertext { u: a.u - b.u, v: a.v - b.v }
}

pub fn CiphertextMulScalar(ct: &Ciphertext, s: &Scalar) -> Ciphertext {
    Ciphertext { u: ct.u * *s, v: ct.v * *s }
}

pub fn EncodeToPoint(x: u128) -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT * ScalarFromU128(x)
}

pub fn EncodeScalarToPoint(x: &Scalar) -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT * *x
}

// -----------------------------------------------------------------------------
// Interval discrete-log decoding for Open
// -----------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DecodeBSGSTable {
    pub start: u64,
    pub end: u64,
    pub m: u64,
    pub baby: HashMap<[u8; 32], u64>,
    pub minus_giant_step: RistrettoPoint,
}

fn CeilSqrtU64(n: u64) -> u64 {
    if n <= 1 {
        return n;
    }

    // sqrt(u64::MAX) < 2^32, so this upper bound is enough for all u64 inputs.
    let mut lo = 1u64;
    let mut hi = 1u64 << 32;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if (mid as u128) * (mid as u128) >= n as u128 {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

pub fn BuildDecodeBSGSTableRange(start: u64, end: u64) -> DecodeBSGSTable {
    assert!(start <= end, "invalid BSGS range");

    let n = end - start + 1;
    let m = CeilSqrtU64(n);
    let mut baby = HashMap::with_capacity(m as usize);

    let mut cur = RistrettoPoint::default();
    for j in 0..m {
        baby.insert(PointBytes(&cur), j);
        cur += RISTRETTO_BASEPOINT_POINT;
    }

    DecodeBSGSTable {
        start,
        end,
        m,
        baby,
        minus_giant_step: -(RISTRETTO_BASEPOINT_POINT * ScalarFromU64(m)),
    }
}

pub fn DecodeToIntBSGS(p: &RistrettoPoint, table: &DecodeBSGSTable) -> Option<u64> {
    if PointEqual(p, &RistrettoPoint::default()) {
        return None;
    }

    let n = table.end - table.start + 1;
    let giant_steps = (n + table.m - 1) / table.m;

    // Decode p = wG over w in [start,end].  Equivalently decode
    // p - start*G = xG over x in [0,end-start].
    let mut cur = *p - (RISTRETTO_BASEPOINT_POINT * ScalarFromU64(table.start));
    for i in 0..giant_steps {
        if let Some(j) = table.baby.get(&PointBytes(&cur)) {
            let x = i * table.m + *j;
            if x < n {
                return Some(table.start + x);
            }
        }
        cur += table.minus_giant_step;
    }

    None
}

pub fn ComKeyGen(len: usize) -> ComKey {
    let pc_gens = PedersenGens::default();
    let mut hs = Vec::with_capacity(len.max(1));
    hs.push(pc_gens.B);
    for i in 1..len.max(1) {
        hs.push(HashToPoint(format!("OARS-Ristretto-H-{i}").as_bytes()));
    }
    ComKey { pc_gens, hs }
}

pub fn CommitSingle(ck: &ComKey, msg: Scalar, blind: Scalar) -> RistrettoPoint {
    ck.pc_gens.commit(msg, blind)
}

pub fn CommitSingleInt(ck: &ComKey, msg: u128, blind: Scalar) -> RistrettoPoint {
    CommitSingle(ck, ScalarFromU128(msg), blind)
}

pub fn BatchCommit(ck: &ComKey, msgs: &[Scalar], blind: Scalar) -> RistrettoPoint {
    assert!(msgs.len() <= ck.hs.len());
    let mut out = ck.pc_gens.B_blinding * blind;
    for (m, h) in msgs.iter().zip(ck.hs.iter()) {
        out += *h * *m;
    }
    out
}

pub fn AppendBytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

pub fn AppendPoint(hasher: &mut Sha256, p: &RistrettoPoint) {
    AppendBytes(hasher, &p.compress().to_bytes());
}

pub fn AppendCiphertext(hasher: &mut Sha256, ct: &Ciphertext) {
    AppendPoint(hasher, &ct.u);
    AppendPoint(hasher, &ct.v);
}

pub fn Challenge(hasher: Sha256) -> Scalar {
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order(bytes)
}

pub fn IntToBits(x: usize, length: usize) -> Vec<bool> {
    (0..length).map(|i| ((x >> i) & 1) == 1).collect()
}

pub fn BitsToScalars(bits: &[bool]) -> Vec<Scalar> {
    bits.iter().map(|b| if *b { Scalar::ONE } else { Scalar::ZERO }).collect()
}

pub fn PointEqual(a: &RistrettoPoint, b: &RistrettoPoint) -> bool {
    a.compress().to_bytes() == b.compress().to_bytes()
}

pub fn CiphertextEqual(a: &Ciphertext, b: &Ciphertext) -> bool {
    PointEqual(&a.u, &b.u) && PointEqual(&a.v, &b.v)
}

pub fn NegPoint(p: &RistrettoPoint) -> RistrettoPoint {
    -*p
}


pub fn RandInt(bits: usize) -> u128 {
    assert!(bits <= 127);
    let mut bytes = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    let mut x = u128::from_le_bytes(bytes);
    if bits < 128 {
        let mask = if bits == 128 { u128::MAX } else { (1u128 << bits) - 1 };
        x &= mask;
    }
    x
}

