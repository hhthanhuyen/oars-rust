use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};

use crate::core::setup::crs;
use crate::crypto::*;

// -----------------------------------------------------------------------------
// OOM proof
// -----------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct OomProof {
    pub ct_a: Ciphertext,
    pub a: RistrettoPoint,
    pub b: RistrettoPoint,
    pub c: RistrettoPoint,
    pub d: RistrettoPoint,
    pub z_v0: Scalar,
    pub z_w0: Scalar,
    pub z_ra: Scalar,
    pub z_a: Scalar,
    pub z_d: Scalar,
    pub z: Scalar,
    pub gs: Vec<Ciphertext>,
    pub fs: Vec<Scalar>,
    pub chall: Scalar,
}

#[derive(Clone, Debug)]
pub struct OomState {
    pub ell: usize,
    pub w: u128,
    pub v: Scalar,
    pub r: Scalar,
    pub upk: RistrettoPoint,
}

pub fn GetIndex(p: &RistrettoPoint, list: &[RistrettoPoint]) -> usize {
    let target = p.compress().to_bytes();
    list.iter()
        .position(|x| x.compress().to_bytes() == target)
        .expect("point not found in list")
}

pub fn OOMChallenge(m: &[u8], rset: &[RistrettoPoint], d: &Ciphertext, a: &Ciphertext, ca: &RistrettoPoint, cb: &RistrettoPoint, cc: &RistrettoPoint, cd: &RistrettoPoint, gs: &[Ciphertext]) -> Scalar {
    let mut h = Sha256::new();
    AppendBytes(&mut h, b"OARS-Ristretto-OOM");
    AppendBytes(&mut h, m);
    for p in rset { AppendPoint(&mut h, p); }
    AppendCiphertext(&mut h, d);
    AppendCiphertext(&mut h, a);
    AppendPoint(&mut h, ca);
    AppendPoint(&mut h, cb);
    AppendPoint(&mut h, cc);
    AppendPoint(&mut h, cd);
    for g in gs { AppendCiphertext(&mut h, g); }
    Challenge(h)
}

pub fn OOMProve(crs: &crs, st: &OomState, rset: &[RistrettoPoint], d: &Ciphertext, msg: &[u8]) -> OomProof {
    let n = rset.len();
    let m = n.trailing_zeros() as usize;
    let w_s = ScalarFromU128(st.w);
    let recomputed_upk = CommitSingle(&crs.comkey, w_s, st.v);
    assert!(PointEqual(&recomputed_upk, &st.upk));
    assert!(PointEqual(&rset[st.ell], &st.upk));

    let v0 = RandomScalar();
    let w0 = RandomScalar();
    let r_a = RandomScalar();
    let com0 = CommitSingle(&crs.comkey, w0, v0);
    let ct_a = Encrypt(&com0, &crs.enckey.public, &r_a);

    // ct[ell] encrypts zero.
    let mut ct = Vec::with_capacity(n);
    for rk in rset {
        let enc_neg = Encrypt(&NegPoint(rk), &crs.enckey.public, &Scalar::ZERO);
        ct.push(CiphertextAdd(d, &enc_neg));
    }

    let mut b_bits = vec![false; 2 * m];
    let ell_bits = IntToBits(st.ell, m);
    for i in 0..m {
        for j in 0..2 {
            if (ell_bits[i] && j == 1) || (!ell_bits[i] && j == 0) {
                b_bits[2 * i + j] = true;
            }
        }
    }
    let b_arr = BitsToScalars(&b_bits);
    let r_b = RandomScalar();
    let com_b = BatchCommit(&crs.comkey, &b_arr, r_b);

    let mut a_arr = vec![Scalar::ZERO; 2 * m];
    for i in 0..m {
        let ai = RandomScalar();
        a_arr[2 * i + 1] = ai;
        a_arr[2 * i] = -ai;
    }
    let r_a_com = RandomScalar();
    let com_a = BatchCommit(&crs.comkey, &a_arr, r_a_com);

    let mut c_arr = vec![Scalar::ZERO; 2 * m];
    for i in 0..m {
        for j in 0..2 {
            let factor = Scalar::ONE - Scalar::from(2u64) * b_arr[2 * i + j];
            c_arr[2 * i + j] = a_arr[2 * i + j] * factor;
        }
    }
    let r_c = RandomScalar();
    let com_c = BatchCommit(&crs.comkey, &c_arr, r_c);

    let mut d_arr = vec![Scalar::ZERO; 2 * m];
    for i in 0..m {
        for j in 0..2 {
            d_arr[2 * i + j] = -(a_arr[2 * i + j] * a_arr[2 * i + j]);
        }
    }
    let r_d_com = RandomScalar();
    let com_d = BatchCommit(&crs.comkey, &d_arr, r_d_com);

    let mut p_arr = vec![Scalar::ZERO; n * m];
    for k in 0..n {
        let k_bits = IntToBits(k, m);
        let mut coeffs = vec![Scalar::ONE];
        for i in 0..m {
            let aij = if k_bits[i] { a_arr[2 * i + 1] } else { a_arr[2 * i] };
            if ell_bits[i] != k_bits[i] {
                for c in coeffs.iter_mut() {
                    *c *= aij;
                }
            } else {
                let l = coeffs.len();
                let mut new_coeffs = vec![Scalar::ZERO; l + 1];
                new_coeffs[0] = coeffs[0] * aij;
                for ci in 1..l {
                    new_coeffs[ci] = coeffs[ci] * aij + coeffs[ci - 1];
                }
                new_coeffs[l] = coeffs[l - 1];
                coeffs = new_coeffs;
            }
        }
        for i in 0..m {
            p_arr[k * m + i] = coeffs.get(i).copied().unwrap_or(Scalar::ZERO);
        }
    }

    let mut g_arr = vec![Ciphertext::zero(); m];
    let mut rho_arr = vec![Scalar::ZERO; m];
    for i in 0..m {
        rho_arr[i] = RandomScalar();
        g_arr[i] = Encrypt(&RistrettoPoint::default(), &crs.enckey.public, &rho_arr[i]);
        for k in 0..n {
            let coeff = p_arr[k * m + i];
            if coeff != Scalar::ZERO {
                g_arr[i] = CiphertextAdd(&g_arr[i], &CiphertextMulScalar(&ct[k], &coeff));
            }
        }
    }

    let chall = OOMChallenge(msg, rset, d, &ct_a, &com_a, &com_b, &com_c, &com_d, &g_arr);

    let z_v0 = v0 + chall * st.v;
    let z_w0 = w0 + chall * w_s;
    let z_ra = r_a + chall * st.r;

    let mut fs = vec![Scalar::ZERO; 2 * m];
    for i in 0..m {
        for j in 0..2 {
            fs[2 * i + j] = a_arr[2 * i + j] + chall * b_arr[2 * i + j];
        }
    }

    let z_a = r_a_com + chall * r_b;
    let z_d = r_d_com + chall * r_c;

    let mut cexp = chall;
    let mut chall_pow_m = Scalar::ONE;
    for _ in 0..m { chall_pow_m *= chall; }
    let mut sum = rho_arr[0];
    for j in 1..m {
        if j == 1 {
            cexp = chall;
        } else {
            cexp *= chall;
        }
        sum += cexp * rho_arr[j];
    }
    let z = chall_pow_m * st.r - sum;

    OomProof {
        ct_a,
        a: com_a,
        b: com_b,
        c: com_c,
        d: com_d,
        z_v0,
        z_w0,
        z_ra,
        z_a,
        z_d,
        z,
        gs: g_arr,
        fs,
        chall,
    }
}

pub fn OOMVerify(crs: &crs, proof: &OomProof, rset: &[RistrettoPoint], d: &Ciphertext, msg: &[u8]) -> bool {
    let chall = OOMChallenge(msg, rset, d, &proof.ct_a, &proof.a, &proof.b, &proof.c, &proof.d, &proof.gs);
    if chall != proof.chall { return false; }
    let n = rset.len();
    let m = n.trailing_zeros() as usize;
    if proof.fs.len() != 2 * m || proof.gs.len() != m { return false; }

    let mut ct = Vec::with_capacity(n);
    for rk in rset {
        let enc_neg = Encrypt(&NegPoint(rk), &crs.enckey.public, &Scalar::ZERO);
        ct.push(CiphertextAdd(d, &enc_neg));
    }

    let lhs1 = CiphertextAdd(&CiphertextMulScalar(d, &chall), &proof.ct_a);
    let rhs1_msg = CommitSingle(&crs.comkey, proof.z_w0, proof.z_v0);
    let rhs1 = Encrypt(&rhs1_msg, &crs.enckey.public, &proof.z_ra);
    if !CiphertextEqual(&lhs1, &rhs1) { return false; }

    for i in 0..m {
        if proof.fs[2 * i] + proof.fs[2 * i + 1] != chall { return false; }
    }

    let lhs3 = proof.a + proof.b * chall;
    let rhs3 = BatchCommit(&crs.comkey, &proof.fs, proof.z_a);
    if !PointEqual(&lhs3, &rhs3) { return false; }

    let lhs4 = proof.d + proof.c * chall;
    let tmp_rhs: Vec<Scalar> = proof.fs.iter().map(|f| (chall - *f) * *f).collect();
    let rhs4 = BatchCommit(&crs.comkey, &tmp_rhs, proof.z_d);
    if !PointEqual(&lhs4, &rhs4) { return false; }

    let lhs5 = Encrypt(&RistrettoPoint::default(), &crs.enckey.public, &proof.z);
    let mut rhs5 = CiphertextMulScalar(&proof.gs[0], &(-Scalar::ONE));
    let mut cexp = -Scalar::ONE;
    for i in 1..m {
        cexp *= chall;
        rhs5 = CiphertextAdd(&rhs5, &CiphertextMulScalar(&proof.gs[i], &cexp));
    }
    for k in 0..n {
        let k_bits = IntToBits(k, m);
        let mut prod = Scalar::ONE;
        for i in 0..m {
            prod *= if k_bits[i] { proof.fs[2 * i + 1] } else { proof.fs[2 * i] };
        }
        rhs5 = CiphertextAdd(&rhs5, &CiphertextMulScalar(&ct[k], &prod));
    }
    CiphertextEqual(&lhs5, &rhs5)
}

