use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};

use crate::core::setup::{EvaluateCircuitP, crs, usk};
use crate::crypto::*;
use crate::core::r0proof::{r0Prove1st, r0Simulate};
use crate::core::r1proof::{r1Prove1st, r1Simulate};
use crate::core::r2proof::{r2Prove1st, r2Simulate};
use crate::core::r3proof::{r3Prove1st, r3Simulate};

// -----------------------------------------------------------------------------
// OR proof shared types, simulation and composition
// -----------------------------------------------------------------------------

pub fn IsLowOption(option: usize) -> bool {
    option == 0 || option == 1
}

pub fn C0EncryptsW(option: usize) -> bool {
    option == 2 || option == 3
}

pub fn C1EncryptsUPK(option: usize) -> bool {
    option == 1 || option == 3
}

#[derive(Clone, Debug)]
pub struct RelationProof {
    pub option: usize,
    pub a_V: RistrettoPoint,
    pub a_Vprime: RistrettoPoint,
    pub a: RistrettoPoint,
    pub a_d: Ciphertext,
    pub a_C0: [Ciphertext; 2],
    pub a_C1: [Ciphertext; 2],
    pub z_w: Scalar,
    pub z_vw: Scalar,
    pub z_wprime: Scalar,
    pub z_vwprime: Scalar,
    pub z_a: Scalar,
    pub z_v0: Scalar,
    pub z_ad: Scalar,
    pub z_m0: [Scalar; 2],
    pub z_m1: [Scalar; 2],
    pub chall: Scalar,
}

#[derive(Clone, Debug)]
pub struct RealRelationState {
    pub y_w: Scalar,
    pub v_w: Scalar,
    pub y_wprime: Scalar,
    pub v_wprime: Scalar,
    pub v_a: Scalar,
    pub v0: Scalar,
    pub r_ad: Scalar,
    pub r_m0: [Scalar; 2],
    pub r_m1: [Scalar; 2],
}

#[derive(Clone, Debug)]
pub struct OrProof {
    pub proof0: RelationProof,
    pub proof1: RelationProof,
    pub P_result: bool,
}

pub fn RelationFirstMessage(crs: &crs, option: usize, y_w: Scalar, v_w: Scalar, y_wprime: Scalar, v_wprime: Scalar, v_a: Scalar, v0: Scalar, r_ad: Scalar, r_m0: [Scalar; 2], r_m1: [Scalar; 2]) -> (RelationProof, RealRelationState) {
    let a_V = CommitSingle(&crs.comkey, y_w, v_w);
    let a_Vprime = CommitSingle(&crs.comkey, y_wprime, v_wprime);
    let a = CommitSingle(&crs.comkey, Scalar::ZERO, v_a);
    let com_y = CommitSingle(&crs.comkey, y_w, v0);
    let a_d = Encrypt(&com_y, &crs.enckey.public, &r_ad);

    let mut a_C0 = [Ciphertext::zero(); 2];
    let mut a_C1 = [Ciphertext::zero(); 2];
    let msg_c0 = if C0EncryptsW(option) { EncodeScalarToPoint(&y_w) } else { RistrettoPoint::default() };
    let msg_c1 = if C1EncryptsUPK(option) { com_y } else { RistrettoPoint::default() };
    for i in 0..2 {
        a_C0[i] = Encrypt(&msg_c0, &crs.Opk[i], &r_m0[i]);
        a_C1[i] = Encrypt(&msg_c1, &crs.Opk[i], &r_m1[i]);
    }

    let proof = RelationProof {
        option,
        a_V,
        a_Vprime,
        a,
        a_d,
        a_C0,
        a_C1,
        z_w: Scalar::ZERO,
        z_vw: Scalar::ZERO,
        z_wprime: Scalar::ZERO,
        z_vwprime: Scalar::ZERO,
        z_a: Scalar::ZERO,
        z_v0: Scalar::ZERO,
        z_ad: Scalar::ZERO,
        z_m0: [Scalar::ZERO; 2],
        z_m1: [Scalar::ZERO; 2],
        chall: Scalar::ZERO,
    };
    let state = RealRelationState { y_w, v_w, y_wprime, v_wprime, v_a, v0, r_ad, r_m0, r_m1 };
    (proof, state)
}

pub fn RealFirstMessage(crs: &crs, option: usize) -> (RelationProof, RealRelationState) {
    RelationFirstMessage(
        crs,
        option,
        RandomScalar(),
        RandomScalar(),
        RandomScalar(),
        RandomScalar(),
        RandomScalar(),
        RandomScalar(),
        RandomScalar(),
        [RandomScalar(), RandomScalar()],
        [RandomScalar(), RandomScalar()],
    )
}

pub fn RelationCompleteReal(
    _crs: &crs,
    mut proof: RelationProof,
    state: &RealRelationState,
    chall: Scalar,
    usk: &usk,
    wprime: u128,
    r_v: Scalar,
    r_vprime: Scalar,
    r_oom: Scalar,
    r0: [Scalar; 2],
    r1: [Scalar; 2],
) -> RelationProof {
    let w = ScalarFromU128(usk.w);
    let wp = ScalarFromU128(wprime);
    proof.chall = chall;
    proof.z_w = state.y_w + chall * w;
    proof.z_vw = state.v_w + chall * r_v;
    proof.z_wprime = state.y_wprime + chall * wp;
    proof.z_vwprime = state.v_wprime + chall * r_vprime;
    let rel_blind = if IsLowOption(proof.option) { r_v + r_vprime } else { r_v - r_vprime };
    proof.z_a = state.v_a + chall * rel_blind;
    proof.z_v0 = state.v0 + chall * usk.v;
    proof.z_ad = state.r_ad + chall * r_oom;
    for i in 0..2 {
        proof.z_m0[i] = state.r_m0[i] + chall * r0[i];
        proof.z_m1[i] = state.r_m1[i] + chall * r1[i];
    }
    proof
}

pub fn AppendRelationFirstMessage(h: &mut Sha256, proof: &RelationProof) {
    AppendBytes(h, &[proof.option as u8]);
    AppendPoint(h, &proof.a_V);
    AppendPoint(h, &proof.a_Vprime);
    AppendPoint(h, &proof.a);
    AppendCiphertext(h, &proof.a_d);
    for x in &proof.a_C0 { AppendCiphertext(h, x); }
    for x in &proof.a_C1 { AppendCiphertext(h, x); }
}

pub fn ComputeORChallenge(
    msg: &[u8],
    R: &[RistrettoPoint],
    v: &RistrettoPoint,
    vprime: &RistrettoPoint,
    d: &Ciphertext,
    c0: &[Ciphertext; 2],
    c1: &[Ciphertext; 2],
    p0: &RelationProof,
    p1: &RelationProof,
    P_result: bool,
) -> Scalar {
    let mut h = Sha256::new();
    AppendBytes(&mut h, b"OARS-Ristretto-OR");
    AppendBytes(&mut h, msg);
    AppendBytes(&mut h, &[P_result as u8]);
    for p in R { AppendPoint(&mut h, p); }
    AppendPoint(&mut h, v);
    AppendPoint(&mut h, vprime);
    AppendCiphertext(&mut h, d);
    for x in c0 { AppendCiphertext(&mut h, x); }
    for x in c1 { AppendCiphertext(&mut h, x); }
    AppendRelationFirstMessage(&mut h, p0);
    AppendRelationFirstMessage(&mut h, p1);
    Challenge(h)
}

pub fn RelationVerify(
    crs: &crs,
    proof: &RelationProof,
    v: &RistrettoPoint,
    vprime: &RistrettoPoint,
    d: &Ciphertext,
    c0: &[Ciphertext; 2],
    c1: &[Ciphertext; 2],
) -> bool {
    let lhs1 = proof.a_V + (*v * proof.chall);
    let rhs1 = CommitSingle(&crs.comkey, proof.z_w, proof.z_vw);
    if !PointEqual(&lhs1, &rhs1) { return false; }

    let lhs2 = proof.a_Vprime + (*vprime * proof.chall);
    let rhs2 = CommitSingle(&crs.comkey, proof.z_wprime, proof.z_vwprime);
    if !PointEqual(&lhs2, &rhs2) { return false; }

    let threshold_point = if IsLowOption(proof.option) { *v + *vprime } else { *v - *vprime };
    let target = if IsLowOption(proof.option) { crs.B - 1 } else { crs.B };
    let lhs3 = proof.a + threshold_point * proof.chall;
    let rhs3 = CommitSingle(&crs.comkey, proof.chall * ScalarFromU128(target), proof.z_a);
    if !PointEqual(&lhs3, &rhs3) { return false; }

    let lhs4 = CiphertextAdd(&proof.a_d, &CiphertextMulScalar(d, &proof.chall));
    let com_z = CommitSingle(&crs.comkey, proof.z_w, proof.z_v0);
    let rhs4 = Encrypt(&com_z, &crs.enckey.public, &proof.z_ad);
    if !CiphertextEqual(&lhs4, &rhs4) { return false; }

    let msg_c0 = if C0EncryptsW(proof.option) { EncodeScalarToPoint(&proof.z_w) } else { RistrettoPoint::default() };
    let msg_c1 = if C1EncryptsUPK(proof.option) { com_z } else { RistrettoPoint::default() };
    for i in 0..2 {
        let lhs5 = CiphertextAdd(&proof.a_C0[i], &CiphertextMulScalar(&c0[i], &proof.chall));
        let rhs5 = Encrypt(&msg_c0, &crs.Opk[i], &proof.z_m0[i]);
        if !CiphertextEqual(&lhs5, &rhs5) { return false; }

        let lhs6 = CiphertextAdd(&proof.a_C1[i], &CiphertextMulScalar(&c1[i], &proof.chall));
        let rhs6 = Encrypt(&msg_c1, &crs.Opk[i], &proof.z_m1[i]);
        if !CiphertextEqual(&lhs6, &rhs6) { return false; }
    }
    true
}

pub fn SimulateRelationProof(
    crs: &crs,
    option: usize,
    chall: Scalar,
    v: &RistrettoPoint,
    vprime: &RistrettoPoint,
    d: &Ciphertext,
    c0: &[Ciphertext; 2],
    c1: &[Ciphertext; 2],
) -> RelationProof {
    let z_w = RandomScalar();
    let z_vw = RandomScalar();
    let z_wprime = RandomScalar();
    let z_vwprime = RandomScalar();
    let z_a = RandomScalar();
    let z_v0 = RandomScalar();
    let z_ad = RandomScalar();
    let z_m0 = [RandomScalar(), RandomScalar()];
    let z_m1 = [RandomScalar(), RandomScalar()];

    let a_V = CommitSingle(&crs.comkey, z_w, z_vw) - (*v * chall);
    let a_Vprime = CommitSingle(&crs.comkey, z_wprime, z_vwprime) - (*vprime * chall);
    let threshold_point = if IsLowOption(option) { *v + *vprime } else { *v - *vprime };
    let target = if IsLowOption(option) {
        ScalarFromU128(crs.B - 1)
    } else {
        ScalarFromU128(crs.B)
    };
    let a = CommitSingle(&crs.comkey, chall * target, z_a) - (threshold_point * chall);

    let com_z = CommitSingle(&crs.comkey, z_w, z_v0);
    let a_d = CiphertextSub(&Encrypt(&com_z, &crs.enckey.public, &z_ad), &CiphertextMulScalar(d, &chall));

    let mut a_C0 = [Ciphertext::zero(); 2];
    let mut a_C1 = [Ciphertext::zero(); 2];
    let msg_c0 = if C0EncryptsW(option) { EncodeScalarToPoint(&z_w) } else { RistrettoPoint::default() };
    let msg_c1 = if C1EncryptsUPK(option) { com_z } else { RistrettoPoint::default() };
    for i in 0..2 {
        a_C0[i] = CiphertextSub(&Encrypt(&msg_c0, &crs.Opk[i], &z_m0[i]), &CiphertextMulScalar(&c0[i], &chall));
        a_C1[i] = CiphertextSub(&Encrypt(&msg_c1, &crs.Opk[i], &z_m1[i]), &CiphertextMulScalar(&c1[i], &chall));
    }

    RelationProof {
        option,
        a_V,
        a_Vprime,
        a,
        a_d,
        a_C0,
        a_C1,
        z_w,
        z_vw,
        z_wprime,
        z_vwprime,
        z_a,
        z_v0,
        z_ad,
        z_m0,
        z_m1,
        chall,
    }
}

fn Prove1stByOption(crs: &crs, option: usize) -> (RelationProof, RealRelationState) {
    match option {
        0 => r0Prove1st(crs),
        1 => r1Prove1st(crs),
        2 => r2Prove1st(crs),
        3 => r3Prove1st(crs),
        _ => panic!("invalid option"),
    }
}

fn SimulateByOption(
    crs: &crs,
    option: usize,
    chall: Scalar,
    V: &RistrettoPoint,
    Vprime: &RistrettoPoint,
    d: &Ciphertext,
    C_0: &[Ciphertext; 2],
    C_1: &[Ciphertext; 2],
) -> RelationProof {
    match option {
        0 => r0Simulate(crs, chall, V, Vprime, d, C_0, C_1),
        1 => r1Simulate(crs, chall, V, Vprime, d, C_0, C_1),
        2 => r2Simulate(crs, chall, V, Vprime, d, C_0, C_1),
        3 => r3Simulate(crs, chall, V, Vprime, d, C_0, C_1),
        _ => panic!("invalid option"),
    }
}

pub fn ORProve(
    crs: &crs,
    option: usize,
    usk: &usk,
    wprime: u128,
    r_v: Scalar,
    r_vprime: Scalar,
    r_oom: Scalar,
    v: &RistrettoPoint,
    vprime: &RistrettoPoint,
    d: &Ciphertext,
    c0: &[Ciphertext; 2],
    c1: &[Ciphertext; 2],
    r0: [Scalar; 2],
    r1: [Scalar; 2],
    msg: &[u8],
    R: &[RistrettoPoint],
) -> OrProof {
    let P_result = EvaluateCircuitP(&crs.Opk, msg, R);
    let (proof0_option, proof1_option, real_is_proof0) = if !P_result {
        // P(opk, M, R) = 0: prove R00 OR R10.
        (0usize, 2usize, option == 0)
    } else {
        // P(opk, M, R) = 1: prove R01 OR R11.
        (1usize, 3usize, option == 1)
    };
    let sim_chall = RandomScalar();

    let real_option = if real_is_proof0 { proof0_option } else { proof1_option };
    let sim_option = if real_is_proof0 { proof1_option } else { proof0_option };

    let (real_first, real_state) = Prove1stByOption(crs, real_option);
    let sim_proof = SimulateByOption(crs, sim_option, sim_chall, v, vprime, d, c0, c1);

    let (mut p0, mut p1) = if real_is_proof0 {
        (real_first, sim_proof)
    } else {
        (sim_proof, real_first)
    };

    let total_chall = ComputeORChallenge(msg, R, v, vprime, d, c0, c1, &p0, &p1, P_result);
    let real_chall = total_chall - sim_chall;

    if real_is_proof0 {
        p0 = RelationCompleteReal(crs, p0, &real_state, real_chall, usk, wprime, r_v, r_vprime, r_oom, r0, r1);
    } else {
        p1 = RelationCompleteReal(crs, p1, &real_state, real_chall, usk, wprime, r_v, r_vprime, r_oom, r0, r1);
    }
    OrProof { proof0: p0, proof1: p1, P_result }
}
