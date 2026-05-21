#![allow(non_snake_case, non_camel_case_types)]

pub mod crypto;
pub mod core;
pub mod bench;

#[cfg(test)]
mod tests {
    use super::core::{CRSGen, MsgStandard, MsgAudit, OKGen, Sign, UKGen, VerifyFull};
    use super::crypto::RandomScalar;
    use super::bench::MakeRandomRing;

    #[test]
    fn all_four_relations_small() {
        let n = 16usize;
        let k = 32usize;
        let b = 16usize;
        let bound = crate::crypto::Powerof2(b);
        let mut rset = MakeRandomRing(n);
        let okey = OKGen();
        let crs = CRSGen(n, b, k, okey.Opk);
        for option in 0..4 {
            let (ell, w, msg) = match option {
                0 => (0usize, 123u128, MsgStandard()),
                1 => (n / 2, 456u128, MsgAudit()),
                2 => (1usize, bound + 789u128, MsgStandard()),
                3 => (n - 1, bound + 111u128, MsgAudit()),
                _ => unreachable!(),
            };
            let ukey = UKGen(&crs, w, RandomScalar());
            rset[ell] = ukey.Upk;
            let sig = Sign(&crs, &crs.Opk, &ukey.Upk, &ukey.Usk, &msg, &rset);
            let report = VerifyFull(&crs, &sig, &rset);
            assert!(report.ok, "option {option} failed: {:?}", report);
        }
    }
}
