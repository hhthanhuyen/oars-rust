use curve25519_dalek::ristretto::RistrettoPoint;
use std::time::Instant;

use crate::core::{CRSGen, EvaluateCircuitP, MsgStandard, MsgAudit, OKGen, Open, OpenUserKey, OpenWitness, Sign, SignatureSize, UKGen, Verify};
use crate::crypto::{BuildDecodeBSGSTableRange, HashToPoint, PointEqual, Powerof2, RandomScalar, RandInt};

fn RandIntBelow(bound: u128) -> u128 {
    if bound == 0 { return 0; }
    RandInt(64) % bound
}

pub fn MakeRandomRing(n: usize) -> Vec<RistrettoPoint> {
    (0..n)
        .map(|i| HashToPoint(format!("OARS-ring-random-{i}-{}", RandInt(64)).as_bytes()))
        .collect()
}

const BENCHMARK_PARAMS: &[(usize, usize, usize)] = &[
    (16, 32, 16),
    (64, 32, 16),
    (128, 32, 16),
    (256, 40, 20),
    (512, 40, 20),
    (1024, 40, 20),
];

const OPEN_UPK_OPTION: usize = 1;
const OPEN_W_OPTION: usize = 2;

fn BenchmarkCase(option: usize, n: usize, k: usize, logB: usize) -> (usize, u128, Vec<u8>) {
    let B = Powerof2(logB);
    let maxWitness = Powerof2(k);

    match option {
        0 => (0usize, RandIntBelow(B), MsgStandard()),
        1 => (n / 2, RandIntBelow(B), MsgAudit()),
        2 => (1usize, B + RandIntBelow(maxWitness - B), MsgStandard()),
        3 => (n - 1, B + RandIntBelow(maxWitness - B), MsgAudit()),
        _ => unreachable!(),
    }
}

fn BuildOpeningTable(k: usize, logB: usize) -> crate::crypto::DecodeBSGSTable {
    let tableStart = Powerof2(logB) as u64;
    let tableEnd = (Powerof2(k) - 1) as u64;
    BuildDecodeBSGSTableRange(tableStart, tableEnd)
}

fn ShortPoint(p: &RistrettoPoint) -> String {
    let bytes = p.compress().to_bytes();
    bytes[..5].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}

fn OpenWitnessLabel(w: Option<u64>) -> String {
    match w {
        Some(x) => x.to_string(),
        None => "-".to_string(),
    }
}

fn OpenUserKeyLabel(upk: &Option<RistrettoPoint>) -> String {
    match upk {
        Some(p) => ShortPoint(p),
        None => "-".to_string(),
    }
}

fn OpenUserKeyMatches(opened: &Option<RistrettoPoint>, expected: &Option<RistrettoPoint>) -> bool {
    match (opened, expected) {
        (None, None) => true,
        (Some(a), Some(b)) => PointEqual(a, b),
        _ => false,
    }
}

pub fn TestFunctions() {
    println!("==Test functions==");
    for &(n, k, logB) in BENCHMARK_PARAMS {
        let okey = OKGen();
        let crs = CRSGen(n, logB, k, okey.Opk);
        let lookup = BuildOpeningTable(k, logB);

        for option in 0..4 {
            let mut R = MakeRandomRing(n);
            let (ell, w, M) = BenchmarkCase(option, n, k, logB);
            let ukey = UKGen(&crs, w, RandomScalar());
            R[ell] = ukey.Upk;

            let signature = Sign(&crs, &crs.Opk, &ukey.Upk, &ukey.Usk, &M, &R);
            let ok = Verify(&crs, &signature, &R);

            let (openedW, openedUpk) = Open(&crs, &okey.Osk, &signature, &lookup);
            let expectedW = if w >= crs.B { Some(w as u64) } else { None };
            let expectedUpk = if EvaluateCircuitP(&crs.Opk, &M, &R) { Some(ukey.Upk) } else { None };
            let wOK = openedW == expectedW;
            let upkOK = OpenUserKeyMatches(&openedUpk, &expectedUpk);

            println!(
                "Option-{option} | Params-({n},{k},{logB}) | verify={ok} | openW={} expectedW={} match={} | openUpk={} expectedUpk={} match={}",
                OpenWitnessLabel(openedW),
                OpenWitnessLabel(expectedW),
                wOK,
                OpenUserKeyLabel(&openedUpk),
                OpenUserKeyLabel(&expectedUpk),
                upkOK,
            );
        }
    }
}

pub fn Benchmark(iter: usize) {
    println!("\n==Benchmark ({iter} iterations each)==");
    println!(
        "{:<18} | {:<15} | {:<15} | {:<15} | {:<15} | {:<15}",
        "Params-(n,k,b)",
        "Sign (ms)",
        "Verify (ms)",
        "Open upk (ms)",
        "Open w (ms)",
        "Size (bytes)"
    );
    println!("{}", "-".repeat(113));

    for &(n, k, logB) in BENCHMARK_PARAMS {
        // Opening decodes traceable witnesses by baby-step giant-step over
        // [2^logB, 2^k - 1]. Table generation is not counted in Open time.
        let lookup = BuildOpeningTable(k, logB);

        let mut totalSignTime = 0f64;
        let mut totalVerifyTime = 0f64;
        let mut totalOpenUserKeyTime = 0f64;
        let mut totalOpenWitnessTime = 0f64;
        let mut size = 0usize;

        for _ in 0..iter {
            let okey = OKGen();
            let crs = CRSGen(n, logB, k, okey.Opk);

            for option in 0..4 {
                let mut R = MakeRandomRing(n);
                let (ell, w, M) = BenchmarkCase(option, n, k, logB);
                let ukey = UKGen(&crs, w, RandomScalar());
                R[ell] = ukey.Upk;

                let startSign = Instant::now();
                let signature = Sign(&crs, &crs.Opk, &ukey.Upk, &ukey.Usk, &M, &R);
                totalSignTime += startSign.elapsed().as_secs_f64() * 1000.0;
                size = SignatureSize(&signature);

                let startVerify = Instant::now();
                let ok = Verify(&crs, &signature, &R);
                totalVerifyTime += startVerify.elapsed().as_secs_f64() * 1000.0;
                assert!(ok, "Benchmark verification failed");

                // OPEN_UPK_OPTION: P=1 and w<B, so only the user public key is opened.
                // OPEN_W_OPTION:   P=0 and w>=B, so only the witness is opened.
                match option {
                    OPEN_UPK_OPTION => {
                        let startOpen = Instant::now();
                        let user_key = OpenUserKey(&okey.Osk, &signature);
                        totalOpenUserKeyTime += startOpen.elapsed().as_secs_f64() * 1000.0;
                        assert!(user_key.is_some(), "OpenUserKey failed");
                    }
                    OPEN_W_OPTION => {
                        let startOpen = Instant::now();
                        let witness = OpenWitness(&okey.Osk, &signature, &lookup);
                        totalOpenWitnessTime += startOpen.elapsed().as_secs_f64() * 1000.0;
                        assert_eq!(witness, Some(w as u64), "OpenWitness failed");
                    }
                    _ => {}
                }
            }
        }

        let signVerifyRuns = 4 * iter;
        let avgSignTime = totalSignTime / signVerifyRuns as f64;
        let avgVerifyTime = totalVerifyTime / signVerifyRuns as f64;
        // OpenUserKey is measured once per benchmark iteration using option 1.
        // OpenWitness is measured once per benchmark iteration using option 2.
        let avgOpenUserKeyTime = totalOpenUserKeyTime / iter as f64;
        let avgOpenWitnessTime = totalOpenWitnessTime / iter as f64;

        println!(
            "Params-({n:4},{k:3},{logB:2}) | {avgSignTime:10.4} ms | {avgVerifyTime:10.4} ms | {avgOpenUserKeyTime:10.4} ms | {avgOpenWitnessTime:10.4} ms | {size:10}"
        );
    }

    println!("\n{}", "=".repeat(113));
}
