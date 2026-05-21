use oars_ristretto::bench::{Benchmark, TestFunctions};

const DEFAULT_ITER: usize = 100;

fn main() {
    println!("System Information:");
    println!("  os: {}", std::env::consts::OS);
    println!("  arch: {}", std::env::consts::ARCH);
    println!(
        "  CPUs: {}",
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    );

    TestFunctions();

    let iter = std::env::var("OARS_ITER")
        .ok()
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(DEFAULT_ITER);
    Benchmark(iter);

}
