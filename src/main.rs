use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use ssh_key::{Algorithm, PrivateKey};

fn main() {
    let mut args = std::env::args();
    let cmd = args.next().unwrap();

    let Some(suffix) = args.next() else {
        eprintln!("usage: {cmd} SUFFIX");
        std::process::exit(1);
    };

    let threads = std::thread::available_parallelism().expect("get available parallelism");
    let count = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    println!("Spawning {threads} threads...");

    for _ in 0..threads.get() {
        let count = count.clone();
        let suffix = suffix.clone();
        thread::spawn(move || {
            generate_keys(&suffix, count);
        });
    }

    println!("Generating keys...");
    loop {
        thread::sleep(Duration::from_millis(250));
        let count = count.load(Ordering::Relaxed);
        let kps = count as f64 / start.elapsed().as_secs_f64();

        println!("\x1B[AKeys so far: {count} ({kps:.0} keys/s)");
    }
}

fn generate_keys(suffix: &str, count: Arc<AtomicU64>) {
    let mut rng = rand::thread_rng();
    loop {
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let pubkey = key.public_key().to_openssh().unwrap();

        if pubkey.ends_with(suffix) {
            println!(
                "Private key: \n{}",
                *key.to_openssh(ssh_key::LineEnding::LF).unwrap(),
            );
            println!("Public key: {}\n", pubkey);
            break;
        }

        count.fetch_add(1, Ordering::Relaxed);
    }
}
