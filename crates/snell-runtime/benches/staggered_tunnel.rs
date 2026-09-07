//! Persistent connections with independent lognormal idle intervals.
//!
//! Median 200 ms, sigma 1, clipped to 1 ms..5 s; deterministic per-connection seeds.
//! Each burst echoes 64 KiB. Warmup is 3 s, measurement defaults to 15 s.
//! SNELL_BENCH_FLAVOR=v4|v6s|v6u and SNELL_BENCH_CONNECTIONS=100,256 select cases.
#[path = "support/tunnel.rs"]
mod worker;

use std::io;
use std::time::Duration;
use tokio::time::Instant;
use worker::Process;

const BURST_BYTES: usize = 64 << 10;
const MAX_SAMPLES_PER_CONNECTION: usize = 4096;

fn main() {
    if std::env::args()
        .nth(1)
        .is_some_and(|a| a.starts_with("--role="))
    {
        worker::main();
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(run())
        .unwrap();
}

// SplitMix64 + Box-Muller avoids a benchmark-only RNG dependency.
struct IdleRng(u64);
impl IdleRng {
    fn uniform(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^= z >> 31;
        ((z >> 11) as f64 + 0.5) / ((1u64 << 53) as f64)
    }
    fn next(&mut self) -> Duration {
        let normal =
            (-2.0 * self.uniform().ln()).sqrt() * (std::f64::consts::TAU * self.uniform()).cos();
        Duration::from_secs_f64((0.2 * normal.exp()).clamp(0.001, 5.0))
    }
}

async fn run() -> io::Result<()> {
    let seconds: u64 = std::env::var("SNELL_BENCH_SECONDS")
        .unwrap_or_else(|_| "15".into())
        .parse()
        .map_err(io::Error::other)?;
    if !(1..=60).contains(&seconds) {
        return Err(io::Error::other("SNELL_BENCH_SECONDS must be 1..=60"));
    }
    let flavors = std::env::var("SNELL_BENCH_FLAVOR").unwrap_or_else(|_| "v4,v6s,v6u".into());
    let counts = std::env::var("SNELL_BENCH_CONNECTIONS").unwrap_or_else(|_| "100,256".into());
    println!(
        "phase,flavor,connections,role,elapsed_ms,rss_kib,leased_bytes,bursts,bytes,mib_per_s,p50_us,p99_us,idle_p50_ms,idle_p99_ms"
    );
    for flavor in flavors.split(',') {
        if !["v4", "v6s", "v6u"].contains(&flavor) {
            return Err(io::Error::other("unknown benchmark flavor"));
        }
        for count in counts.split(',') {
            let count: usize = count.parse().map_err(io::Error::other)?;
            if !(1..=512).contains(&count) {
                return Err(io::Error::other("connection count must be 1..=512"));
            }
            measure(flavor, count, Duration::from_secs(seconds)).await?;
        }
    }
    Ok(())
}

async fn measure(flavor: &str, count: usize, duration: Duration) -> io::Result<()> {
    let echo = Process::start(&["--role=echo", &count.to_string()])?;
    let mut server = Process::start(&["--role=server", flavor])?;
    let mut client = Process::start(&["--role=client", flavor, &server.addr.to_string()])?;
    let mut streams = Vec::with_capacity(count);
    for _ in 0..count {
        let stream = worker::socks5_connect(client.addr, echo.addr).await?;
        stream.set_nodelay(true)?;
        streams.push(stream);
    }
    let start = Instant::now();
    let measured = start + Duration::from_secs(3);
    let end = measured + duration;
    let mut tasks = tokio::task::JoinSet::new();
    for (index, mut stream) in streams.into_iter().enumerate() {
        tasks.spawn(async move {
            let mut rng = IdleRng(0x534e454c4c ^ index as u64);
            let mut latency = Vec::with_capacity(256);
            let mut idle = Vec::with_capacity(256);
            loop {
                let idle_start = Instant::now();
                let next = idle_start + rng.next();
                if next >= end {
                    break;
                }
                tokio::time::sleep_until(next).await;
                let burst_start = Instant::now();
                if burst_start >= end {
                    break;
                }
                tokio::time::timeout(
                    Duration::from_secs(5),
                    worker::pipelined_echo(&mut stream, BURST_BYTES, 8 << 10, index as u8),
                )
                .await
                .map_err(io::Error::other)??;
                if burst_start >= measured {
                    if latency.len() == MAX_SAMPLES_PER_CONNECTION {
                        return Err(io::Error::other("benchmark sample cap reached"));
                    }
                    latency.push(burst_start.elapsed().as_micros() as u64);
                    idle.push((burst_start - idle_start).as_micros() as u64);
                }
            }
            // Keep every original connection open through the entire measurement.
            tokio::time::sleep_until(end).await;
            io::Result::Ok((stream, latency, idle))
        });
    }
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while Instant::now() < end {
        tick.tick().await;
        let phase = if Instant::now() < measured {
            "warmup"
        } else {
            "sample"
        };
        for (role, process) in [("server", &mut server), ("client", &mut client)] {
            let (rss, leased) = process.snapshot()?;
            println!(
                "{phase},{flavor},{count},{role},{:.3},{rss},{leased},,,,,,,",
                start.elapsed().as_secs_f64() * 1000.0
            );
        }
    }
    let mut connections = Vec::with_capacity(count);
    let mut latencies = Vec::new();
    let mut idles = Vec::new();
    while let Some(result) = tasks.join_next().await {
        let (stream, latency, idle) = result??;
        connections.push(stream);
        latencies.extend(latency);
        idles.extend(idle);
    }
    latencies.sort_unstable();
    idles.sort_unstable();
    if latencies.is_empty() {
        return Err(io::Error::other("no measured bursts"));
    }
    let quantile = |values: &[u64], pct: usize| values[(values.len() * pct).div_ceil(100) - 1];
    let bytes = latencies.len() * BURST_BYTES;
    println!(
        "summary,{flavor},{count},driver,{:.3},,,{},{},{:.3},{},{},{:.3},{:.3}",
        duration.as_secs_f64() * 1000.0,
        latencies.len(),
        bytes,
        bytes as f64 / duration.as_secs_f64() / (1 << 20) as f64,
        quantile(&latencies, 50),
        quantile(&latencies, 99),
        quantile(&idles, 50) as f64 / 1000.0,
        quantile(&idles, 99) as f64 / 1000.0
    );
    eprintln!(
        "{flavor} n={count}: {} bursts, p99={} us, idle median={:.1} ms",
        latencies.len(),
        quantile(&latencies, 99),
        quantile(&idles, 50) as f64 / 1000.0
    );
    drop(connections);
    Ok(())
}
