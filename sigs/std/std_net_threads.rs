//! Networking, threads and synchronization from std, for the std
//! fingerprint databases (sigs/README.md): `TcpStream`, `TcpListener`,
//! `UdpSocket`, address parsing and name resolution, `thread`, `Mutex`,
//! `RwLock`, `Condvar`, `Barrier`, `Once` / `OnceLock`, atomics, `mpsc`.
//! These are the parts of std a networked implant is built from.
//!
//! Std only, edition 2021, no `unsafe`, and it must build with every
//! toolchain in sigs/toolchains.txt. It is only compiled in CI, never run
//! there. Run without arguments it opens no socket and only exercises the
//! threads and locks; the network paths are taken when argv asks for them
//! (`connect <host:port>`, `listen <addr>`, `udp <bind> <peer>`,
//! `resolve <host:port>`), so they are in the binary but do nothing by
//! default.

use std::collections::HashMap;
use std::env;
use std::hint::black_box;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream,
    ToSocketAddrs, UdpSocket,
};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Barrier, Condvar, Mutex, Once, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};

static INIT: Once = Once::new();
static CONFIG: OnceLock<HashMap<&'static str, u32>> = OnceLock::new();
static COUNTER: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static LOCAL: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

fn config() -> &'static HashMap<&'static str, u32> {
    CONFIG.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("workers", 4);
        m.insert("retries", 3);
        m
    })
}

#[inline(never)]
fn addresses(input: &str) -> String {
    let ip: Result<IpAddr, _> = input.parse();
    let v4 = Ipv4Addr::new(192, 168, 1, 10);
    let v6: Ipv6Addr = "fe80::1".parse().unwrap_or(Ipv6Addr::LOCALHOST);
    let sa = SocketAddr::new(IpAddr::V4(v4), 8443);
    let sa4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    let parsed: Option<SocketAddr> = "10.0.0.1:53".parse().ok();
    format!(
        "{ip:?} {v4} {} {} {v6} {} {sa} {} {sa4} {parsed:?} {:?}",
        v4.is_private(),
        u32::from(v4),
        v6.is_loopback(),
        sa.port(),
        v4.octets()
    )
}

#[inline(never)]
fn resolve(host: &str) -> io::Result<Vec<SocketAddr>> {
    Ok(host.to_socket_addrs()?.collect())
}

#[inline(never)]
fn tcp_client(target: &str) -> io::Result<String> {
    let addr = resolve(target)?
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_nodelay(true)?;
    let local = stream.local_addr()?;
    let peer = stream.peer_addr()?;
    write!(stream, "GET / HTTP/1.0\r\nHost: {}\r\n\r\n", target)?;
    stream.flush()?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut status = String::new();
    reader.read_line(&mut status)?;
    let mut rest = Vec::new();
    reader.take(1 << 16).read_to_end(&mut rest)?;
    stream.shutdown(Shutdown::Both)?;
    Ok(format!(
        "{local} -> {peer}: {} ({} bytes)",
        status.trim_end(),
        rest.len()
    ))
}

#[inline(never)]
fn tcp_server(bind: &str) -> io::Result<String> {
    let listener = TcpListener::bind(bind)?;
    listener.set_nonblocking(false)?;
    let local = listener.local_addr()?;
    let served = Arc::new(AtomicUsize::new(0));
    let (conn, peer) = listener.accept()?;
    let served2 = Arc::clone(&served);
    let h = thread::spawn(move || -> io::Result<()> {
        let mut conn = conn;
        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf)?;
        conn.write_all(&buf[..n])?;
        served2.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let r = h.join().map_err(|_| io::Error::other("handler panicked"))?;
    r?;
    for stream in listener.incoming().take(0) {
        drop(stream?);
    }
    Ok(format!(
        "{local} served {peer} ({})",
        served.load(Ordering::SeqCst)
    ))
}

#[inline(never)]
fn udp(bind: &str, peer: &str) -> io::Result<String> {
    let sock = UdpSocket::bind(bind)?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    sock.set_broadcast(false)?;
    sock.set_ttl(64)?;
    let sent = sock.send_to(b"ping", peer)?;
    let mut buf = [0u8; 512];
    let (n, from) = sock.recv_from(&mut buf)?;
    sock.connect(peer)?;
    sock.send(b"again")?;
    let m = sock.recv(&mut buf)?;
    Ok(format!(
        "{} sent {sent}, got {n} from {from}, then {m}",
        sock.local_addr()?
    ))
}

#[inline(never)]
fn workers(n: usize) -> String {
    INIT.call_once(|| COUNTER.store(1, Ordering::Relaxed));
    let parallel = thread::available_parallelism().map_or(1, |p| p.get());
    let shared = Arc::new(Mutex::new(Vec::new()));
    let table = Arc::new(RwLock::new(HashMap::<usize, String>::new()));
    let barrier = Arc::new(Barrier::new(n));
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<(usize, u64)>();
    let mut handles = Vec::new();
    for id in 0..n {
        let shared = Arc::clone(&shared);
        let table = Arc::clone(&table);
        let barrier = Arc::clone(&barrier);
        let stop = Arc::clone(&stop);
        let tx = tx.clone();
        let h = thread::Builder::new()
            .name(format!("worker-{id}"))
            .stack_size(256 * 1024)
            .spawn(move || {
                barrier.wait();
                LOCAL.with(|l| l.set(l.get() + id as u32));
                let mut acc = 0u64;
                for i in 0..1000u64 {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    acc = acc.wrapping_mul(31).wrapping_add(i ^ id as u64);
                }
                if let Ok(mut v) = shared.lock() {
                    v.push(acc);
                }
                if let Ok(mut t) = table.write() {
                    t.insert(id, thread::current().name().unwrap_or("?").to_owned());
                }
                COUNTER.fetch_add(1, Ordering::AcqRel);
                let _ = tx.send((id, acc));
                acc
            });
        if let Ok(h) = h {
            handles.push(h);
        }
    }
    drop(tx);
    let mut results = Vec::new();
    loop {
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(r) => results.push(r),
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {
                stop.store(true, Ordering::Release);
                break;
            }
        }
    }
    let joined: u64 = handles
        .into_iter()
        .filter_map(|h| h.join().ok())
        .fold(0, u64::wrapping_add);
    let names = table.read().map(|t| t.len()).unwrap_or(0);
    let total = shared.lock().map(|v| v.len()).unwrap_or(0);
    format!(
        "{parallel} {} {joined} {names} {total} {}",
        results.len(),
        COUNTER.load(Ordering::Relaxed)
    )
}

#[inline(never)]
fn condvar_and_sync_channel() -> String {
    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    let pair2 = Arc::clone(&pair);
    let (stx, srx) = mpsc::sync_channel::<String>(2);
    let started = Instant::now();
    let total = thread::scope(|s| {
        s.spawn(move || {
            let (lock, cv) = &*pair2;
            if let Ok(mut ready) = lock.lock() {
                *ready = true;
                cv.notify_all();
            }
            for i in 0..4 {
                if stx.send(format!("msg {i}")).is_err() {
                    break;
                }
            }
        });
        let (lock, cv) = &*pair;
        let mut ready = lock.lock().unwrap_or_else(|e| e.into_inner());
        while !*ready {
            match cv.wait_timeout(ready, Duration::from_millis(500)) {
                Ok((g, _)) => ready = g,
                Err(e) => ready = e.into_inner().0,
            }
        }
        drop(ready);
        let mut got = Vec::new();
        while let Ok(m) = srx.recv() {
            got.push(m);
        }
        match srx.try_recv() {
            Err(TryRecvError::Disconnected) | Err(TryRecvError::Empty) | Ok(_) => {}
        }
        got.len()
    });
    thread::sleep(Duration::from_millis(1));
    thread::yield_now();
    format!("{total} {:?}", started.elapsed() < Duration::from_secs(60))
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
    println!("{}", addresses(black_box("127.0.0.1")));
    println!("{:?}", config().get("workers"));
    println!(
        "{}",
        workers(black_box(
            config().get("workers").copied().unwrap_or(2) as usize
        ))
    );
    println!("{}", condvar_and_sync_channel());
    let result = match arg(0) {
        "connect" => tcp_client(arg(1)),
        "listen" => tcp_server(arg(1)),
        "udp" => udp(arg(1), arg(2)),
        "resolve" => resolve(arg(1)).map(|v| format!("{v:?}")),
        _ => Ok(String::new()),
    };
    match result {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
