//! A tour of the commonly used parts of std, for the std fingerprint
//! databases (sigs/README.md): collections, strings and formatting, I/O and
//! the file system, paths, environment and processes, time, `Rc` / `Arc`,
//! errors.
//!
//! std itself ships precompiled with the toolchain, but generic and
//! `#[inline]` std code is compiled into the program that uses it, at the
//! program's optimization level. The more std a program instantiates, the
//! more of that code the database can name.
//!
//! Std only, edition 2021, no `unsafe`, and it must build with every
//! toolchain in sigs/toolchains.txt (so no recently stabilized APIs). It is
//! only compiled in CI, never run there. Run without arguments, it only
//! works in memory; the file system and process paths are taken when
//! argv asks for them (`fs <dir>`, `run <program> [args..]`, `stdin`), so
//! they are in the binary but do nothing by default.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, LinkedList, VecDeque};
use std::env;
use std::error::Error;
use std::fmt::{self, Write as _};
use std::fs::{self, File, OpenOptions};
use std::hint::black_box;
use std::io::{self, BufRead, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Record {
    id: u32,
    name: String,
    tags: Vec<String>,
}

#[derive(Debug)]
enum TourError {
    Parse(String),
    Io(io::Error),
}

impl fmt::Display for TourError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TourError::Parse(s) => write!(f, "cannot parse {s:?}"),
            TourError::Io(e) => write!(f, "i/o: {e}"),
        }
    }
}

impl Error for TourError {}

impl From<io::Error> for TourError {
    fn from(e: io::Error) -> Self {
        TourError::Io(e)
    }
}

impl FromStr for Record {
    type Err = TourError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(';');
        let id = parts
            .next()
            .and_then(|p| p.trim().parse::<u32>().ok())
            .ok_or_else(|| TourError::Parse(s.to_owned()))?;
        let name = parts.next().unwrap_or("").trim().to_owned();
        let tags = parts
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        Ok(Record { id, name, tags })
    }
}

#[inline(never)]
fn collections(seed: u64) -> String {
    let mut out = String::new();
    let mut v: Vec<u64> = (0..64).map(|i| (i * 2654435761 ^ seed) % 1000).collect();
    v.sort_unstable();
    v.dedup();
    v.retain(|x| x % 3 != 0);
    let found = v.binary_search(&black_box(500)).is_ok();
    let sums: Vec<u64> = v.chunks(4).map(|c| c.iter().sum()).collect();
    let maxw = v.windows(2).map(|w| w[1] - w[0]).max().unwrap_or(0);
    let mut sorted = v.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    sorted.reverse();
    let _ = writeln!(
        out,
        "vec {} {found} {:?} {maxw}",
        v.len(),
        &sums[..sums.len().min(3)]
    );

    let mut hm: HashMap<String, Vec<u64>> = HashMap::new();
    for x in &v {
        hm.entry(format!("k{}", x % 7)).or_default().push(*x);
    }
    let mut keys: Vec<_> = hm.keys().cloned().collect();
    keys.sort();
    let hs: HashSet<u64> = v.iter().map(|x| x % 10).collect();
    let mut bt: BTreeMap<u64, &str> = BTreeMap::new();
    bt.insert(3, "three");
    bt.insert(1, "one");
    bt.insert(2, "two");
    let range: Vec<_> = bt.range(2..).map(|(k, v)| format!("{k}={v}")).collect();
    let bs: BTreeSet<char> = "the quick brown fox"
        .chars()
        .filter(|c| c.is_alphabetic())
        .collect();
    let mut dq: VecDeque<u64> = VecDeque::with_capacity(8);
    dq.push_back(1);
    dq.push_front(0);
    dq.extend([2, 3, 4]);
    dq.rotate_left(2);
    let mut heap: BinaryHeap<u64> = v.iter().copied().collect();
    let top: Vec<u64> = std::iter::from_fn(|| heap.pop()).take(3).collect();
    let mut ll: LinkedList<&str> = LinkedList::new();
    ll.push_back("b");
    ll.push_front("a");
    let _ = writeln!(
        out,
        "maps {keys:?} {} {range:?} {bs:?} {dq:?} {top:?} {ll:?}",
        hs.len()
    );
    hm.remove("k0");
    if hm.contains_key("k1") {
        out.push_str("has k1\n");
    }
    out
}

#[inline(never)]
fn strings(input: &str) -> String {
    let mut out = String::with_capacity(256);
    let upper = input.to_uppercase();
    let replaced = input.replace("o", "0");
    let words: Vec<&str> = input.split_whitespace().collect();
    let joined = words.join("-");
    let rev: String = input.chars().rev().collect();
    let idx: Vec<(usize, char)> = input
        .char_indices()
        .filter(|(_, c)| c.is_ascii_digit())
        .collect();
    let trimmed = input.trim_matches(|c: char| !c.is_alphanumeric());
    let starts = input.starts_with("the") && input.ends_with('x') || input.contains("fox");
    let (head, tail) = input.split_at(input.len() / 2);
    let lines: Vec<String> = input.lines().map(str::to_owned).collect();
    let bytes = input.as_bytes().to_vec();
    let back = String::from_utf8(bytes.clone()).unwrap_or_default();
    let lossy: Cow<'_, str> = String::from_utf8_lossy(&bytes[..bytes.len().min(5)]);
    let num: i64 = "-12345".parse().unwrap_or(0);
    let flt: f64 = "3.25e2".parse().unwrap_or(0.0);
    let hex = u32::from_str_radix("ff", 16).unwrap_or(0);
    let _ = writeln!(
        out,
        "{upper} {replaced} {joined} {rev} {idx:?} {trimmed} {starts}"
    );
    let _ = writeln!(
        out,
        "[{head}|{tail}] {} {back} {lossy} {num} {flt}",
        lines.len()
    );
    let _ = writeln!(
        out,
        "{num:>10} {num:<10}| {flt:.3} {flt:e} {hex:#x} {hex:08b} {hex:o} {:?}",
        'x'
    );
    let rec: Result<Record, _> = "7; Name ; A ;B".parse();
    if let Ok(r) = &rec {
        let _ = writeln!(out, "{r:?}\n{r:#?}");
    }
    let e = "x".parse::<Record>().unwrap_err();
    let _ = writeln!(out, "{e} / {e:?} / {}", e.source().is_none());
    let mut s = String::from("abc");
    s.insert(0, '>');
    s.insert_str(1, "<<");
    s.truncate(5);
    let _ = s.pop();
    s.extend(['1', '2']);
    s.make_ascii_uppercase();
    out.push_str(&s);
    out += &format!("{:?} {:?}", s.find('B'), s.rsplit_once('A'));
    out
}

#[inline(never)]
fn shared() -> usize {
    let rc = Rc::new(RefCell::new(vec![1, 2, 3]));
    let rc2 = Rc::clone(&rc);
    rc2.borrow_mut().push(4);
    let weak = Rc::downgrade(&rc);
    let cell = Cell::new(5);
    cell.set(cell.get() + 1);
    let arc: Arc<str> = Arc::from("shared");
    let boxed: Box<dyn Fn(usize) -> usize> = Box::new(move |x| x + cell.get());
    let n = rc.borrow().len() + weak.upgrade().map_or(0, |r| r.borrow().len()) + arc.len();
    boxed(n) + Rc::strong_count(&rc)
}

#[inline(never)]
fn io_in_memory() -> io::Result<String> {
    let mut cur = Cursor::new(Vec::new());
    {
        let mut w = BufWriter::new(&mut cur);
        for i in 0..5 {
            writeln!(w, "line {i}")?;
        }
        w.flush()?;
    }
    cur.seek(SeekFrom::Start(0))?;
    let mut lines = Vec::new();
    for line in BufReader::new(&mut cur).lines() {
        lines.push(line?);
    }
    cur.seek(SeekFrom::Start(2))?;
    let mut rest = String::new();
    cur.read_to_string(&mut rest)?;
    let mut buf = [0u8; 4];
    let mut r: &[u8] = b"abcdef";
    r.read_exact(&mut buf)?;
    let mut sink = io::sink();
    io::copy(&mut io::repeat(b'z').take(10), &mut sink)?;
    Ok(format!("{} {} {:?}", lines.len(), rest.len(), buf))
}

#[inline(never)]
fn file_system(dir: &Path) -> Result<String, Box<dyn Error>> {
    let base: PathBuf = dir.join("unforge-std-tour");
    fs::create_dir_all(base.join("sub"))?;
    let file = base.join("sub").join("data.txt");
    {
        let mut f = File::create(&file)?;
        f.write_all(b"1;one;a\n2;two;b\n")?;
        f.sync_all()?;
    }
    let mut f = OpenOptions::new().append(true).read(true).open(&file)?;
    writeln!(f, "3;three;c")?;
    let text = fs::read_to_string(&file)?;
    let records: Vec<Record> = text.lines().filter_map(|l| l.parse().ok()).collect();
    let copy = base.join("copy.txt");
    fs::copy(&file, &copy)?;
    let moved = base.join("moved.txt");
    fs::rename(&copy, &moved)?;
    let meta = fs::metadata(&moved)?;
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok());
    let mut names = Vec::new();
    for entry in fs::read_dir(&base)? {
        let entry = entry?;
        names.push((
            entry.file_name().to_string_lossy().into_owned(),
            entry.file_type()?.is_dir(),
        ));
    }
    names.sort();
    let bytes = fs::read(&moved)?;
    let canon = fs::canonicalize(&moved)?;
    fs::write(base.join("out.bin"), &bytes)?;
    fs::remove_file(&moved)?;
    fs::remove_dir_all(&base)?;
    Ok(format!(
        "{} {} {:?} {:?} {} {}",
        records.len(),
        meta.len(),
        modified.map(|d| d.as_secs() > 0),
        names,
        canon.display(),
        bytes.len()
    ))
}

#[inline(never)]
fn paths(p: &str) -> String {
    let path = Path::new(p);
    let mut buf = PathBuf::from("/tmp");
    buf.push("a");
    buf.push("b.tar.gz");
    buf.set_extension("zst");
    let comps: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    format!(
        "{:?} {:?} {:?} {:?} {} {:?} {} {:?}",
        path.file_name(),
        path.file_stem(),
        path.extension(),
        path.parent(),
        path.is_absolute(),
        comps,
        buf.display(),
        buf.strip_prefix("/tmp").ok()
    )
}

#[inline(never)]
fn environment() -> String {
    let args: Vec<String> = env::args().collect();
    let os_args = env::args_os().count();
    let home = env::var("HOME").unwrap_or_else(|_| String::from("?"));
    let n_vars = env::vars().filter(|(k, _)| k.starts_with('X')).count();
    let path_dirs = env::var_os("PATH").map_or(0, |p| env::split_paths(&p).count());
    let cwd = env::current_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    let exe = env::current_exe().ok();
    format!(
        "{} {os_args} {home} {n_vars} {path_dirs} {cwd} {:?} {} {} {}",
        args.len(),
        exe.as_deref().and_then(Path::file_name),
        env::temp_dir().display(),
        env::consts::OS,
        std::process::id()
    )
}

#[inline(never)]
fn run(program: &str, args: &[String]) -> io::Result<String> {
    let out = Command::new(program)
        .args(args)
        .env("UNFORGE_TOUR", "1")
        .env_remove("UNFORGE_UNSET")
        .current_dir(env::temp_dir())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"hello\n")?;
    }
    let status = child.wait()?;
    let _ = child.kill();
    Ok(format!(
        "{:?} {} {} {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).len(),
        out.stderr.len(),
        status.success()
    ))
}

#[inline(never)]
fn read_stdin() -> io::Result<usize> {
    let stdin = io::stdin();
    let mut line = String::new();
    let mut total = 0;
    while stdin.lock().read_line(&mut line)? > 0 {
        total += line.len();
        line.clear();
    }
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "read {total} bytes")?;
    Ok(total)
}

#[inline(never)]
fn time() -> String {
    let start = Instant::now();
    let now = SystemTime::now();
    let since = now.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let d = Duration::from_millis(1500) + Duration::from_secs_f64(0.25);
    let later = start.checked_add(d);
    let elapsed = start.elapsed();
    format!(
        "{} {:?} {} {:?} {}",
        since.as_secs() > 0,
        d,
        later.is_some(),
        d.checked_sub(Duration::from_secs(1)),
        elapsed.as_nanos() < u128::MAX
    )
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut out = io::stdout().lock();
    let seed = black_box(args.len() as u64 + 17);
    let mut report = String::new();
    report.push_str(&collections(seed));
    report.push_str(&strings(black_box(
        "the quick brown fox 42 jumps over 7 lazy dogs",
    )));
    let _ = writeln!(report, "\n{} {:?}", shared(), io_in_memory().ok());
    let _ = writeln!(
        report,
        "{}",
        paths(black_box("/usr/lib/x86_64/libfoo.so.1"))
    );
    let _ = writeln!(report, "{}", environment());
    let _ = writeln!(report, "{}", time());
    let result: Result<String, Box<dyn Error>> = match args.first().map(String::as_str) {
        Some("fs") => file_system(Path::new(args.get(1).map_or(".", String::as_str))),
        Some("run") => match args.get(1) {
            Some(p) => run(p, args.get(2..).unwrap_or(&[])).map_err(Into::into),
            None => Err(Box::new(TourError::Parse(String::from(
                "run needs a program",
            )))),
        },
        Some("stdin") => read_stdin().map(|n| n.to_string()).map_err(Into::into),
        _ => Ok(String::new()),
    };
    if writeln!(out, "{report}").is_err() {
        return ExitCode::FAILURE;
    }
    match result {
        Ok(s) => {
            let _ = writeln!(out, "{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
