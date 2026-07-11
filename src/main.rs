use anyhow::{Context, Result, anyhow};
use hmac::{Hmac, Mac};
use reqwest::Client;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Mutex as AsyncMutex, mpsc},
    time::{sleep, timeout},
};
use tracing::{error, info, warn};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Deserialize)]
struct Config {
    #[serde(default)]
    site_id: String,
    #[serde(default)]
    listen: ListenConfig,
    #[serde(default)]
    storage: StorageConfig,
    #[serde(default)]
    upload: UploadConfig,
    #[serde(default)]
    collectors: Vec<CollectorConfig>,
}
#[derive(Debug, Clone, Deserialize)]
struct ListenConfig {
    #[serde(default = "default_bind")]
    bind: String,
    #[serde(default = "default_port")]
    port: u16,
}
#[derive(Debug, Clone, Deserialize)]
struct StorageConfig {
    #[serde(default = "default_db")]
    database: String,
    #[serde(default = "default_queue_limit")]
    max_bytes: u64,
}
#[derive(Debug, Clone, Deserialize)]
struct UploadConfig {
    #[serde(default)]
    url: String,
    #[serde(default)]
    key_id: String,
    #[serde(default)]
    secret: String,
    #[serde(default = "default_batch")]
    batch_size: usize,
    #[serde(default = "default_upload_timeout")]
    timeout_seconds: u64,
    #[serde(default = "default_upload_interval")]
    interval_seconds: u64,
    #[serde(default = "default_retry_max")]
    max_retries: u32,
}
#[derive(Debug, Clone, Deserialize)]
struct CollectorConfig {
    id: String,
    address: u8,
    #[serde(default = "default_func")]
    function: u8,
    #[serde(default)]
    start: u16,
    #[serde(default = "default_count")]
    count: u16,
    #[serde(default = "default_poll")]
    interval_seconds: u64,
    #[serde(default = "default_response_timeout")]
    response_timeout_seconds: u64,
    #[serde(default = "default_retries")]
    retries: u32,
}
fn default_bind() -> String {
    "0.0.0.0".into()
}
fn default_port() -> u16 {
    12345
}
fn default_db() -> String {
    "collector.db".into()
}
fn default_queue_limit() -> u64 {
    1_073_741_824
}
fn default_batch() -> usize {
    100
}
fn default_upload_timeout() -> u64 {
    15
}
fn default_upload_interval() -> u64 {
    5
}
fn default_retry_max() -> u32 {
    8
}
fn default_func() -> u8 {
    3
}
fn default_count() -> u16 {
    32
}
fn default_poll() -> u64 {
    300
}
fn default_response_timeout() -> u64 {
    5
}
fn default_retries() -> u32 {
    2
}
impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_port(),
        }
    }
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database: default_db(),
            max_bytes: default_queue_limit(),
        }
    }
}
impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            key_id: String::new(),
            secret: String::new(),
            batch_size: default_batch(),
            timeout_seconds: default_upload_timeout(),
            interval_seconds: default_upload_interval(),
            max_retries: default_retry_max(),
        }
    }
}
impl Config {
    fn load(path: &str) -> Result<Self> {
        let text = fs::read_to_string(path).with_context(|| format!("read config {path}"))?;
        let mut c: Config = toml::from_str(&text).context("parse TOML")?;
        if let Ok(secret) = std::env::var("KWOO_UPLOAD_SECRET") {
            if !secret.is_empty() {
                c.upload.secret = secret;
            }
        }
        if c.site_id.is_empty() {
            return Err(anyhow!("site_id is required"));
        }
        if c.collectors.is_empty() {
            return Err(anyhow!("at least one collector is required"));
        }
        if c.upload.url.is_empty() || c.upload.key_id.is_empty() || c.upload.secret.is_empty() {
            return Err(anyhow!(
                "upload.url, upload.key_id and upload.secret are required"
            ));
        }
        let mut ids = HashMap::new();
        let mut addrs = HashMap::new();
        for x in &c.collectors {
            if x.id.is_empty() || ids.insert(x.id.clone(), true).is_some() {
                return Err(anyhow!("collector ids must be non-empty and unique"));
            }
            if x.address == 0 || addrs.insert(x.address, true).is_some() {
                return Err(anyhow!("collector addresses must be non-zero and unique"));
            }
            if !matches!(x.function, 3 | 4)
                || x.count == 0
                || x.count > 125
                || x.interval_seconds == 0
            {
                return Err(anyhow!("invalid collector {}", x.id));
            }
        }
        c.upload.batch_size = c.upload.batch_size.max(1);
        Ok(c)
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffff;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa001
            } else {
                crc >> 1
            };
        }
    }
    crc
}
fn read_frame(addr: u8, func: u8, start: u16, count: u16) -> Vec<u8> {
    let mut f = vec![addr, func];
    f.extend(start.to_be_bytes());
    f.extend(count.to_be_bytes());
    f.extend(crc16(&f).to_le_bytes());
    f
}
fn frame_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 3 {
        return None;
    }
    match buf[1] {
        3 | 4 => Some(5 + buf[2] as usize),
        6 => Some(8),
        _ => Some(0),
    }
}
fn hex_bytes(v: &[u8]) -> String {
    hex::encode_upper(v)
        .chars()
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|x| x.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Debug)]
struct Response {
    addr: u8,
    func: u8,
    raw: Vec<u8>,
    crc_ok: bool,
}
#[derive(Clone)]
struct Gateway {
    writer: Arc<AsyncMutex<Option<tokio::net::tcp::OwnedWriteHalf>>>,
}
impl Gateway {
    async fn send(&self, data: &[u8]) -> Result<()> {
        let mut g = self.writer.lock().await;
        match g.as_mut() {
            Some(w) => w.write_all(data).await.context("send to gateway"),
            None => Err(anyhow!("no gateway connected")),
        }
    }
}

async fn gateway_server(
    bind: String,
    port: u16,
    gateway: Gateway,
    tx: mpsc::Sender<Response>,
) -> Result<()> {
    let listener = TcpListener::bind((bind.as_str(), port)).await?;
    info!(%bind, port, "gateway listener started");
    loop {
        let (stream, peer) = listener.accept().await?;
        let mut guard = gateway.writer.lock().await;
        if guard.is_some() {
            warn!(%peer, "rejecting second gateway connection");
            drop(stream);
            continue;
        }
        let (reader, writer) = stream.into_split();
        *guard = Some(writer);
        drop(guard);
        info!(%peer, "gateway connected");
        let gw = gateway.clone();
        let out = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = read_gateway(reader, out).await {
                warn!(%peer, "gateway reader: {e:#}");
            }
            *gw.writer.lock().await = None;
            info!(%peer, "gateway disconnected");
        });
    }
}
async fn read_gateway(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    tx: mpsc::Sender<Response>,
) -> Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        loop {
            if buf.first() == Some(&0x56) {
                buf.remove(0);
                continue;
            }
            if buf.starts_with(b"*26051501*") {
                buf.drain(..10);
                continue;
            }
            if buf.first() == Some(&b'*') && buf.len() < 10 {
                break;
            }
            if buf.len() < 2 {
                break;
            }
            let len = match frame_len(&buf) {
                Some(0) => {
                    buf.remove(0);
                    continue;
                }
                Some(n) => n,
                None => break,
            };
            if buf.len() < len {
                break;
            }
            let raw: Vec<u8> = buf.drain(..len).collect();
            let crc_ok = raw.len() >= 2
                && crc16(&raw[..raw.len() - 2])
                    == u16::from_le_bytes([raw[raw.len() - 2], raw[raw.len() - 1]]);
            if matches!(raw[1], 3 | 4) {
                let _ = tx
                    .send(Response {
                        addr: raw[0],
                        func: raw[1],
                        raw,
                        crc_ok,
                    })
                    .await;
            }
        }
    }
}

#[derive(Clone)]
struct Queue {
    db: Arc<Mutex<Connection>>,
    max_bytes: u64,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Event {
    event_id: String,
    site_id: String,
    collector_id: String,
    address: u8,
    requested_at: i64,
    received_at: i64,
    function: u8,
    start: u16,
    count: u16,
    request_hex: String,
    response_hex: String,
    crc_valid: bool,
}
impl Queue {
    fn open(path: &str, max_bytes: u64) -> Result<Self> {
        if let Some(p) = Path::new(path).parent() {
            if !p.as_os_str().is_empty() {
                fs::create_dir_all(p)?;
            }
        }
        let c = Connection::open(path)?;
        c.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, bytes INTEGER NOT NULL, created_at INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS events_created ON events(created_at);")?;
        Ok(Self {
            db: Arc::new(Mutex::new(c)),
            max_bytes,
        })
    }
    fn enqueue(&self, e: &Event) -> Result<()> {
        let payload = serde_json::to_string(e)?;
        let db = self.db.lock().unwrap();
        let used: i64 = db.query_row("SELECT COALESCE(SUM(bytes),0) FROM events", [], |r| {
            r.get(0)
        })?;
        if used as u64 + payload.len() as u64 > self.max_bytes {
            return Err(anyhow!("local queue capacity exceeded"));
        }
        db.execute(
            "INSERT OR IGNORE INTO events(event_id,payload,bytes,created_at) VALUES (?1,?2,?3,?4)",
            params![e.event_id, payload, payload.len() as i64, now_ms()],
        )?;
        Ok(())
    }
    fn batch(&self, n: usize) -> Result<Vec<Event>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare("SELECT payload FROM events ORDER BY created_at LIMIT ?1")?;
        let rows = st.query_map(params![n as i64], |r| {
            let s: String = r.get(0)?;
            serde_json::from_str(&s).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
    fn ack(&self, ids: &[String]) -> Result<()> {
        let db = self.db.lock().unwrap();
        let tx = db.unchecked_transaction()?;
        for id in ids {
            tx.execute("DELETE FROM events WHERE event_id=?1", params![id])?;
        }
        tx.commit()?;
        Ok(())
    }
}

async fn poller(
    cfg: Config,
    gateway: Gateway,
    mut responses: mpsc::Receiver<Response>,
    queue: Queue,
) {
    let mut next: HashMap<String, tokio::time::Instant> = cfg
        .collectors
        .iter()
        .map(|c| (c.id.clone(), tokio::time::Instant::now()))
        .collect();
    loop {
        let (idx, wait) = cfg
            .collectors
            .iter()
            .enumerate()
            .map(|(i, c)| (i, next[&c.id]))
            .min_by_key(|(_, t)| *t)
            .unwrap();
        if wait > tokio::time::Instant::now() {
            sleep(wait - tokio::time::Instant::now()).await;
            continue;
        }
        let c = &cfg.collectors[idx];
        next.insert(
            c.id.clone(),
            tokio::time::Instant::now() + Duration::from_secs(c.interval_seconds),
        );
        let req = read_frame(c.address, c.function, c.start, c.count);
        let requested_at = now_ms();
        let mut got = None;
        for attempt in 0..=c.retries {
            if let Err(e) = gateway.send(&req).await {
                warn!(collector=%c.id, "send failed: {e:#}");
                break;
            }
            let deadline = Duration::from_secs(c.response_timeout_seconds);
            let result = timeout(deadline, async {
                loop {
                    match responses.recv().await {
                        Some(r) if r.addr == c.address && r.func == c.function => break Some(r),
                        Some(_) => continue,
                        None => break None,
                    }
                }
            })
            .await;
            if let Ok(Some(r)) = result {
                got = Some(r);
                break;
            }
            if attempt < c.retries {
                sleep(Duration::from_secs((attempt + 1) as u64)).await;
            }
        }
        if let Some(r) = got {
            let e = Event {
                event_id: Uuid::new_v4().to_string(),
                site_id: cfg.site_id.clone(),
                collector_id: c.id.clone(),
                address: c.address,
                requested_at,
                received_at: now_ms(),
                function: c.function,
                start: c.start,
                count: c.count,
                request_hex: hex_bytes(&req),
                response_hex: hex_bytes(&r.raw),
                crc_valid: r.crc_ok,
            };
            if r.crc_ok {
                if let Err(err) = queue.enqueue(&e) {
                    error!(collector=%c.id, "queue event: {err:#}");
                }
            } else {
                warn!(collector=%c.id, "response CRC invalid");
            }
        } else {
            warn!(collector=%c.id, "poll timeout or failed")
        }
    }
}

async fn uploader(cfg: UploadConfig, site_id: String, queue: Queue) {
    let client = match Client::builder()
        .timeout(Duration::from_secs(cfg.timeout_seconds))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!("HTTP client: {e}");
            return;
        }
    };
    let mut backoff = 1u64;
    let mut failures = 0u32;
    loop {
        let batch = match queue.batch(cfg.batch_size) {
            Ok(x) => x,
            Err(e) => {
                error!("queue read: {e:#}");
                sleep(Duration::from_secs(backoff)).await;
                continue;
            }
        };
        if batch.is_empty() {
            sleep(Duration::from_secs(cfg.interval_seconds)).await;
            continue;
        }
        let body = match serde_json::to_vec(
            &serde_json::json!({"site_id": site_id, "sent_at": now_ms(), "events": batch}),
        ) {
            Ok(b) => b,
            Err(e) => {
                error!("serialize upload: {e}");
                continue;
            }
        };
        let ts = now_ms() / 1000;
        let mut hash = Sha256::new();
        hash.update(&body);
        let digest = hex::encode(hash.finalize());
        let canonical = format!("POST\n/v1/telemetry/raw\n{}\n{}", ts, digest);
        let mut mac =
            HmacSha256::new_from_slice(cfg.secret.as_bytes()).expect("HMAC accepts any key");
        mac.update(canonical.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        let resp = client
            .post(&cfg.url)
            .header("X-Key-Id", &cfg.key_id)
            .header("X-Timestamp", ts.to_string())
            .header("X-Signature", sig)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                let ids: Vec<String> = batch.iter().map(|e| e.event_id.clone()).collect();
                if let Err(e) = queue.ack(&ids) {
                    error!("queue ack: {e:#}");
                }
                backoff = 1;
                failures = 0;
            }
            Ok(r) if r.status().is_client_error() && r.status().as_u16() != 429 => {
                error!(status=%r.status(), "permanent upload error");
                sleep(Duration::from_secs(60)).await;
                failures = 0;
            }
            Ok(r) => {
                warn!(status=%r.status(), "upload retryable error");
                sleep(Duration::from_secs(backoff.min(300))).await;
                backoff = (backoff * 2).min(300);
                failures = failures.saturating_add(1);
                if failures >= cfg.max_retries.max(1) {
                    sleep(Duration::from_secs(60)).await;
                    failures = 0;
                }
            }
            Err(e) => {
                warn!("upload failed: {e}");
                sleep(Duration::from_secs(backoff.min(300))).await;
                backoff = (backoff * 2).min(300);
                failures = failures.saturating_add(1);
                if failures >= cfg.max_retries.max(1) {
                    sleep(Duration::from_secs(60)).await;
                    failures = 0;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".into());
    let cfg = Config::load(&path)?;
    let queue = Queue::open(&cfg.storage.database, cfg.storage.max_bytes)?;
    let gateway = Gateway {
        writer: Arc::new(AsyncMutex::new(None)),
    };
    let (tx, rx) = mpsc::channel(128);
    let server_gateway = gateway.clone();
    let listen = cfg.listen.clone();
    tokio::spawn(async move {
        if let Err(e) = gateway_server(listen.bind, listen.port, server_gateway, tx).await {
            error!("gateway server stopped: {e:#}");
        }
    });
    let poll_gateway = gateway.clone();
    let poll_cfg = cfg.clone();
    let poll_queue = queue.clone();
    tokio::spawn(async move { poller(poll_cfg, poll_gateway, rx, poll_queue).await });
    let upload_cfg = cfg.upload.clone();
    let site = cfg.site_id.clone();
    tokio::spawn(async move { uploader(upload_cfg, site, queue).await });
    tokio::signal::ctrl_c().await?;
    info!("shutdown");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crc_and_frame() {
        assert_eq!(
            hex_bytes(&read_frame(0x0b, 3, 0, 32)),
            "0B 03 00 00 00 20 44 B8"
        );
    }
    #[test]
    fn parse_len() {
        assert_eq!(frame_len(&[1, 3, 4]), Some(9));
        assert_eq!(frame_len(&[1, 6, 0, 0, 0, 1, 0, 0]), Some(8));
    }
}
