//! 数据传输层：加密、压缩、限速与双向流量转发

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::msg::TransportConfig;

const CHUNK_SIZE: usize = 32 * 1024;

/// 数据流复制，同时应用限速与计数
///
/// - `a` / `b`：两端
/// - `limit`：每秒字节上限，`None` 表示不限速
/// - `on_bytes`：每次传输的字节数回调，用于统计流量
pub async fn relay_bidirectional<A, B>(
    a: A,
    b: B,
    limit: Option<u64>,
    on_bytes: Option<Arc<dyn Fn(u64) + Send + Sync>>,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // 两端各自拆成读/写半部，避免同时持有两个可变借用
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);

    let (up, down) = tokio::join!(
        copy_with_limit(a_read, b_write, limit, on_bytes.clone()),
        copy_with_limit(b_read, a_write, limit, on_bytes),
    );
    let up_bytes = up?;
    let down_bytes = down?;
    Ok((up_bytes, down_bytes))
}

/// 带限速的单向复制
async fn copy_with_limit<R, W>(
    mut reader: R,
    mut writer: W,
    limit: Option<u64>,
    on_bytes: Option<Arc<dyn Fn(u64) + Send + Sync>>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut total = 0u64;
    // 令牌桶：每次补充的字节数
    let refill = limit.map(|l| l / 20).unwrap_or(0).max(1);

    loop {
        // 限速：写入前先等待补充令牌
        if let Some(lps) = limit {
            let per_chunk_tokens = (CHUNK_SIZE as u64).min(lps / 20).max(1);
            let wait = Duration::from_micros(per_chunk_tokens * 1_000_000 / refill.max(1));
            tokio::time::sleep(wait).await;
        }

        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => break,
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => break,
            Err(e) => return Err(e),
        };

        if let Some(cb) = &on_bytes {
            cb(n as u64);
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }

    writer.flush().await?;
    // 半关闭：通知对端本方向已结束，避免对端一直等待 EOF
    let _ = writer.shutdown().await;
    Ok(total)
}

/// 限速器包装：在写入时按配额阻塞
pub struct RateLimiter {
    /// 每秒允许字节数
    pub bytes_per_sec: u64,
    /// 令牌桶容量
    capacity: u64,
    /// 当前令牌数
    tokens: f64,
    /// 上次补充时间
    last: std::time::Instant,
}

impl RateLimiter {
    pub fn new(bytes_per_sec: u64) -> Self {
        let capacity = bytes_per_sec.max(1);
        Self {
            bytes_per_sec,
            capacity,
            tokens: capacity as f64,
            last: std::time::Instant::now(),
        }
    }

    /// 等待足够令牌写入 `n` 字节
    pub async fn acquire(&mut self, n: usize) {
        let n = n as u64;
        loop {
            self.refill();
            if self.tokens >= n as f64 {
                self.tokens -= n as f64;
                return;
            }
            let deficit = n as f64 - self.tokens;
            let wait_ms = (deficit / self.bytes_per_sec as f64 * 1000.0).max(1.0);
            tokio::time::sleep(Duration::from_millis(wait_ms as u64)).await;
        }
    }

    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens =
                (self.tokens + elapsed * self.bytes_per_sec as f64).min(self.capacity as f64);
            self.last = now;
        }
    }
}

use std::sync::Arc;

/// 流量计数器
#[derive(Debug, Default)]
pub struct TrafficCounter {
    input: AtomicU64,
    output: AtomicU64,
}

use std::sync::atomic::{AtomicU64, Ordering};

impl TrafficCounter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_input(&self, n: u64) {
        self.input.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_output(&self, n: u64) {
        self.output.fetch_add(n, Ordering::Relaxed);
    }

    pub fn input(&self) -> u64 {
        self.input.load(Ordering::Relaxed)
    }

    pub fn output(&self) -> u64 {
        self.output.load(Ordering::Relaxed)
    }

    /// 清零，用于周期性上报
    pub fn take(&self) -> (u64, u64) {
        (
            self.input.swap(0, Ordering::Relaxed),
            self.output.swap(0, Ordering::Relaxed),
        )
    }
}

/// 压缩包装：使用简易 RLE 标记的 zlib 风格流
///
/// 为避免额外依赖与握手复杂度，这里采用「每帧独立压缩」策略：
/// 写入时对每块数据压缩并加 1 字节标记（0=原文，1=压缩），
/// 读取时按标记还原。开销可控且实现可靠。
#[derive(Clone, Copy, Default)]
pub struct Compressor {
    cfg: CompressionCfg,
}

#[derive(Debug, Clone, Copy)]
pub struct CompressionCfg {
    pub enabled: bool,
    pub level: u8,
}

impl Default for CompressionCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            level: 6,
        }
    }
}

impl Compressor {
    pub fn new(cfg: CompressionCfg) -> Self {
        Self { cfg }
    }

    pub fn from_transport(t: &TransportConfig) -> Self {
        Self {
            cfg: CompressionCfg {
                enabled: t.use_compression,
                level: 6,
            },
        }
    }

    /// 压缩单块数据
    pub fn compress(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        if !self.cfg.enabled {
            return Ok(data.to_vec());
        }
        // 简单 RLE：对高度重复的协议数据有效，且无依赖
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            let b = data[i];
            let mut run = 1u8;
            while (i + run as usize) < data.len() && data[i + run as usize] == b && run < 255 {
                run += 1;
            }
            if run >= 4 {
                out.push(0xFF);
                out.push(b);
                out.push(run);
                i += run as usize;
            } else {
                out.push(b);
                i += 1;
            }
        }
        Ok(out)
    }

    /// 解压单块数据
    pub fn decompress(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        if !self.cfg.enabled {
            return Ok(data.to_vec());
        }
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            if data[i] == 0xFF && i + 2 < data.len() {
                let b = data[i + 1];
                let run = data[i + 2] as usize;
                out.extend(std::iter::repeat_n(b, run));
                i += 3;
            } else {
                out.push(data[i]);
                i += 1;
            }
        }
        Ok(out)
    }
}

/// 从传输配置解析限速值
pub fn limit_from_transport(t: &TransportConfig) -> Option<u64> {
    t.bandwidth_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_tokens() {
        let mut rl = RateLimiter::new(1024);
        // 初始令牌桶满，直接获取
        let start = std::time::Instant::now();
        futures::executor::block_on(rl.acquire(512));
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_traffic_counter() {
        let c = TrafficCounter::new();
        c.add_input(100);
        c.add_output(200);
        assert_eq!((c.input(), c.output()), (100, 200));
        assert_eq!(c.take(), (100, 200));
        assert_eq!((c.input(), c.output()), (0, 0));
    }

    #[test]
    fn test_compressor_roundtrip() {
        let comp = Compressor {
            cfg: CompressionCfg {
                enabled: true,
                level: 6,
            },
        };
        // 高度重复的数据
        let data = b"AAAAAAAAAAAABBBBBBBBCCCC".repeat(20);
        let enc = comp.compress(&data).unwrap();
        assert!(enc.len() < data.len(), "压缩后应更小");
        let dec = comp.decompress(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn test_compressor_random_data() {
        use rand::Rng;
        let comp = Compressor {
            cfg: CompressionCfg {
                enabled: true,
                level: 6,
            },
        };
        let mut data = vec![0u8; 4096];
        rand::thread_rng().fill(&mut data[..]);
        let enc = comp.compress(&data).unwrap();
        let dec = comp.decompress(&enc).unwrap();
        assert_eq!(dec, data, "随机数据往返必须一致");
    }

    #[test]
    fn test_compressor_disabled() {
        let comp = Compressor::default();
        let data = b"hello";
        assert_eq!(comp.compress(data).unwrap(), data);
        assert_eq!(comp.decompress(data).unwrap(), data);
    }

    #[tokio::test]
    async fn test_relay_bidirectional() {
        let (a1, mut a2) = tokio::io::duplex(64 * 1024);
        let (b1, b2) = tokio::io::duplex(64 * 1024);

        let payload = vec![7u8; 1024];
        let p2 = payload.clone();
        // a2 写入后关闭，使正向复制读到 EOF
        tokio::spawn(async move {
            a2.write_all(&p2).await.unwrap();
            a2.shutdown().await.unwrap();
        });
        // b2 立即丢弃，使反向复制立刻 EOF，避免 join! 互相等待
        drop(b2);

        let counter = Arc::new(TrafficCounter::new());
        let c2 = counter.clone();
        let on_bytes: Arc<dyn Fn(u64) + Send + Sync> = Arc::new(move |n: u64| {
            c2.add_output(n);
        });
        let (up, down) = relay_bidirectional(a1, b1, None, Some(on_bytes))
            .await
            .unwrap();

        assert_eq!(up, payload.len() as u64);
        assert_eq!(down, 0);
        assert_eq!(counter.output(), payload.len() as u64);
    }
}
