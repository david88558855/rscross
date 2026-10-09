//! 双向字节转发工具。
//!
//! 两条路径的形态不同：
//! - FerroTunnel 路径：TCP ↔ TCP，直接 `copy_bidirectional`。
//! - Iroh 路径：TCP ↔ QUIC 双向流，而 QUIC 的收发是**两个独立的类型**
//!   （`SendStream` / `RecvStream`），不能整体做 `copy_bidirectional`，
//!   因此拆成两个方向的 `copy` 并用 `try_join!` 汇合，最后显式关闭写侧。

use rscross_common::{Error, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// TCP ↔ TCP 双向转发，返回 `(上行字节, 下行字节)`。
pub async fn tcp_to_tcp(a: TcpStream, b: TcpStream) -> Result<(u64, u64)> {
    let (mut a, mut b) = (a, b);
    tokio::io::copy_bidirectional(&mut a, &mut b)
        .await
        .map_err(Error::transport)
}

/// 通用的「读侧/写侧分离」双向转发。
///
/// `up` 方向：`src_read` → `dst_write`；`down` 方向：`dst_read` → `src_write`。
/// 返回值顺序为 `(up 字节数, down 字节数)`。
pub async fn bridge_split<R1, W1, R2, W2>(
    mut src_read: R1,
    mut src_write: W1,
    mut dst_read: R2,
    mut dst_write: W2,
) -> Result<(u64, u64)>
where
    R1: AsyncRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    let up = tokio::io::copy(&mut src_read, &mut dst_write);
    let down = tokio::io::copy(&mut dst_read, &mut src_write);
    let (sent, received) = tokio::try_join!(up, down).map_err(Error::transport)?;
    // 尽力关闭写侧：某些对端对「半关闭」敏感（HTTP keep-alive、gRPC trailers）。
    let _ = dst_write.shutdown().await;
    let _ = src_write.shutdown().await;
    Ok((sent, received))
}

/// 人类可读的字节数格式化（控制台与日志共用）。
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut idx = 0usize;
    while value >= 1024.0 && idx + 1 < UNITS.len() {
        value /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn bridge_split_moves_bytes_both_ways() {
        let mut src_read: &[u8] = b"ping";
        let mut src_write: Vec<u8> = Vec::new();
        let mut dst_read: &[u8] = b"pong";
        let mut dst_write: Vec<u8> = Vec::new();

        let (up, down) = bridge_split(&mut src_read, &mut src_write, &mut dst_read, &mut dst_write)
            .await
            .expect("bridge");

        assert_eq!(up, 4, "src → dst 应搬运 4 字节");
        assert_eq!(down, 4, "dst → src 应搬运 4 字节");
        assert_eq!(dst_write, b"ping");
        assert_eq!(src_write, b"pong");
    }

    /// 起一个回显服务，验证 `tcp_to_tcp` 真的把两条 TCP 连接对拼起来。
    #[tokio::test]
    async fn tcp_to_tcp_splices_two_connections() {
        // 右侧：回显服务
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind echo");
        let echo_addr = echo.local_addr().expect("addr");
        let echo_task = tokio::spawn(async move {
            let (mut sock, _) = echo.accept().await.expect("accept echo");
            let mut buf = [0u8; 4];
            if sock.read_exact(&mut buf).await.is_ok() {
                let _ = sock.write_all(&buf).await;
            }
            let _ = sock.shutdown().await;
        });

        // 左侧：客户端连接
        let left = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind left");
        let left_addr = left.local_addr().expect("addr");

        let right = TcpStream::connect(echo_addr).await.expect("connect echo");
        let relay = tokio::spawn(async move {
            let (client_side, _) = left.accept().await.expect("accept left");
            tcp_to_tcp(client_side, right).await
        });

        let mut caller = TcpStream::connect(left_addr).await.expect("connect left");
        caller.write_all(b"pong").await.expect("write");
        let mut buf = [0u8; 4];
        caller.read_exact(&mut buf).await.expect("read echo");
        assert_eq!(&buf, b"pong");

        drop(caller);
        let _ = relay.await;
        let _ = echo_task.await;
    }

    #[test]
    fn human_bytes_formats() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.00 KB");
        assert_eq!(human_bytes(1024 * 1024), "1.00 MB");
    }
}
