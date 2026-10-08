//! `rscross-transport`：把两个传输库**各司其职**地组合起来。
//!
//! # 角色划分（对应需求 1）
//!
//! | 能力 | 承担者 | 说明 |
//! |---|---|---|
//! | NAT 打洞 | **Iroh** | QUIC over UDP + QAD(NAT 地址发现) + 打洞；`net_report` 负责 NAT 类型探测 |
//! | 中继回退 | **Iroh Relay** 与 **FerroTunnel** | 打洞失败时 Iroh 自动落到 relay；FerroTunnel 提供「客户端主动外连」的稳定反向隧道 |
//! | 密钥交换 | **Iroh** | `SecretKey`(Ed25519) 的公钥即 `EndpointId`，同时充当 QUIC/TLS1.3 的证书身份，天然双向认证 |
//! | 节点发现 | **Iroh** | `presets::N0` 挂载 DNS/Pkarr address lookup（`PkarrPublisher` + `PkarrResolver` + `DnsAddressLookup`） |
//! | 反向隧道/多路复用/Host 路由/限速 | **FerroTunnel** | `Server` 内置 `bind`(控制面) + `http_bind`(HTTP 入口)；`Client` 按 `tunnel_id` 映射本地服务 |
//! | 业务身份、配置下发、审计 | rscross 自身 | 见 `rscross-server` / `rscross-client` |
//!
//! 为什么要两个而不是一个：
//! - FerroTunnel 解决的是**「内网节点如何被公网访问」**——客户端主动外连，天然穿透 NAT；
//!   但它不提供点对点直连，所有流量都过服务端。
//! - Iroh 解决的是**「两个节点如何直连」**——打洞成功后流量不过服务端，带宽与延迟都更优。
//! - 二者组合成「直连优先 + 中继兜底」，并且 Iroh 的公钥身份把「节点发现 + 认证」从
//!   「共享 token」升级为「每个节点一把密钥」。

pub mod forward;
pub mod path;
pub mod p2p;
pub mod relay;

pub use path::{PathChoice, PathProbe, PathSelector};
pub use p2p::{
    addr_from_id, decode_addr, encode_addr, load_or_create_secret_key, P2pDataHandler, P2pNode,
    P2pOptions, P2pStream, TunnelTargets, ALPN_CONTROL, ALPN_DATA,
};
pub use relay::{RelayServer, RelayTunnelClient, RelayTunnelState};

/// 便捷重导出：底层两套传输库的顶层类型。
pub mod upstream {
    pub use ferrotunnel::{Client as FerryClient, Server as FerryServer, TunnelInfo as FerryTunnelInfo};
    pub use iroh::{Endpoint as IrohEndpoint, EndpointAddr as IrohEndpointAddr, SecretKey as IrohSecretKey};
}
