//! 路径选择：决定一次数据面连接走「Iroh 直连」还是「中继」。
//!
//! 策略来自控制面下发的 [`rscross_common::PathPolicy`]：
//! - `auto`：直连可用就走直连，否则回落中继（默认）。
//! - `p2p-only`：只允许直连。用于对「数据不经第三方/不经服务端」有硬要求的场景；
//!   直连不可用时**拒绝服务**而不是静默降级。
//! - `relay-only`：全部走中继，便于统一审计、限速与出口治理。

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use rscross_common::{PathKind, PathPolicy};

/// 一次连通性探测的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathProbe {
    /// 是否成功。
    pub ok: bool,
    /// 往返时延（毫秒），失败时为 `None`。
    pub rtt_ms: Option<u32>,
    /// 失败原因（成功时为 `None`）。
    pub error: Option<String>,
}

impl PathProbe {
    /// 构造成功结果。
    pub fn ok(rtt_ms: u32) -> Self {
        Self {
            ok: true,
            rtt_ms: Some(rtt_ms),
            error: None,
        }
    }

    /// 构造失败结果。
    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            rtt_ms: None,
            error: Some(error.into()),
        }
    }
}

/// 选定的路径。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathChoice {
    /// 路径类型。
    pub kind: PathKind,
    /// 选择理由，直接写进日志与审计。
    pub reason: &'static str,
}

/// 路径选择器。多线程共享，内部状态为原子量，读路径无锁。
#[derive(Debug)]
pub struct PathSelector {
    policy: PathPolicy,
    p2p_healthy: AtomicBool,
    p2p_rtt_ms: AtomicU32,
    /// 连续失败次数，用于避免「一失败就永久降级」。
    consecutive_failures: AtomicU32,
}

impl PathSelector {
    /// 用给定策略创建。
    pub fn new(policy: PathPolicy) -> Self {
        Self {
            policy,
            p2p_healthy: AtomicBool::new(false),
            p2p_rtt_ms: AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
        }
    }

    /// 当前策略。
    pub fn policy(&self) -> PathPolicy {
        self.policy
    }

    /// 更新策略（控制面热更新配置时调用）。
    pub fn set_policy(&mut self, policy: PathPolicy) {
        self.policy = policy;
    }

    /// 记录一次探测结果。
    pub fn observe(&self, probe: &PathProbe) {
        if probe.ok {
            self.p2p_healthy.store(true, Ordering::Relaxed);
            self.consecutive_failures.store(0, Ordering::Relaxed);
            if let Some(rtt) = probe.rtt_ms {
                self.p2p_rtt_ms.store(rtt, Ordering::Relaxed);
            }
        } else {
            let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
            // 连续 3 次失败才判定直连不可用，避免瞬时抖动导致流量在两条路径间反复横跳。
            if failures >= 3 {
                self.p2p_healthy.store(false, Ordering::Relaxed);
            }
        }
    }

    /// 直连当前是否健康。
    pub fn p2p_healthy(&self) -> bool {
        self.p2p_healthy.load(Ordering::Relaxed)
    }

    /// 最近一次测得的直连 RTT。
    pub fn p2p_rtt_ms(&self) -> Option<u32> {
        match self.p2p_rtt_ms.load(Ordering::Relaxed) {
            0 => None,
            v => Some(v),
        }
    }

    /// 该策略下是否允许回落中继。
    pub fn allows_relay(&self) -> bool {
        !matches!(self.policy, PathPolicy::P2pOnly)
    }

    /// 做出一次选择。
    pub fn choose(&self) -> PathChoice {
        match self.policy {
            PathPolicy::P2pOnly => PathChoice {
                kind: PathKind::P2p,
                reason: "策略=p2p-only，强制直连",
            },
            PathPolicy::RelayOnly => PathChoice {
                kind: PathKind::FerryRelay,
                reason: "策略=relay-only，全部经服务端中继",
            },
            PathPolicy::Auto => {
                if self.p2p_healthy() {
                    PathChoice {
                        kind: PathKind::P2p,
                        reason: "策略=auto，直连健康",
                    }
                } else {
                    PathChoice {
                        kind: PathKind::FerryRelay,
                        reason: "策略=auto，直连不可用，回落 FerroTunnel 中继",
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_falls_back_when_unhealthy() {
        let s = PathSelector::new(PathPolicy::Auto);
        assert_eq!(s.choose().kind, PathKind::FerryRelay);

        s.observe(&PathProbe::ok(12));
        assert_eq!(s.choose().kind, PathKind::P2p);
        assert_eq!(s.p2p_rtt_ms(), Some(12));
    }

    #[test]
    fn needs_three_failures_to_downgrade() {
        let s = PathSelector::new(PathPolicy::Auto);
        s.observe(&PathProbe::ok(5));
        s.observe(&PathProbe::failed("timeout"));
        assert!(s.p2p_healthy(), "一次失败不应立刻降级");
        s.observe(&PathProbe::failed("timeout"));
        assert!(s.p2p_healthy(), "两次失败仍不降级");
        s.observe(&PathProbe::failed("timeout"));
        assert!(!s.p2p_healthy(), "三次连续失败后降级");
        assert_eq!(s.choose().kind, PathKind::FerryRelay);
    }

    #[test]
    fn relay_only_never_picks_direct() {
        let s = PathSelector::new(PathPolicy::RelayOnly);
        s.observe(&PathProbe::ok(1));
        assert_eq!(s.choose().kind, PathKind::FerryRelay);
        assert!(s.allows_relay());
    }

    #[test]
    fn p2p_only_disallows_relay() {
        let s = PathSelector::new(PathPolicy::P2pOnly);
        assert!(!s.allows_relay());
        assert_eq!(s.choose().kind, PathKind::P2p);
    }
}
