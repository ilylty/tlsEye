use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TlsState {
    /// DNS 不包含该 IP，且请求双方的 TLS 公钥不一致
    Mismatch = 0,
    /// 解析 SNI 得到的 IP 列表中包含 Dst IP
    DnsMatch = 1,
    /// DNS 未包含该 IP，但 Dst IP 返回的证书公钥与解析 IP 证书公钥一致
    TlsMatch = 2,
    /// 探测 TLS 证书时，Dst IP 连接失败，或所有解析 IP 均连接失败
    IpConnectionFailed = 8,
    /// 遍历所有预配置的 DNS/DoH 列表后，均无法解析该 SNI
    DnsResolutionFailed = 9,
}

impl TlsState {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn is_alert(&self) -> bool {
        matches!(
            self,
            TlsState::Mismatch | TlsState::IpConnectionFailed | TlsState::DnsResolutionFailed
        )
    }

    pub fn is_valid(&self) -> bool {
        matches!(self, TlsState::DnsMatch | TlsState::TlsMatch)
    }
}

impl std::fmt::Display for TlsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_u8())
    }
}
