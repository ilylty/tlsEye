use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::models::state::TlsState;

/// 模拟器或抓包工具发送到 Kafka 的原始消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawKafkaMessage {
    pub ori_ip: IpAddr,
    pub dst_ip: IpAddr,
    /// base64 encoded payload
    #[serde(alias = "payload", alias = "payload_base64")]
    pub payload: String,
}

/// 解析出 SNI 后的待处理任务数据
#[derive(Debug, Clone)]
pub struct AnalysisTask {
    pub ori_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub sni: String,
}

/// 写入 Redis Result DB (DB 1) 的异常结果记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub ori_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub sni: String,
    pub state: u8,
    pub timestamp: u64,
}

impl AlertRecord {
    pub fn new(
        ori_ip: IpAddr,
        dst_ip: IpAddr,
        sni: String,
        state: TlsState,
        timestamp: u64,
    ) -> Self {
        Self {
            ori_ip,
            dst_ip,
            sni,
            state: state.as_u8(),
            timestamp,
        }
    }
}
