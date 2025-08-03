use std::net::Ipv4Addr;
use std::time::Duration;
use pnet::util::MacAddr;
use crate::core::Cidr;
use super::error::ScanError;

/// Result for devices discovered via ARP (has MAC address)
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub response_time: Duration,
}

/// Result for hosts discovered via ICMP ping (no MAC address)
#[derive(Debug, Clone)]
pub struct PingResult {
    pub ip: Ipv4Addr,
    pub response_time: Duration,
    pub ttl: Option<u8>,
}

/// Helper trait to extract IP from result types for sorting
pub trait HasIp {
    fn ip(&self) -> Ipv4Addr;
}

impl HasIp for DiscoveredDevice {
    fn ip(&self) -> Ipv4Addr {
        self.ip
    }
}

impl HasIp for PingResult {
    fn ip(&self) -> Ipv4Addr {
        self.ip
    }
}

/// Common interface for all network scanners
#[async_trait::async_trait]
pub trait NetworkScanner: Clone + Send + Sync + 'static {
    type Result: Send + Sync + Clone + HasIp + 'static;
    
    /// Scan a single IP address
    async fn scan_ip(&self, target_ip: Ipv4Addr) -> Result<Option<Self::Result>, ScanError>;
    
    /// Scan a network range - default implementation using parallel scan_ip calls
    async fn scan_network(&self, network: &Cidr) -> Result<Vec<Self::Result>, ScanError> {
        let tasks: Vec<_> = network.network_addresses()
            .into_iter()
            .map(|ip| {
                // Clone self for each task
                let scanner = self.clone();
                tokio::spawn(async move { scanner.scan_ip(ip).await })
            })
            .collect();

        let mut devices = Vec::new();
        for task in tasks {
            if let Ok(Ok(Some(device))) = task.await {
                devices.push(device);
            }
        }

        devices.sort_by_key(|d| d.ip());
        Ok(devices)
    }
}