use std::net::Ipv4Addr;
use std::time::Duration;

use crate::core::Cidr;
use super::scanners::{ArpScanner, PingScanner, PingResult, NetworkScanner};
pub use super::scanners::{ScanError, DiscoveredDevice};

/// High-level network discovery orchestrator
pub struct NetworkDiscovery {
    interface_name: String,
    timeout: Duration,
}

impl NetworkDiscovery {
    pub fn new(interface_name: String, timeout: Duration) -> Self {
        NetworkDiscovery { interface_name, timeout }
    }

    /// Create an ARP scanner for this network configuration
    pub fn arp_scanner(&self) -> ArpScanner {
        ArpScanner::new(self.interface_name.clone(), self.timeout)
    }

    /// Create a ping scanner for this network configuration
    pub fn ping_scanner(&self) -> PingScanner {
        PingScanner::new(self.timeout)
    }

    /// Scan network using ARP (Layer 2 - local network only)
    pub async fn scan_network_arp(&self, network: &Cidr) -> Result<Vec<DiscoveredDevice>, ScanError> {
        let scanner = self.arp_scanner();
        scanner.scan_network(network).await
    }

    /// Scan network using ICMP ping (Layer 3 - can reach beyond local network)
    pub async fn scan_network_ping(&self, network: &Cidr) -> Result<Vec<PingResult>, ScanError> {
        let scanner = self.ping_scanner();
        scanner.scan_network(network).await
    }

    /// Scan a single IP using ARP
    pub async fn scan_ip_arp(&self, target_ip: Ipv4Addr) -> Result<Option<DiscoveredDevice>, ScanError> {
        let scanner = self.arp_scanner();
        scanner.scan_ip(target_ip).await
    }

    /// Scan a single IP using ICMP ping  
    pub async fn scan_ip_ping(&self, target_ip: Ipv4Addr) -> Result<Option<PingResult>, ScanError> {
        let scanner = self.ping_scanner();
        scanner.scan_ip(target_ip).await
    }

    /// Default scanning method - uses ARP scanning for local network discovery
    pub async fn scan_ip(&self, target_ip: Ipv4Addr) -> Result<Option<DiscoveredDevice>, ScanError> {
        self.scan_ip_arp(target_ip).await
    }

    /// Default scanning method - uses ARP scanning for local network discovery  
    pub async fn scan_network(&self, network: &Cidr) -> Result<Vec<DiscoveredDevice>, ScanError> {
        self.scan_network_arp(network).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_arp_scan_ip() {
        let discovery = NetworkDiscovery::new("wlp4s0".to_string(), Duration::from_secs(1));
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        match discovery.scan_ip_arp(target_ip).await {
            Ok(Some(device)) => {
                println!("ARP: Discovered device: IP: {}, MAC: {}, Response Time: {:?}", device.ip, device.mac, device.response_time);
            },
            Ok(None) => println!("ARP: No device found at {}", target_ip),
            Err(e) => eprintln!("ARP: Error scanning IP: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_ping_scan_ip() {
        let discovery = NetworkDiscovery::new("wlp4s0".to_string(), Duration::from_secs(1));
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        match discovery.scan_ip_ping(target_ip).await {
            Ok(Some(result)) => {
                println!("PING: Host {} is alive, Response Time: {:?}, TTL: {:?}", 
                    result.ip, result.response_time, result.ttl);
            },
            Ok(None) => println!("PING: No response from {}", target_ip),
            Err(e) => eprintln!("PING: Error scanning IP: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_arp_scan_network() {
        let discovery = NetworkDiscovery::new("wlp4s0".to_string(), Duration::from_secs(1));
        let cidr = Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 29).unwrap(); // Small range
        match discovery.scan_network_arp(&cidr).await {
            Ok(devices) => {
                println!("ARP: Discovered {} devices:", devices.len());
                for device in devices {
                    println!("  📱 {} -> {} ({}ms)", 
                        device.ip, 
                        device.mac, 
                        device.response_time.as_millis()
                    );
                }
            },
            Err(e) => eprintln!("ARP: Network scan error: {:?}", e),
        }
    }
}