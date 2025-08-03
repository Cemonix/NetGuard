use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use pnet::transport::{self, TransportChannelType, TransportProtocol, tcp_packet_iter};
use pnet::packet::tcp::{TcpPacket, TcpFlags, MutableTcpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;

use crate::core::{calculate_internet_checksum, constants, NetworkInterface};
use crate::discovery::scanners::PacketError;
use crate::discovery::ScanError;

#[derive(Debug, Clone)]
pub enum ScanResult {
    Open,
    Closed,
    Filtered,
    OpenFiltered, // Common in UDP scans
}

#[derive(Debug, Clone)]
pub enum UdpScanResult {
    Open,
    Closed,
    OpenFiltered, // Most common - ambiguous result
}

#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub port: u16,
    pub result: ScanResult,
    pub service: Option<ServiceInfo>,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
}

pub struct TcpConnectScanner {
    network_interface: NetworkInterface,
    timeout: Duration,
}

impl TcpConnectScanner {
    pub fn new(network_interface: NetworkInterface, timeout_ms: u64) -> Self {
        Self {
            network_interface,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    pub async fn scan_port(&self, ip: IpAddr, port: u16) -> bool {
        let target = SocketAddr::new(ip, port);

        match timeout(self.timeout, TcpStream::connect(target)).await {
            Ok(Ok(_)) => true,   // Connection successful
            Ok(Err(_)) => false, // Connection refused (port closed)
            Err(_) => false,     // Timeout (port filtered/firewalled)
        }
    }

    pub async fn syn_scan(&self, target: Ipv4Addr, port: u16) -> Result<ScanResult, ScanError> {
        let start_time = Instant::now();
        
        // Create raw TCP transport channel
        let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
        let (mut tx, mut rx) = match transport::transport_channel(
            constants::DEFAULT_SOCKET_BUFFER_SIZE, protocol
        ) {
            Ok(channel) => channel,
            Err(e) => {
                let error_msg = if e.to_string().contains("permission") {
                    "Raw socket access requires root privileges. Try: sudo ./netguard"
                } else {
                    "Failed to create transport channel"
                };
                return Err(ScanError::NetworkError(format!("{}: {}", error_msg, e)));
            }
        };

        // Generate a random source port for the scan
        let source_port = (std::process::id() as u16).wrapping_add(port) % 32768 + 32768;

        // Build and send TCP SYN packet
        match self.build_tcp_packet(target, port, source_port, constants::TCP_FLAG_SYN) {
            Ok(tcp_packet_bytes) => {
                // Create mutable TCP packet for sending
                if let Some(tcp_packet) = MutableTcpPacket::new(&mut tcp_packet_bytes.clone()) {
                    // Send the SYN packet
                    if let Err(e) = tx.send_to(tcp_packet, std::net::IpAddr::V4(target)) {
                        return Err(PacketError::SendFailed(format!("Failed to send SYN packet: {}", e)).into());
                    }
                } else {
                    return Err(PacketError::CreationFailed(format!("Failed to create mutable TCP packet.")).into());
                }
            }
            Err(e) => {
                return Err(PacketError::CreationFailed(format!("Failed to create TCP packet: {}", e)).into());
            }
        }

        // Listen for TCP response with timeout
        let mut iter = tcp_packet_iter(&mut rx);
        let timeout_instant = start_time + self.timeout;

        loop {
            if Instant::now() > timeout_instant {
                return Ok(ScanResult::Filtered); // Timeout - likely filtered
            }

            // Check for incoming TCP packets
            match iter.next() {
                Ok((packet, addr)) => {
                    // Check if this response is from our target
                    if let std::net::IpAddr::V4(source_ip) = addr {
                        if source_ip == target {
                            if let Some(tcp_packet) = TcpPacket::new(packet.packet()) {
                                // Check if this is a response to our SYN packet
                                if tcp_packet.get_destination() == source_port && 
                                   tcp_packet.get_source() == port {
                                    
                                    let flags = tcp_packet.get_flags();
                                    
                                    // Check response type
                                    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                                        // SYN-ACK received - port is open!
                                        // Send RST to close connection (stealth)
                                        self.send_rst_packet(
                                            target, port, source_port,
                                            tcp_packet.get_acknowledgement(), &mut tx
                                        ).await;
                                        return Ok(ScanResult::Open);
                                    } else if flags & TcpFlags::RST != 0 {
                                        // RST received - port is closed
                                        return Ok(ScanResult::Closed);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    // No packet available right now, continue waiting
                    tokio::task::yield_now().await;
                    continue;
                }
            }
        }
    }

    fn build_tcp_packet(
        &self,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        source_port: u16,
        flag: u8,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut packet = vec![0u8; constants::TCP_HEADER_SIZE];
        
        // Build TCP header using constants for clarity
        // Source port (16 bits)
        packet[constants::TCP_SOURCE_PORT_OFFSET..constants::TCP_SOURCE_PORT_OFFSET + 2]
            .copy_from_slice(&source_port.to_be_bytes());
        
        // Destination port (16 bits)
        packet[constants::TCP_DEST_PORT_OFFSET..constants::TCP_DEST_PORT_OFFSET + 2]
            .copy_from_slice(&dest_port.to_be_bytes());
        
        // Sequence number (32 bits)
        packet[constants::TCP_SEQUENCE_OFFSET..constants::TCP_SEQUENCE_OFFSET + 4]
            .copy_from_slice(&constants::DEFAULT_SEQUENCE_START.to_be_bytes());
        
        // Acknowledgment number (32 bits) - 0 for SYN packet
        packet[constants::TCP_ACK_OFFSET..constants::TCP_ACK_OFFSET + 4]
            .copy_from_slice(&0u32.to_be_bytes());
        
        // Data offset (4 bits) + Reserved (3 bits) + NS flag (1 bit)
        // Data offset = 5 (20 bytes / 4) shifted left by 4 bits
        packet[12] = 5 << 4;
        
        // TCP flags (8 bits)
        packet[constants::TCP_FLAGS_OFFSET] = flag;

        // Window size (16 bits)
        packet[constants::TCP_WINDOW_OFFSET..constants::TCP_WINDOW_OFFSET + 2]
            .copy_from_slice(&constants::DEFAULT_TCP_WINDOW_SIZE.to_be_bytes());

        // Checksum (16 bits) - will be calculated later
        packet[constants::TCP_CHECKSUM_OFFSET..constants::TCP_CHECKSUM_OFFSET + 2]
            .copy_from_slice(&0u16.to_be_bytes());
        
        // Urgent pointer (16 bits) - 0 for normal packets
        packet[constants::TCP_URGENT_OFFSET..constants::TCP_URGENT_OFFSET + 2]
            .copy_from_slice(&0u16.to_be_bytes());
        
        // Calculate and set the TCP checksum
        let checksum = self.calculate_tcp_checksum(&packet, dest_ip)?;
        packet[constants::TCP_CHECKSUM_OFFSET..constants::TCP_CHECKSUM_OFFSET + 2]
            .copy_from_slice(&checksum.to_be_bytes());
        
        Ok(packet)
    }

    /// Send RST packet to close the connection (for stealth scanning)
    async fn send_rst_packet(
        &self,
        target: Ipv4Addr,
        target_port: u16,
        source_port: u16,
        ack_number: u32,
        tx: &mut pnet::transport::TransportSender,
    ) {
        match self.build_tcp_packet(target, target_port, source_port, constants::TCP_FLAG_RST) {
            Ok(mut rst_packet_bytes) => {
                // Set the sequence number to the ACK number we received
                rst_packet_bytes[constants::TCP_SEQUENCE_OFFSET..constants::TCP_SEQUENCE_OFFSET + 4]
                    .copy_from_slice(&ack_number.to_be_bytes());
                
                // Recalculate checksum after modifying sequence number
                rst_packet_bytes[constants::TCP_CHECKSUM_OFFSET..constants::TCP_CHECKSUM_OFFSET + 2]
                    .copy_from_slice(&0u16.to_be_bytes());
                    
                if let Ok(checksum) = self.calculate_tcp_checksum(&rst_packet_bytes, target) {
                    rst_packet_bytes[constants::TCP_CHECKSUM_OFFSET..constants::TCP_CHECKSUM_OFFSET + 2]
                        .copy_from_slice(&checksum.to_be_bytes());
                }
                
                // Create mutable TCP packet for sending
                if let Some(rst_packet) = MutableTcpPacket::new(&mut rst_packet_bytes) {
                    // Send RST packet
                    if let Err(e) = tx.send_to(rst_packet, std::net::IpAddr::V4(target)) {
                        eprintln!("Failed to send RST packet: {}", e);
                    }
                } else {
                    eprintln!("Failed to create mutable RST packet");
                }
            }
            Err(e) => {
                eprintln!("Failed to build RST packet: {}", e);
            }
        }
    }

    fn calculate_tcp_checksum(
        &self,
        tcp_packet: &[u8],
        dest_ip: Ipv4Addr,
    ) -> Result<u16, ScanError> {
        // Get source IP from network interface
        let (source_ipv4, _mac_addr) = self.network_interface.get_interface_info()
            .map_err(|e| ScanError::NetworkError(format!("Failed to get interface info: {}", e)))?;

        // Build pseudo-header for checksum calculation
        let mut pseudo_header = Vec::with_capacity(12); // Pseudo-header is always 12 bytes
        
        // Source IP (4 bytes)
        pseudo_header.extend_from_slice(&source_ipv4.octets());
        
        // Destination IP (4 bytes)
        pseudo_header.extend_from_slice(&dest_ip.octets());
        
        // Zero byte (1 byte)
        pseudo_header.push(0);
        
        // Protocol (1 byte) - TCP is protocol 6
        pseudo_header.push(6);
        
        // TCP length (2 bytes) - length of TCP header + data
        let tcp_length = tcp_packet.len() as u16;
        pseudo_header.extend_from_slice(&tcp_length.to_be_bytes());

        // Create complete packet for checksum: pseudo-header + TCP packet
        let mut checksum_data = pseudo_header;
        checksum_data.extend_from_slice(tcp_packet);

        // Calculate checksum using the same algorithm as ICMP
        let checksum = calculate_internet_checksum(&checksum_data);
        
        Ok(checksum)
    }
}
