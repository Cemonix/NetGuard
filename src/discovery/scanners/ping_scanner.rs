use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use pnet::transport::{self, icmp_packet_iter, TransportChannelType, TransportProtocol};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;

use super::error::ScanError;
use super::common::{NetworkScanner, PingResult};

// ICMP Protocol Constants
const ICMP_ECHO_REQUEST_TYPE: u8 = 8;
const ICMP_HEADER_SIZE: usize = 8;

// Default Configuration Values  
const DEFAULT_PING_PAYLOAD_SIZE: usize = 32;   // Standard ping payload (matches system ping)
const DEFAULT_SOCKET_BUFFER_SIZE: usize = 4096; // Socket buffer for handling packet bursts
const DEFAULT_SEQUENCE_START: u16 = 1;         // Starting sequence number

// Protocol Field Offsets (for manual packet parsing)
const ICMP_TYPE_OFFSET: usize = 0;
const ICMP_CODE_OFFSET: usize = 1;  
const ICMP_CHECKSUM_OFFSET: usize = 2;
const ICMP_ID_OFFSET: usize = 4;
const ICMP_SEQUENCE_OFFSET: usize = 6;

/// Configuration for ICMP ping scanner
#[derive(Clone)]
pub struct PingScanner {
    timeout: Duration,
    header_size: usize,
    packet_size: usize,
    buffer_size: usize,
    sequence_start: u16,
}

impl PingScanner {
    /// Creates a new ICMP ping scanner with default configuration
    pub fn new(timeout: Duration) -> Self {
        PingScanner { 
            timeout,
            header_size: ICMP_HEADER_SIZE,
            packet_size: DEFAULT_PING_PAYLOAD_SIZE,
            buffer_size: DEFAULT_SOCKET_BUFFER_SIZE,
            sequence_start: DEFAULT_SEQUENCE_START,
        }
    }

    /// Configure the ping payload size (data portion, not including ICMP header)
    /// Standard sizes: 32 bytes (default), 56 bytes (Linux ping default with headers)
    pub fn with_packet_size(mut self, size: usize) -> Self {
        self.packet_size = size;
        self
    }

    /// Configure the socket buffer size for receiving packets
    /// Larger buffers can handle more simultaneous pings but use more memory
    /// Typical values: 1024-8192 bytes
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Configure the starting sequence number for ICMP packets
    /// Useful for avoiding conflicts when multiple scanners are running
    pub fn with_sequence_start(mut self, seq: u16) -> Self {
        self.sequence_start = seq;
        self
    }

    /// Builds an ICMP Echo Request packet with the given ID and sequence number.
    /// The checksum field is left as zero and should be set after calling this function.
    fn build_icmp_packet(&self, id: u16, seq: u16) -> Vec<u8> {
        let mut packet = vec![0; self.packet_size + self.header_size]; // Header + payload
        let icmp_header = &mut packet[..self.header_size];
        
        // Build ICMP header using constants for clarity
        icmp_header[ICMP_TYPE_OFFSET] = ICMP_ECHO_REQUEST_TYPE;
        icmp_header[ICMP_CODE_OFFSET] = 0; // Code 0 for Echo Request
        icmp_header[ICMP_CHECKSUM_OFFSET..ICMP_CHECKSUM_OFFSET + 2].copy_from_slice(&[0, 0]); // Checksum placeholder
        icmp_header[ICMP_ID_OFFSET..ICMP_ID_OFFSET + 2].copy_from_slice(&id.to_be_bytes());
        icmp_header[ICMP_SEQUENCE_OFFSET..ICMP_SEQUENCE_OFFSET + 2].copy_from_slice(&seq.to_be_bytes());
        
        // Payload is already zero-initialized (standard for ping)
        packet
    }

    /// Calculates the ICMP checksum for a given packet.
    /// 
    /// The checksum is computed by interpreting the packet as a sequence of 16-bit words,
    /// summing them using one's complement arithmetic, and then taking the one's complement
    /// of the final sum. If the packet length is odd, the last byte is padded with zero.
    /// 
    /// # Algorithm Details
    /// 
    /// 1. The packet is split into 2-byte chunks. Each chunk is converted to a `u16` in big-endian order.
    ///    - If a chunk has only one byte (odd-length packet), it is padded with zero as the second byte.
    /// 2. Each 16-bit word is added to a 32-bit accumulator (`sum`).
    /// 3. After all words are summed, any overflow from the upper 16 bits is folded back into the lower 16 bits.
    ///    - This is done by repeatedly adding the upper 16 bits to the lower 16 bits until no overflow remains.
    /// 4. The final sum is inverted (one's complement) and returned as the checksum.
    /// 
    /// This algorithm follows the standard ICMP checksum calculation as specified in RFC 1071.
    fn calculate_checksum(packet: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in packet.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += u32::from(word);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

#[async_trait::async_trait]
impl NetworkScanner for PingScanner {
    type Result = PingResult;

    async fn scan_ip(&self, target_ip: Ipv4Addr) -> Result<Option<Self::Result>, ScanError> {
        let start_time = Instant::now();
        
        // Create raw ICMP transport channel with configurable buffer size
        let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
        let (mut tx, mut rx) = match transport::transport_channel(self.buffer_size, protocol) {
            Ok(channel) => channel,
            Err(e) => return Err(ScanError::NetworkError(format!("Failed to create ICMP socket: {}", e))),
        };

        // Build ICMP Echo Request packet with unique identifiers
        let id = std::process::id() as u16; // Use process ID as identifier
        let seq = self.sequence_start;
        let mut packet_buf = self.build_icmp_packet(id, seq);
        
        // Calculate and set checksum using protocol constants
        let checksum = Self::calculate_checksum(&packet_buf);
        packet_buf[ICMP_CHECKSUM_OFFSET..ICMP_CHECKSUM_OFFSET + 2].copy_from_slice(&checksum.to_be_bytes());

        // Create proper ICMP packet from buffer
        let icmp_packet = MutableIcmpPacket::new(&mut packet_buf)
            .ok_or(ScanError::NetworkError("Failed to create ICMP packet".to_string()))?;

        // Send packet to target IP
        match tx.send_to(icmp_packet, std::net::IpAddr::V4(target_ip)) {
            Ok(_) => {},
            Err(e) => return Err(ScanError::NetworkError(format!("Failed to send ICMP packet: {}", e))),
        }

        // Listen for ICMP Echo Reply with timeout
        let mut iter = icmp_packet_iter(&mut rx);
        let timeout_instant = start_time + self.timeout;
        
        loop {
            if Instant::now() > timeout_instant {
                return Ok(None); // Timeout - no response
            }

            // Non-blocking check for packets
            match iter.next() {
                Ok((packet, addr)) => {
                    // Check if this is our Echo Reply
                    if let std::net::IpAddr::V4(source_ip) = addr {
                        if source_ip == target_ip {
                            if let Some(icmp_packet) = IcmpPacket::new(packet.packet()) {
                                // Check if it's an Echo Reply (Type 0) and matches our ID
                                if icmp_packet.get_icmp_type() == IcmpTypes::EchoReply {
                                    let packet_data = icmp_packet.packet();
                                    let received_id = u16::from_be_bytes([
                                        packet_data[ICMP_ID_OFFSET], 
                                        packet_data[ICMP_ID_OFFSET + 1]
                                    ]);
                                    
                                    if received_id == id {
                                        // Success! Calculate response time
                                        let response_time = start_time.elapsed();
                                        
                                        // Extract TTL from IP header (if available)
                                        // Note: TTL extraction depends on raw socket access
                                        let ttl = None; // TODO: Extract from IP header
                                        
                                        return Ok(Some(PingResult {
                                            ip: target_ip,
                                            response_time,
                                            ttl,
                                        }));
                                    }
                                }
                            }
                        }
                    }
                },
                Err(_) => {
                    // No packet available right now, continue waiting
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    continue;
                }
            }
        }
    }
}