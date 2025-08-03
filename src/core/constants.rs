// Default constants for network operations
pub const DEFAULT_SOCKET_BUFFER_SIZE: usize = 4096; // Socket buffer for handling packet bursts
pub const DEFAULT_PING_PAYLOAD_SIZE: usize = 32; // Standard ping payload (matches system ping)
pub const DEFAULT_SEQUENCE_START: u16 = 1; // Starting sequence number
pub const DEFAULT_TCP_WINDOW_SIZE: u16 = 8192;

// ICMP Protocol Constants
pub const ICMP_ECHO_REQUEST_TYPE: u8 = 8;
pub const ICMP_HEADER_SIZE: usize = 8;

// Protocol Field Offsets (for manual packet parsing)
pub const ICMP_TYPE_OFFSET: usize = 0;
pub const ICMP_CODE_OFFSET: usize = 1;
pub const ICMP_CHECKSUM_OFFSET: usize = 2;
pub const ICMP_ID_OFFSET: usize = 4;
pub const ICMP_SEQUENCE_OFFSET: usize = 6;

// IPv4
pub const IPV4_ADDRESS_LENGTH: usize = 4;
pub const IPV4_HEADER_SIZE: usize = 20; // Standard IPv4 header size
pub const IPV4_OCTET_LEN: u8 = 8; // Bits in an octet
pub const IPV4_PREFIX_MAX: u8 = 32; // Max prefix length for IPv4 CIDR

// MAC Address
pub const MAC_ADDRESS_LENGTH: usize = 6; // Standard MAC address length

// ARP Protocol Constants
pub const ARP_PACKET_SIZE: usize = 28; // Header (8) + Sender MAC (6) + Sender IP (4) + Target MAC (6) + Target IP (4)
pub const ARP_HEADER_SIZE: usize = 8; // Hardware type (2) + Protocol type (2) + Hardware size (1) + Protocol size (1) + Operation (2)

// TCP Protocol Constants
pub const TCP_HEADER_SIZE: usize = 20; // Minimum TCP header size (without options)
pub const TCP_TOTAL_PACKET_SIZE: usize = IPV4_HEADER_SIZE + TCP_HEADER_SIZE;

// TCP Header Field Offsets (for manual packet construction)
pub const TCP_SOURCE_PORT_OFFSET: usize = 0;
pub const TCP_DEST_PORT_OFFSET: usize = 2;
pub const TCP_SEQUENCE_OFFSET: usize = 4;
pub const TCP_ACK_OFFSET: usize = 8;
pub const TCP_FLAGS_OFFSET: usize = 13;
pub const TCP_WINDOW_OFFSET: usize = 14;
pub const TCP_CHECKSUM_OFFSET: usize = 16;
pub const TCP_URGENT_OFFSET: usize = 18;

// TCP Flags
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_URG: u8 = 0x20;