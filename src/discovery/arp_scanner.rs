use std::{error::Error, fmt::{self, Display}};

use crate::core::{Ipv4Address, MacAddress, IPV4_ADDRESS_LENGTH, MAC_ADDRESS_LENGTH};

pub const ARP_PACKET_SIZE: usize = 28; // Header (8) + Sender MAC (6) + Sender IP (4) + Target MAC (6) + Target IP (4)
pub const ARP_HEADER_SIZE: usize = 8; // Hardware type (2) + Protocol type (2) + Hardware size (1) + Protocol size (1) + Operation (2)

#[derive(Debug, PartialEq)]
pub enum ArpError {
    InvalidPacketSize,
    InvalidOperation,
    InvalidHardwareType,
    InvalidProtocolType,
}

impl fmt::Display for ArpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpError::InvalidPacketSize => write!(f, "Invalid ARP packet size"),
            ArpError::InvalidOperation => write!(f, "Invalid ARP operation"),
            ArpError::InvalidHardwareType => write!(f, "Invalid hardware type"),
            ArpError::InvalidProtocolType => write!(f, "Invalid protocol type"),
        }
    }
}

impl Error for ArpError {}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum HardwareType {
    Ethernet = 1
}


impl HardwareType {
    pub fn from_u16(value: u16) -> Result<Self, ArpError> {
        match value {
            1 => Ok(HardwareType::Ethernet),
            _ => Err(ArpError::InvalidHardwareType),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ProtocolType {
    Ipv4 = 0x0800
}

impl ProtocolType {
    pub fn from_u16(value: u16) -> Result<Self, ArpError> {
        match value {
            0x0800 => Ok(ProtocolType::Ipv4),
            _ => Err(ArpError::InvalidProtocolType),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Operation {
    Request = 1,
    Reply = 2
}

impl Operation {
    pub fn from_u16(value: u16) -> Result<Self, ArpError> {
        match value {
            1 => Ok(Operation::Request),
            2 => Ok(Operation::Reply),
            _ => Err(ArpError::InvalidOperation),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ArpPacket {
    hardware_type: HardwareType,
    hardware_size: u8,
    protocol_type: ProtocolType,
    protocol_size: u8,
    operation: Operation,
    sender_mac: MacAddress,
    sender_ip: Ipv4Address,
    target_mac: MacAddress,
    target_ip: Ipv4Address
}

impl ArpPacket {
    pub fn new(
        hardware_type: HardwareType,
        protocol_type: ProtocolType,
        operation: Operation,
        sender_mac: MacAddress,
        sender_ip: Ipv4Address,
        target_mac: MacAddress,
        target_ip: Ipv4Address
    ) -> Self {
        ArpPacket {
            hardware_type,
            hardware_size: MAC_ADDRESS_LENGTH as u8,
            protocol_type,
            protocol_size: IPV4_ADDRESS_LENGTH as u8,
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }

    pub fn hardware_type(&self) -> HardwareType {
        self.hardware_type
    }

    pub fn protocol_type(&self) -> ProtocolType {
        self.protocol_type
    }

    pub fn hardware_size(&self) -> u8 {
        self.hardware_size
    }

    pub fn protocol_size(&self) -> u8 {
        self.protocol_size
    }

    pub fn operation(&self) -> Operation {
        self.operation
    }

    pub fn sender_mac(&self) -> MacAddress {
        self.sender_mac
    }

    pub fn sender_ip(&self) -> Ipv4Address {
        self.sender_ip
    }

    pub fn target_mac(&self) -> MacAddress {
        self.target_mac
    }

    pub fn target_ip(&self) -> Ipv4Address {
        self.target_ip
    }

    pub fn is_request(&self) -> bool {
        self.operation == Operation::Request
    }

    pub fn is_reply(&self) -> bool {
        self.operation == Operation::Reply
    }

    pub fn to_bytes(&self) -> [u8; ARP_PACKET_SIZE] {
        let mut bytes = [0u8; ARP_PACKET_SIZE];
        let mut index = 0;

        // Hardware type (2 bytes, big-endian)
        let hw_type = (self.hardware_type as u16).to_be_bytes();
        bytes[index..index+2].copy_from_slice(&hw_type);
        index += 2;

        // Protocol type (2 bytes, big-endian) 
        let proto_type = (self.protocol_type as u16).to_be_bytes();
        bytes[index..index+2].copy_from_slice(&proto_type);
        index += 2;

        // Hardware address length (1 byte)
        bytes[index] = self.hardware_size;
        index += 1;

        // Protocol address length (1 byte)
        bytes[index] = self.protocol_size;
        index += 1;

        // Operation (2 bytes, big-endian)
        let operation = (self.operation as u16).to_be_bytes();
        bytes[index..index+2].copy_from_slice(&operation);
        index += 2;

        // Sender hardware address (6 bytes)
        bytes[index..index+6].copy_from_slice(&self.sender_mac.address());
        index += 6;

        // Sender protocol address (4 bytes)
        bytes[index..index+4].copy_from_slice(&self.sender_ip.address());
        index += 4;

        // Target hardware address (6 bytes)
        bytes[index..index+6].copy_from_slice(&self.target_mac.address());
        index += 6;

        // Target protocol address (4 bytes)
        bytes[index..index+4].copy_from_slice(&self.target_ip.address());

        bytes
    }

    pub fn from_bytes(bytes: &[u8; ARP_PACKET_SIZE]) -> Result<Self, ArpError> {
        let mut index = 0;

        // Parse hardware type (2 bytes)
        let hw_type = u16::from_be_bytes([bytes[index], bytes[index+1]]);
        let hardware_type = HardwareType::from_u16(hw_type)?;
        index += 2;

        // Parse protocol type (2 bytes)
        let proto_type = u16::from_be_bytes([bytes[index], bytes[index+1]]);
        let protocol_type = ProtocolType::from_u16(proto_type)?;
        index += 2;

        // Parse hardware and protocol sizes
        let hardware_size = bytes[index];
        index += 1;
        let protocol_size = bytes[index];
        index += 1;

        // Validate sizes
        if hardware_size != MAC_ADDRESS_LENGTH as u8 || protocol_size != IPV4_ADDRESS_LENGTH as u8 {
            return Err(ArpError::InvalidPacketSize);
        }

        // Parse operation (2 bytes)
        let op = u16::from_be_bytes([bytes[index], bytes[index+1]]);
        let operation = Operation::from_u16(op)?;
        index += 2;

        // Parse sender MAC (6 bytes)
        let mut sender_mac_bytes = [0u8; 6];
        sender_mac_bytes.copy_from_slice(&bytes[index..index+6]);
        let sender_mac = MacAddress::new(sender_mac_bytes);
        index += 6;

        // Parse sender IP (4 bytes)
        let mut sender_ip_bytes = [0u8; 4];
        sender_ip_bytes.copy_from_slice(&bytes[index..index+4]);
        let sender_ip = Ipv4Address::new(sender_ip_bytes);
        index += 4;

        // Parse target MAC (6 bytes)
        let mut target_mac_bytes = [0u8; 6];
        target_mac_bytes.copy_from_slice(&bytes[index..index+6]);
        let target_mac = MacAddress::new(target_mac_bytes);
        index += 6;

        // Parse target IP (4 bytes)
        let mut target_ip_bytes = [0u8; 4];
        target_ip_bytes.copy_from_slice(&bytes[index..index+4]);
        let target_ip = Ipv4Address::new(target_ip_bytes);

        Ok(ArpPacket {
            hardware_type,
            hardware_size,
            protocol_type,
            protocol_size,
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }

    pub fn create_request(
        sender_mac: MacAddress,
        sender_ip: Ipv4Address,
        target_ip: Ipv4Address
    ) -> Self {
        let target_mac = MacAddress::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        Self::new(
            HardwareType::Ethernet,
            ProtocolType::Ipv4,
            Operation::Request,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        )
    }

    pub fn create_reply(
        sender_mac: MacAddress,
        sender_ip: Ipv4Address,
        target_mac: MacAddress,
        target_ip: Ipv4Address
    ) -> Self {
        Self::new(
            HardwareType::Ethernet,
            ProtocolType::Ipv4,
            Operation::Reply,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        )
    }

    pub fn is_request_for(&self, ip: &Ipv4Address) -> bool {
        self.target_ip == *ip
    }
}

impl Display for ArpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ARP Packet: {{ hardware_type: {:?}, protocol_type: {:?}, operation: {:?}, sender_mac: {}, sender_ip: {}, target_mac: {}, target_ip: {} }}",
            self.hardware_type,
            self.protocol_type,
            self.operation,
            self.sender_mac.to_string(),
            self.sender_ip.to_string(),
            self.target_mac.to_string(),
            self.target_ip.to_string()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_type_from_u16() {
        assert_eq!(HardwareType::from_u16(1), Ok(HardwareType::Ethernet));
        assert_eq!(HardwareType::from_u16(2), Err(ArpError::InvalidHardwareType));
    }

    #[test]
    fn test_protocol_type_from_u16() {
        assert_eq!(ProtocolType::from_u16(0x0800), Ok(ProtocolType::Ipv4));
        assert_eq!(ProtocolType::from_u16(0x0806), Err(ArpError::InvalidProtocolType));
    }

    #[test]
    fn test_operation_from_u16() {
        assert_eq!(Operation::from_u16(1), Ok(Operation::Request));
        assert_eq!(Operation::from_u16(2), Ok(Operation::Reply));
        assert_eq!(Operation::from_u16(3), Err(ArpError::InvalidOperation));
    }

    #[test]
    fn test_arp_packet_creation() {
        let sender_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let sender_ip = Ipv4Address::new([192, 168, 1, 100]);
        let target_mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let target_ip = Ipv4Address::new([192, 168, 1, 1]);

        let packet = ArpPacket::new(
            HardwareType::Ethernet,
            ProtocolType::Ipv4,
            Operation::Request,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        );

        assert_eq!(packet.hardware_type(), HardwareType::Ethernet);
        assert_eq!(packet.protocol_type(), ProtocolType::Ipv4);
        assert_eq!(packet.operation(), Operation::Request);
        assert_eq!(packet.hardware_size(), MAC_ADDRESS_LENGTH as u8);
        assert_eq!(packet.protocol_size(), IPV4_ADDRESS_LENGTH as u8);
        assert_eq!(packet.sender_mac(), sender_mac);
        assert_eq!(packet.sender_ip(), sender_ip);
        assert_eq!(packet.target_mac(), target_mac);
        assert_eq!(packet.target_ip(), target_ip);
    }

    #[test]
    fn test_arp_request_creation() {
        let sender_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let sender_ip = Ipv4Address::new([192, 168, 1, 100]);
        let target_ip = Ipv4Address::new([192, 168, 1, 1]);

        let packet = ArpPacket::create_request(sender_mac, sender_ip, target_ip);

        assert!(packet.is_request());
        assert!(!packet.is_reply());
        assert_eq!(packet.operation(), Operation::Request);
        assert_eq!(packet.sender_mac(), sender_mac);
        assert_eq!(packet.sender_ip(), sender_ip);
        assert_eq!(packet.target_ip(), target_ip);
        // Target MAC should be zero for requests
        assert_eq!(packet.target_mac(), MacAddress::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_arp_reply_creation() {
        let sender_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let sender_ip = Ipv4Address::new([192, 168, 1, 100]);
        let target_mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let target_ip = Ipv4Address::new([192, 168, 1, 1]);

        let packet = ArpPacket::create_reply(sender_mac, sender_ip, target_mac, target_ip);

        assert!(!packet.is_request());
        assert!(packet.is_reply());
        assert_eq!(packet.operation(), Operation::Reply);
        assert_eq!(packet.sender_mac(), sender_mac);
        assert_eq!(packet.sender_ip(), sender_ip);
        assert_eq!(packet.target_mac(), target_mac);
        assert_eq!(packet.target_ip(), target_ip);
    }

    #[test]
    fn test_arp_packet_to_bytes_request() {
        let sender_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let sender_ip = Ipv4Address::new([192, 168, 1, 100]);
        let target_ip = Ipv4Address::new([192, 168, 1, 1]);

        let packet = ArpPacket::create_request(sender_mac, sender_ip, target_ip);
        let bytes = packet.to_bytes();

        assert_eq!(bytes.len(), ARP_PACKET_SIZE);
        
        // Hardware type (Ethernet = 1)
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 1);
        
        // Protocol type (IPv4 = 0x0800)
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0x0800);
        
        // Hardware size (MAC = 6)
        assert_eq!(bytes[4], 6);
        
        // Protocol size (IPv4 = 4)
        assert_eq!(bytes[5], 4);
        
        // Operation (Request = 1)
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1);
        
        // Sender MAC
        assert_eq!(&bytes[8..14], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        
        // Sender IP
        assert_eq!(&bytes[14..18], &[192, 168, 1, 100]);
        
        // Target MAC (should be zero for request)
        assert_eq!(&bytes[18..24], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        
        // Target IP
        assert_eq!(&bytes[24..28], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_arp_packet_from_bytes_valid() {
        let mut bytes = [0u8; ARP_PACKET_SIZE];
        let mut index = 0;

        // Hardware type (Ethernet)
        bytes[index..index+2].copy_from_slice(&1u16.to_be_bytes());
        index += 2;

        // Protocol type (IPv4)
        bytes[index..index+2].copy_from_slice(&0x0800u16.to_be_bytes());
        index += 2;

        // Hardware size
        bytes[index] = 6;
        index += 1;

        // Protocol size
        bytes[index] = 4;
        index += 1;

        // Operation (Reply)
        bytes[index..index+2].copy_from_slice(&2u16.to_be_bytes());
        index += 2;

        // Sender MAC
        bytes[index..index+6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        index += 6;

        // Sender IP
        bytes[index..index+4].copy_from_slice(&[192, 168, 1, 100]);
        index += 4;

        // Target MAC
        bytes[index..index+6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        index += 6;

        // Target IP
        bytes[index..index+4].copy_from_slice(&[192, 168, 1, 1]);

        let packet = ArpPacket::from_bytes(&bytes).unwrap();

        assert_eq!(packet.hardware_type(), HardwareType::Ethernet);
        assert_eq!(packet.protocol_type(), ProtocolType::Ipv4);
        assert_eq!(packet.operation(), Operation::Reply);
        assert!(packet.is_reply());
    }

    #[test]
    fn test_arp_packet_from_bytes_invalid_hardware_type() {
        let mut bytes = [0u8; ARP_PACKET_SIZE];
        // Set invalid hardware type (999)
        bytes[0..2].copy_from_slice(&999u16.to_be_bytes());
        // Set valid protocol type
        bytes[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        
        assert_eq!(ArpPacket::from_bytes(&bytes), Err(ArpError::InvalidHardwareType));
    }

    #[test]
    fn test_arp_packet_round_trip_comprehensive() {
        let sender_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let sender_ip = Ipv4Address::new([192, 168, 1, 100]);
        let target_mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let target_ip = Ipv4Address::new([192, 168, 1, 1]);

        let original = ArpPacket::create_reply(sender_mac, sender_ip, target_mac, target_ip);
        let bytes = original.to_bytes();
        let reconstructed = ArpPacket::from_bytes(&bytes).unwrap();

        // Verify all fields survived the round trip
        assert_eq!(reconstructed.hardware_type(), original.hardware_type());
        assert_eq!(reconstructed.protocol_type(), original.protocol_type());
        assert_eq!(reconstructed.operation(), original.operation());
        assert_eq!(reconstructed.sender_mac(), original.sender_mac());
        assert_eq!(reconstructed.sender_ip(), original.sender_ip());
        assert_eq!(reconstructed.target_mac(), original.target_mac());
        assert_eq!(reconstructed.target_ip(), original.target_ip());
    }

    #[test]
    fn test_is_request_for() {
        let our_ip = Ipv4Address::new([192, 168, 1, 100]);
        let other_ip = Ipv4Address::new([192, 168, 1, 200]);
        
        let packet = ArpPacket::create_request(
            MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            Ipv4Address::new([192, 168, 1, 1]),
            our_ip
        );

        assert!(packet.is_request_for(&our_ip));
        assert!(!packet.is_request_for(&other_ip));
    }

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", ArpError::InvalidPacketSize), "Invalid ARP packet size");
        assert_eq!(format!("{}", ArpError::InvalidOperation), "Invalid ARP operation");
        assert_eq!(format!("{}", ArpError::InvalidHardwareType), "Invalid hardware type");
        assert_eq!(format!("{}", ArpError::InvalidProtocolType), "Invalid protocol type");
    }
}