use crate::core::{MacAddress, MAC_ADDRESS_LENGTH};

pub const ARP_PACKET_SIZE: usize = 28; // Header (8) + Sender MAC (6) + Sender IP (4) + Target MAC (6) + Target IP (4)
pub const ARP_HEADER_SIZE: usize = 8; // Hardware type (2) + Protocol type (2) + Hardware size (1) + Protocol size (1) + Operation (2)

pub enum HardwareType {
    Ethernet
}

pub enum ProtocolType {
    Ipv4
}

pub enum Operation {
    Request,
    Reply
}

pub struct ArpPacket {
    hardware_type: HardwareType,
    hardware_size: u8,
    protocol_type: ProtocolType,
    protocol_size: u8,
    operation: Operation,
    mac_sender: MacAddress,
    ip_sender: [u8; 4],
    mac_target: MacAddress,
    ip_target: [u8; 4]
}

impl ArpPacket {
    pub fn new(
        hardware_type: HardwareType,
        protocol_type: ProtocolType,
        protocol_size: u8,
        operation: Operation,
        mac_sender: MacAddress,
        ip_sender: [u8; 4],
        mac_target: MacAddress,
        ip_target: [u8; 4]
    ) -> Self {
        ArpPacket {
            hardware_type,
            hardware_size: MAC_ADDRESS_LENGTH as u8,
            protocol_type,
            protocol_size,
            operation,
            mac_sender,
            ip_sender,
            mac_target,
            ip_target
        }
    }
}