use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use pnet::datalink::{self, channel, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::arp::{ArpPacket, MutableArpPacket, ArpHardwareTypes, ArpOperations};
use pnet::packet::{Packet, MutablePacket};
use pnet::util::MacAddr;

use crate::core::MAC_ADDRESS_BROADCAST;
use super::error::ScanError;
use super::common::{NetworkScanner, DiscoveredDevice};

#[derive(Clone)]
pub struct ArpScanner {
    interface_name: String,
    timeout: Duration,
}

impl ArpScanner {
    pub fn new(interface_name: String, timeout: Duration) -> Self {
        ArpScanner { interface_name, timeout }
    }

    fn interface(&self) -> Result<NetworkInterface, ScanError> {
        let interfaces = datalink::interfaces();
        let interface = interfaces.into_iter()
            .find(|iface| iface.name == self.interface_name)
            .ok_or(ScanError::InvalidInterface)?;
        Ok(interface)
    }

    fn get_interface_info(&self) -> Result<(Ipv4Addr, MacAddr), ScanError> {
        let interface = self.interface()?;

        // Get ip address from the interface
        let ipv4_addr = interface.ips
            .iter()
            .find_map(|ip| match ip.ip() {
                IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .ok_or(ScanError::InvalidInterface)?;

        // Get mac_address from the interface
        let mac_address = match interface.mac {
            Some(mac) => mac,
            None => {
                if interface.name == "lo" {
                    MacAddr::new(0, 0, 0, 0, 0, 0) // Loopback interface has no MAC
                } else {
                    return Err(ScanError::InvalidInterface);
                }
            }
        };

        Ok((ipv4_addr, mac_address))
    }

    fn build_arp_request_packet(
        &self,
        local_ip: Ipv4Addr,
        local_mac: MacAddr,
        target_ip: Ipv4Addr,
    ) -> Result<Vec<u8>, ScanError> {
        let mut packet_buffer = vec![0u8; 42]; // 14 bytes Ethernet + 28 bytes ARP
        {
            let mut ethernet_packet = MutableEthernetPacket::new(&mut packet_buffer)
                .ok_or(ScanError::NetworkError("Failed to create Ethernet packet".to_string()))?;

            ethernet_packet.set_destination(MAC_ADDRESS_BROADCAST);
            ethernet_packet.set_source(local_mac);
            ethernet_packet.set_ethertype(EtherTypes::Arp);

            let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut())
                .ok_or(ScanError::NetworkError("Failed to create ARP packet".to_string()))?;

            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Request);
            arp_packet.set_sender_hw_addr(local_mac);
            arp_packet.set_sender_proto_addr(local_ip);
            arp_packet.set_target_hw_addr(MacAddr::new(0, 0, 0, 0, 0, 0));
            arp_packet.set_target_proto_addr(target_ip);
        }
        Ok(packet_buffer)
    }

    async fn send_arp_request(&self, target_ip: Ipv4Addr) -> Result<Option<(MacAddr, Ipv4Addr)>, ScanError> {
        let interface = self.interface()?;
        let channel = match channel(&interface, Default::default()) {
            Ok(channel) => channel,
            Err(e) => return Err(ScanError::NetworkError(e.to_string())),
        };

        let (mut sender, mut receiver) = match channel {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => return Err(ScanError::NetworkError("Unsupported channel type".to_string())),
        };

        let (local_ip, local_mac) = self.get_interface_info()?;

        let packet_buffer = self.build_arp_request_packet(local_ip, local_mac, target_ip)?;

        // Send the packet
        match sender.send_to(packet_buffer.as_slice(), None) {
            Some(result) => match result {
                Ok(_) => {},
                Err(e) => return Err(ScanError::NetworkError(format!("Failed to send packet: {}", e))),
            },
            None => return Err(ScanError::NetworkError("Failed to send packet".to_string())),
        }

        // Listen for responses with timeout
        let start_time = Instant::now();
        
        while start_time.elapsed() < self.timeout {
            match receiver.next() {
                Ok(packet) => {
                    if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                        if ethernet_packet.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp_response) = ArpPacket::new(ethernet_packet.payload()) {
                                // Check if this is a reply to our request
                                if arp_response.get_operation() == ArpOperations::Reply &&
                                   arp_response.get_sender_proto_addr() == target_ip {
                                    return Ok(Some((arp_response.get_sender_hw_addr(), arp_response.get_sender_proto_addr())));
                                }
                            }
                        }
                    }
                },
                Err(_) => continue,
            }
        }

        Ok(None) // Timeout
    }
}

#[async_trait::async_trait]
impl NetworkScanner for ArpScanner {
    type Result = DiscoveredDevice;

    async fn scan_ip(&self, target_ip: Ipv4Addr) -> Result<Option<Self::Result>, ScanError> {
        let start_time = Instant::now();

        if let Some((mac_address, ipv4_address)) = self.send_arp_request(target_ip).await? {
            Ok(Some(DiscoveredDevice { 
                ip: ipv4_address, 
                mac: mac_address, 
                response_time: start_time.elapsed() 
            }))
        } else {
            Ok(None)
        }
    }
}