use std::net::{IpAddr, Ipv4Addr};

use pnet::{datalink, util::MacAddr};
use pnet::datalink::{NetworkInterface as PnetNetworkInterface};

#[derive(Debug)]
pub enum NetworkInterfaceError {
    InvalidInterface,
}

impl std::fmt::Display for NetworkInterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkInterfaceError::InvalidInterface => write!(f, "Invalid network interface"),
        }
    }
}

#[derive(Clone)]
pub struct NetworkInterface {
    interface_name: String,
}

impl NetworkInterface {
    pub fn new(interface_name: String) -> Self {
        NetworkInterface { interface_name }
    }

    pub fn interface(&self) -> Result<PnetNetworkInterface, NetworkInterfaceError> {
        let interfaces = datalink::interfaces();
        let interface = interfaces.into_iter()
            .find(|iface| iface.name == self.interface_name)
            .ok_or(NetworkInterfaceError::InvalidInterface)?;
        Ok(interface)
    }

    pub fn get_interface_info(&self) -> Result<(Ipv4Addr, MacAddr), NetworkInterfaceError> {
        let interface = self.interface()?;

        // Get ip address from the interface
        let ipv4_addr = interface.ips
            .iter()
            .find_map(|ip| match ip.ip() {
                IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .ok_or(NetworkInterfaceError::InvalidInterface)?;

        // Get mac_address from the interface
        let mac_address = match interface.mac {
            Some(mac) => mac,
            None => {
                if interface.name == "lo" {
                    MacAddr::new(0, 0, 0, 0, 0, 0) // Loopback interface has no MAC
                } else {
                    return Err(NetworkInterfaceError::InvalidInterface);
                }
            }
        };

        Ok((ipv4_addr, mac_address))
    }
}
