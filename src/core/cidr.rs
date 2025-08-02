use std::{fmt, str::FromStr};

use crate::core::{ IPV4_ADDRESS_LENGTH, Ipv4Address };

pub const OCTET_LEN: u8 = 8;
pub const PREFIX_MAX: u8 = 32;

// Standard CIDR networks
pub const RFC_A: Cidr = Cidr::new_const(
    Ipv4Address::new_const([10, 0, 0, 0]), 8
);
pub const RFC_B: Cidr = Cidr::new_const(
    Ipv4Address::new_const([172, 16, 0, 0]), 12
);
pub const RFC_C: Cidr = Cidr::new_const(
    Ipv4Address::new_const([192, 168, 0, 0]), 16
);
pub const LOOPBACK: Cidr = Cidr::new_const(
    Ipv4Address::new_const([127, 0, 0, 0]), 8
);
pub const LINK_LOCAL: Cidr = Cidr::new_const(
    Ipv4Address::new_const([169, 254, 0, 0]), 16
);
pub const MULTICAST: Cidr = Cidr::new_const(
    Ipv4Address::new_const([224, 0, 0, 0]), 4
);

#[derive(Debug, PartialEq)]
pub enum CidrError {
    InvalidIpFormat,
    InvalidOctet,
    InvalidPrefixLength,
}

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CidrError::InvalidIpFormat => write!(f, "Invalid IP address format"),
            CidrError::InvalidOctet => write!(f, "Invalid octet value"),
            CidrError::InvalidPrefixLength => write!(f, "Invalid prefix length"),
        }
    }
}

impl std::error::Error for CidrError {}

#[derive(Debug, PartialEq)]
pub enum StandardNetwork {
    RfcA,
    RfcB,
    RfcC,
    Loopback,
    LinkLocal,
    Multicast,
}

impl StandardNetwork {
    pub fn get_cidr(&self) -> &'static Cidr {
        match self {
            StandardNetwork::RfcA => &RFC_A,
            StandardNetwork::RfcB => &RFC_B,
            StandardNetwork::RfcC => &RFC_C,
            StandardNetwork::Loopback => &LOOPBACK,
            StandardNetwork::LinkLocal => &LINK_LOCAL,
            StandardNetwork::Multicast => &MULTICAST,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Cidr {
    network: Ipv4Address, // Network address in CIDR notation
    prefix_len: u8,       // Number of bits in the prefix
}

impl Cidr {
    pub const fn new_const(network: Ipv4Address, prefix_len: u8) -> Self {
        Cidr { network, prefix_len }
    }

    pub fn new(network: Ipv4Address, prefix_len: u8) -> Result<Self, CidrError> {
        if prefix_len > PREFIX_MAX {
            return Err(CidrError::InvalidPrefixLength);
        }

        Ok(Cidr { network, prefix_len })
    }

    pub fn network(&self) -> &Ipv4Address {
        &self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn is_private_ip(ip: &Ipv4Address) -> bool {
        let octets = ip.address();

        match octets[0] {
            10 => true,                                         // 10.0.0.0/8
            127 => true,                                        // 127.0.0.0/8
            172 if octets[1] >= 16 && octets[1] <= 31 => true,  // 172.16.0.0/12
            192 if octets[1] == 168 => true,                    // 192.168.0.0/16
            169 if octets[1] == 254 => true,                    // 169.254.0.0/16
            224..=239 => true,                                  // 224.0.0.0/4
            _ => false,
        }
    }

    pub fn classify_ip(ip: &Ipv4Address) -> Option<StandardNetwork> {
        if RFC_A.contains(ip).unwrap_or(false) { Some(StandardNetwork::RfcA) }
        else if RFC_B.contains(ip).unwrap_or(false) { Some(StandardNetwork::RfcB) }
        else if RFC_C.contains(ip).unwrap_or(false) { Some(StandardNetwork::RfcC) }
        else if LOOPBACK.contains(ip).unwrap_or(false) { Some(StandardNetwork::Loopback) }
        else if LINK_LOCAL.contains(ip).unwrap_or(false) { Some(StandardNetwork::LinkLocal) }
        else if MULTICAST.contains(ip).unwrap_or(false) { Some(StandardNetwork::Multicast) }
        else { None }
    }

    pub fn mask(&self) -> [u8; 4] {
        let mut mask = [0; 4];
        let full_bytes = self.prefix_len / OCTET_LEN;
        let remaining_bits = self.prefix_len % OCTET_LEN;

        for i in 0..full_bytes {
            mask[i as usize] = 255; // Full byte
        }

        if remaining_bits > 0 {
            // Set the remaining bits in the last byte
            // For example, if prefix_len is 25, we need to set the first 7 bits of the last byte
            // mask: 00000001 result: 10000000 | 11111111 << (8 - 1)
            // we move all the ones to the left by 7, so only the last one remains
            mask[full_bytes as usize] = 255 << (OCTET_LEN - remaining_bits);
        }

        mask
    }

    pub fn contains(&self, ip: &Ipv4Address) -> Result<bool, CidrError> {
        let mask = self.mask();

        let ip_bits = ip.address();

        for i in 0..IPV4_ADDRESS_LENGTH {
            if (ip_bits[i] & mask[i]) != (self.network[i] & mask[i]) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn network_addresses(&self) -> Vec<String> {
        let host_bits = 32 - self.prefix_len as u32;
        let host_count = u32::pow(2, host_bits) - 2; // Exclude network and broadcast
        
        let mask = self.mask();
        
        let mut addresses = Vec::with_capacity(host_count as usize);
        for i in 1..=host_count { // Start from 1 to skip network address
            let mut host = [0u8; IPV4_ADDRESS_LENGTH];
            
            // Start with the network address (apply mask)
            // Add the host number i to the network address
            // We need to distribute the 32-bit value i across 4 octets
            // Octet 3 is the least significant byte (rightmost) so we take last byte of i
            // i = 1111 0000 0110 0000 0000 0101 0000 0000 1101 & 0000 0000 0000 0000 0000 0000 0000 1111 (0xFF) = 0000 0000 0000 0000 0000 0000 0000 1101
            // then we shift i to right by octet_len so we get:
            // i = 0000 0000 1111 0000 0110 0000 0000 0101 | 0000 0000 1101 (these are out) & 0xFF = 0000 0000 0000 0000 0000 0000 0000 0101
            for octet in 0..IPV4_ADDRESS_LENGTH {
                let curr_octet = 3 - octet;
                host[curr_octet] = self.network[curr_octet] & mask[curr_octet];
                host[curr_octet] |= ((i >> (octet * OCTET_LEN as usize)) & 0xFF) as u8;
            }

            let addr_str = Ipv4Address::new(host).to_string();
            addresses.push(addr_str);
        }
        addresses
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network.to_string(), self.prefix_len)
    }
}

impl FromStr for Cidr {
    type Err = CidrError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(CidrError::InvalidIpFormat);
        }
        
        let prefix_len = parts[1].parse().map_err(|_| CidrError::InvalidPrefixLength)?;
        let network_str = parts[0];
        let network = Ipv4Address::parse(network_str)
            .map_err(|_| CidrError::InvalidIpFormat)?;
        Ok(Cidr { network, prefix_len })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_new() {
        let cidr = Cidr::new(
            Ipv4Address::new([192, 168, 1, 0]), 24
        );
        assert!(cidr.is_ok());
        let cidr = cidr.unwrap();
        assert_eq!(cidr.network(), &Ipv4Address::new([192, 168, 1, 0]));
        assert_eq!(cidr.prefix_len(), 24);
    }

    #[test]
    fn test_cidr_invalid_prefix_length() {
        let cidr = Cidr::new(
            Ipv4Address::new([192, 168, 1, 0]), 33
        );
        assert!(cidr.is_err());
        assert_eq!(cidr.err(), Some(CidrError::InvalidPrefixLength));
    }

    #[test]
    fn test_cidr_mask() {
        let cidr = Cidr::new(
            Ipv4Address::new([192, 168, 1, 0]), 24
        );
        assert!(cidr.is_ok());
        let cidr = cidr.unwrap();

        assert_eq!(cidr.mask(), [255, 255, 255, 0]);
    }

    #[test]
    fn test_cidr_contains() {
        let cidr = Cidr::new(
            Ipv4Address::new([192, 168, 1, 0]), 24
        );
        assert!(cidr.is_ok());
        let cidr = cidr.unwrap();

        let ip = Ipv4Address::new([192, 168, 1, 1]);
        assert!(cidr.contains(&ip).unwrap());
    }

    #[test]
    fn test_cidr_not_contains() {
        let cidr = Cidr::new(
            Ipv4Address::new([192, 168, 1, 0]), 24
        );
        assert!(cidr.is_ok());
        let cidr = cidr.unwrap();

        let ip = Ipv4Address::new([192, 169, 1, 1]);
        assert!(!cidr.contains(&ip).unwrap());
    }

    #[test]
    fn test_cidr_network_addresses() {
        let cidr = Cidr::new(
            Ipv4Address::new([192, 168, 1, 0]), 24
        );
        assert!(cidr.is_ok());
        let cidr = cidr.unwrap();

        let addresses = cidr.network_addresses();
        assert_eq!(addresses.len(), 254);
        assert_eq!(addresses[0], "192.168.1.1");
        assert_eq!(addresses[253], "192.168.1.254");
    }

    #[test]
    fn test_cidr_display() {
        let cidr = Cidr::new(
            Ipv4Address::new([192, 168, 1, 0]), 24
        );
        assert!(cidr.is_ok());
        let cidr = cidr.unwrap();

        let display = format!("{}", cidr);
        assert_eq!(display, "192.168.1.0/24");
    }

    #[test]
    fn test_cidr_from_str() {
        let cidr: Cidr = "192.168.1.0/24".parse().unwrap();
        assert_eq!(cidr.network(), &Ipv4Address::new([192, 168, 1, 0]));
        assert_eq!(cidr.prefix_len(), 24);
    }

    #[test]
    fn test_cidr_is_private_ip() {
        assert!(Cidr::is_private_ip(&Ipv4Address::new([192, 168, 1, 1])));
        assert!(!Cidr::is_private_ip(&Ipv4Address::new([8, 8, 8, 8])));
    }

    #[test]
    fn test_cidr_classify_ip() {
        assert_eq!(Cidr::classify_ip(&Ipv4Address::new([192, 168, 1, 1])), Some(StandardNetwork::RfcC));
        assert_eq!(Cidr::classify_ip(&Ipv4Address::new([8, 8, 8, 8])), None);
    }

    #[test]
    fn test_standard_networks() {
        assert_eq!(StandardNetwork::RfcA.get_cidr(), &RFC_A);
        assert_eq!(StandardNetwork::RfcB.get_cidr(), &RFC_B);
        assert_eq!(StandardNetwork::RfcC.get_cidr(), &RFC_C);
        assert_eq!(StandardNetwork::Loopback.get_cidr(), &LOOPBACK);
        assert_eq!(StandardNetwork::LinkLocal.get_cidr(), &LINK_LOCAL);
        assert_eq!(StandardNetwork::Multicast.get_cidr(), &MULTICAST);
    }
}
