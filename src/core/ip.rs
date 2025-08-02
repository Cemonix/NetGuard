use std::error::Error;
use std::fmt;
use std::ops::Index;

pub const IPV4_ADDRESS_LENGTH: usize = 4;

#[derive(Debug, PartialEq)]
pub enum IpAddressError {
    InvalidFormat,
    ParseError,
}

impl fmt::Display for IpAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddressError::InvalidFormat => write!(f, "Invalid IP address format"),
            IpAddressError::ParseError => write!(f, "Failed to parse IP address"),
        }
    }
}

impl Error for IpAddressError {}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Ipv4Address {
    address: [u8; IPV4_ADDRESS_LENGTH],
}

impl Ipv4Address {
    pub const fn new_const(address: [u8; IPV4_ADDRESS_LENGTH]) -> Self {
        Ipv4Address { address }
    }

    pub fn new(address: [u8; IPV4_ADDRESS_LENGTH]) -> Self {
        Ipv4Address { address }
    }

    pub fn address(&self) -> [u8; IPV4_ADDRESS_LENGTH] {
        self.address
    }

    pub fn parse(ip_str: &str) -> Result<Self, IpAddressError> {
        let parts: Vec<&str> = ip_str.split('.').collect();
        if parts.len() != IPV4_ADDRESS_LENGTH {
            return Err(IpAddressError::InvalidFormat);
        }
        let mut address = [0u8; IPV4_ADDRESS_LENGTH];
        for (i, part) in parts.iter().enumerate() {
            match part.parse::<u8>() {
                Ok(num) => address[i] = num,
                Err(_) => return Err(IpAddressError::ParseError),
            }
        }
        Ok(Ipv4Address::new(address))
    }
}

impl ToString for Ipv4Address {
    fn to_string(&self) -> String {
        self.address
            .iter()
            .map(|byte| byte.to_string())
            .collect::<Vec<String>>()
            .join(".")
    }
}

impl Index<usize> for Ipv4Address {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        if index >= IPV4_ADDRESS_LENGTH {
            panic!("Index out of bounds");
        }
        &self.address[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_address_new() {
        let ip = Ipv4Address::new([192, 168, 1, 1]);
        assert_eq!(ip.address(), [192, 168, 1, 1]);
    }

    #[test]
    fn test_ipv4_address_parse_valid() {
        let ip = Ipv4Address::parse("192.168.1.1");
        assert!(ip.is_ok());
        assert_eq!(ip.unwrap().address(), [192, 168, 1, 1]);
    }

    #[test]
    fn test_ipv4_address_parse_invalid_format() {
        let ip = Ipv4Address::parse("192.168.1");
        assert!(ip.is_err());
        assert_eq!(ip.err(), Some(IpAddressError::InvalidFormat));
    }

    #[test]
    fn test_ipv4_address_parse_invalid_value() {
        let ip = Ipv4Address::parse("192.168.1.256");
        assert!(ip.is_err());
        assert_eq!(ip.err(), Some(IpAddressError::ParseError));
    }

    #[test]
    fn test_ipv4_address_to_string() {
        let ip = Ipv4Address::new([192, 168, 1, 1]);
        assert_eq!(ip.to_string(), "192.168.1.1");

        let ip = Ipv4Address::new([0, 0, 0, 0]);
        assert_eq!(ip.to_string(), "0.0.0.0");

        let ip = Ipv4Address::new([255, 255, 255, 255]);
        assert_eq!(ip.to_string(), "255.255.255.255");

        let ip = Ipv4Address::new([10, 0, 0, 1]);
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_ipv4_address_indexing() {
        let ip = Ipv4Address::new([192, 168, 1, 1]);
        assert_eq!(ip[0], 192);
        assert_eq!(ip[1], 168);
        assert_eq!(ip[2], 1);
        assert_eq!(ip[3], 1);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_ipv4_address_indexing_out_of_bounds() {
        let ip = Ipv4Address::new([192, 168, 1, 1]);
        let _ = ip[4]; // This should panic
    }
}