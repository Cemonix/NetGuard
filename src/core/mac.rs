use std::{error::Error, fmt};

use pnet::util::MacAddr;

pub const MAC_ADDRESS_LENGTH: usize = 6;

pub const MAC_ADDRESS_BROADCAST: MacAddr = MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);

#[derive(Debug, PartialEq)]
pub enum MacAddressError {
    InvalidFormat,
    InvalidLength,
}

impl fmt::Display for MacAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacAddressError::InvalidFormat => write!(f, "Invalid MAC address format"),
            MacAddressError::InvalidLength => write!(f, "MAC address must be 6 bytes long"),
        }
    }
}

impl Error for MacAddressError {}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct MacAddress {
    address: [u8; MAC_ADDRESS_LENGTH],
}

impl MacAddress {
    // Create a new MAC address from a byte array
    pub fn new(bytes: [u8; MAC_ADDRESS_LENGTH]) -> Self {
        MacAddress { address: bytes }
    }

    pub fn address(&self) -> [u8; MAC_ADDRESS_LENGTH] {
        self.address
    }

    // Parse "aa:bb:cc:dd:ee:ff" -> MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    pub fn parse(address: &str) -> Result<Self, MacAddressError> {
        let parts: Vec<&str> = address.split(':').collect();
        if parts.len() != MAC_ADDRESS_LENGTH {
            return Err(MacAddressError::InvalidLength);
        }

        let mut bytes = [0u8; MAC_ADDRESS_LENGTH];
        for (i, part) in parts.iter().enumerate() {
            if part.len() != 2 {
                return Err(MacAddressError::InvalidFormat);
            }
            bytes[i] = u8::from_str_radix(part, 16)
                .map_err(|_| MacAddressError::InvalidFormat)?;
        }

        Ok(MacAddress { address: bytes })
    }
}

impl ToString for MacAddress {
    // Convert to string "aa:bb:cc:dd:ee:ff"
    fn to_string(&self) -> String {
        self.address
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(":")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes() {
        let mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(mac.address(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_valid() {
        let mac = MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac.address(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_invalid_length() {
        let result = MacAddress::parse("aa:bb:cc:dd:ee");
        assert!(result.is_err());
        assert_eq!(result.err(), Some(MacAddressError::InvalidLength));
    }

    #[test]
    fn test_parse_invalid_format() {
        let result = MacAddress::parse("a:b:c:d:e:f");
        assert!(result.is_err());
        assert_eq!(result.err(), Some(MacAddressError::InvalidFormat));
    }

    #[test]
    fn test_to_string() {
        let mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let str_mac = mac.to_string();
        assert_eq!(str_mac, "aa:bb:cc:dd:ee:ff");
    }
}