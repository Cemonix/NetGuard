use crate::core::NetworkInterfaceError;

/// Common error type for all network scanners
#[derive(Debug)]
pub enum ScanError {
    NetworkError(String),
    Timeout,
    PermissionDenied,
    InvalidTarget,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            ScanError::Timeout => write!(f, "Scan timed out"),
            ScanError::PermissionDenied => write!(f, "Permission denied"),
            ScanError::InvalidTarget => write!(f, "Invalid target"),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<NetworkInterfaceError> for ScanError {
    fn from(err: NetworkInterfaceError) -> Self {
        match err {
            NetworkInterfaceError::InvalidInterface => ScanError::NetworkError("Invalid network interface".to_string()),
        }
    }
}

#[derive(Debug)]
pub enum PacketError {
    CreationFailed(String),
    SendFailed(String),
    ReceiveFailed(String),
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::CreationFailed(msg) => write!(f, "Packet creation failed: {}", msg),
            PacketError::SendFailed(msg) => write!(f, "Packet send failed: {}", msg),
            PacketError::ReceiveFailed(msg) => write!(f, "Packet receive failed: {}", msg),
        }
    }
}

impl std::error::Error for PacketError {}

impl Into<ScanError> for PacketError {
    fn into(self) -> ScanError {
        match self {
            PacketError::CreationFailed(msg) => ScanError::NetworkError(format!("Packet creation failed: {}", msg)),
            PacketError::SendFailed(msg) => ScanError::NetworkError(format!("Packet send failed: {}", msg)),
            PacketError::ReceiveFailed(msg) => ScanError::NetworkError(format!("Packet receive failed: {}", msg)),
        }
    }
}