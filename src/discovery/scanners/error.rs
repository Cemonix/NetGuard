/// Common error type for all network scanners
#[derive(Debug)]
pub enum ScanError {
    NetworkError(String),
    Timeout,
    PermissionDenied,
    InvalidInterface,
    InvalidTarget,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            ScanError::Timeout => write!(f, "Scan timed out"),
            ScanError::PermissionDenied => write!(f, "Permission denied"),
            ScanError::InvalidInterface => write!(f, "Invalid network interface"),
            ScanError::InvalidTarget => write!(f, "Invalid target"),
        }
    }
}

impl std::error::Error for ScanError {}