use std::net::Ipv4Addr;
use std::time::Duration;
use net_guard::discovery::NetworkScanner;
use net_guard::core::Cidr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test single IP scan
    println!("=== Testing Single IP Scan ===");
    let scanner = NetworkScanner::new("wlp4s0".to_string(), Duration::from_millis(1000));
    
    // Try scanning common gateway addresses
    let test_ips = vec![
        Ipv4Addr::new(192, 168, 1, 1),   // Common router
        Ipv4Addr::new(192, 168, 0, 1),   // Alternative router
        Ipv4Addr::new(10, 0, 0, 1),      // Another common router
    ];
    
    for ip in test_ips {
        print!("Scanning {}... ", ip);
        match scanner.scan_ip(ip).await {
            Ok(Some(device)) => {
                println!("✅ Found! MAC: {}, Response: {:?}", device.mac, device.response_time);
            }
            Ok(None) => println!("❌ No response"),
            Err(e) => println!("🚫 Error: {:?}", e),
        }
    }
    
    // Test network scan (small range to be nice to your network)
    println!("\n=== Testing Network Scan ===");
    let cidr = Cidr::new(Ipv4Addr::new(192, 168, 0, 1), 28)?; // Only 16 IPs: .0-.15
    println!("Scanning network {} (16 addresses)...", cidr);

    match scanner.scan_network(&cidr).await {
        Ok(devices) => {
            println!("🎉 Discovered {} devices:", devices.len());
            for device in devices {
                println!("  📱 {} -> {} ({}ms)", 
                    device.ip, 
                    device.mac, 
                    device.response_time.as_millis()
                );
            }
        }
        Err(e) => println!("🚫 Network scan error: {:?}", e),
    }
    
    Ok(())
}

