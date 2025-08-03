use std::net::Ipv4Addr;
use std::time::Duration;
use std::str::FromStr;
use net_guard::discovery::{NetworkDiscovery, PingScanner};
use net_guard::discovery::scanners::NetworkScanner;
use net_guard::core::Cidr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️  NetGuard - Network Scanner");
    println!("=====================================");

    // Configuration - adjust these for your network
    let interface = "wlp4s0".to_string(); // Change to your interface (eth0, wlan0, etc.)
    let timeout = Duration::from_millis(1000);
    
    // Test single IP addresses first
    println!("\n🎯 Testing Single IP Scans");
    println!("---------------------------");
    
    let test_ips = vec![
        Ipv4Addr::new(192, 168, 0, 1),   // Common router IP
        Ipv4Addr::new(8, 8, 8, 8),       // Google DNS (for ping test)
        Ipv4Addr::new(1, 1, 1, 1),       // Cloudflare DNS (for ping test)
    ];

    // Create discovery orchestrator
    let discovery = NetworkDiscovery::new(interface.clone(), timeout);
    
    for ip in test_ips {
        println!("\nTesting IP: {}", ip);
        
        // ARP scan (only works for local network)
        if Cidr::is_private_ip(&ip) {
            print!("  📡 ARP scan: ");
            match discovery.scan_ip_arp(ip).await {
                Ok(Some(device)) => {
                    println!("✅ Found! MAC: {}, Time: {}ms", 
                        device.mac, device.response_time.as_millis());
                }
                Ok(None) => println!("❌ No response"),
                Err(e) => println!("🚫 Error: {}", e),
            }
        } else {
            println!("  📡 ARP scan: ⏭️  Skipped (not local network)");
        }
        
        // ICMP ping scan (works for any reachable IP)
        print!("  🏓 ICMP ping: ");
        match discovery.scan_ip_ping(ip).await {
            Ok(Some(result)) => {
                println!("✅ Alive! Time: {}ms, TTL: {:?}", 
                    result.response_time.as_millis(), result.ttl);
            }
            Ok(None) => println!("❌ No response"),
            Err(e) => println!("🚫 Error: {}", e),
        }
    }

    // Network range scanning
    println!("\n🌐 Network Range Scanning");
    println!("---------------------------");
    
    // Small range for testing - adjust network and range for your setup
    let test_networks = vec![
        ("192.168.1.0/29", "Small local range (.1-.6)"),
        ("192.168.0.0/29", "Alternative range (.1-.6)"),
    ];
    
    for (cidr_str, description) in test_networks {
        println!("\nScanning {} - {}", cidr_str, description);

        match Cidr::from_str(cidr_str) {
            Ok(cidr) => {
                // ARP network scan
                print!("  📡 ARP scan: ");
                match discovery.scan_network_arp(&cidr).await {
                    Ok(devices) => {
                        println!("Found {} devices", devices.len());
                        for device in devices {
                            println!("    📱 {} -> {} ({}ms)", 
                                device.ip, device.mac, device.response_time.as_millis());
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
                
                // ICMP ping network scan 
                print!("  🏓 ICMP scan: ");
                match discovery.scan_network_ping(&cidr).await {
                    Ok(results) => {
                        println!("Found {} hosts", results.len());
                        for result in results {
                            println!("    💻 {} alive ({}ms, TTL: {:?})", 
                                result.ip, result.response_time.as_millis(), result.ttl);
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }
            Err(_) => println!("  ⚠️  Invalid network format: {}", cidr_str),
        }
    }

    // Demonstrate configurable ping scanner
    println!("\n⚙️  Advanced Ping Scanner Configuration");
    println!("--------------------------------------");
    
    let custom_ping_scanner = PingScanner::new(Duration::from_millis(500))
        .with_packet_size(64)        // Larger payload 
        .with_buffer_size(8192)      // Bigger buffer for faster scanning
        .with_sequence_start(42);    // Custom sequence number
    
    let test_ip = Ipv4Addr::new(8, 8, 8, 8);
    println!("Testing custom ping scanner on {}", test_ip);
    
    match custom_ping_scanner.scan_ip(test_ip).await {
        Ok(Some(result)) => {
            println!("✅ Custom ping successful! Time: {}ms", 
                result.response_time.as_millis());
        }
        Ok(None) => println!("❌ Custom ping timeout"),
        Err(e) => println!("🚫 Custom ping error: {}", e),
    }

    println!("\n🎉 Scanning complete!");
    println!("\n💡 Tips:");
    println!("   • Run with sudo for raw socket access");
    println!("   • Adjust interface name for your system");
    println!("   • ARP only works on local network");
    println!("   • ICMP ping works across routers");
    
    Ok(())
}
