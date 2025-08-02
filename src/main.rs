use net_guard::discovery;
use net_guard::core::{Cidr, CidrError, Ipv4Address};

fn main() -> Result<(), Box<CidrError>> {
    let cidr = Cidr::new(Ipv4Address::new_const([192, 168, 1, 0]), 24)?;
    let addrs = cidr.network_addresses();
    println!("First: {}, Last: {}, Number of Hosts: {}", addrs[0], addrs[addrs.len()-1], addrs.len());

    // Test the new functionality
    println!("Is 192.168.1.100 private? {}", Cidr::is_private_ip(&Ipv4Address::new_const([192, 168, 1, 100])));
    println!("Is 8.8.8.8 private? {}", Cidr::is_private_ip(&Ipv4Address::new_const([8, 8, 8, 8])));

    Ok(())
}

