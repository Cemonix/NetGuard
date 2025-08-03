/// Calculates the ICMP checksum for a given packet.
///
/// The checksum is computed by interpreting the packet as a sequence of 16-bit words,
/// summing them using one's complement arithmetic, and then taking the one's complement
/// of the final sum. If the packet length is odd, the last byte is padded with zero.
///
/// # Algorithm Details
///
/// 1. The packet is split into 2-byte chunks. Each chunk is converted to a `u16` in big-endian order.
///    - If a chunk has only one byte (odd-length packet), it is padded with zero as the second byte.
/// 2. Each 16-bit word is added to a 32-bit accumulator (`sum`).
/// 3. After all words are summed, any overflow from the upper 16 bits is folded back into the lower 16 bits.
///    - This is done by repeatedly adding the upper 16 bits to the lower 16 bits until no overflow remains.
/// 4. The final sum is inverted (one's complement) and returned as the checksum.
///
/// This algorithm follows the standard ICMP checksum calculation as specified in RFC 1071.
pub fn calculate_internet_checksum(packet: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in packet.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}