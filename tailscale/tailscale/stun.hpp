#pragma once

// Windows compatibility
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include "netcheck.hpp"
#include <random>
#include <cstring>

namespace netcheck {

// STUN message types
namespace stun_types {
    constexpr uint16_t binding_request = 0x0001;
    constexpr uint16_t binding_response = 0x0101;
}

// STUN attributes
namespace stun_attrs {
    constexpr uint16_t mapped_address = 0x0001;
    constexpr uint16_t xor_mapped_address = 0x0020;
    constexpr uint16_t software = 0x8022;
    constexpr uint16_t fingerprint = 0x8028;
}

// STUN magic cookie
constexpr uint32_t stun_magic_cookie = 0x2112A442;

// STUN FINGERPRINT XOR value (RFC 5389)
constexpr uint32_t fingerprint_xor = 0x5354554e;

// Tailscale SOFTWARE string
constexpr const char* tailscale_software = "tailnode";

STUNTxID::STUNTxID() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    
    uint64_t part1 = dis(gen);
    uint32_t part2 = static_cast<uint32_t>(dis(gen));
    
    std::memcpy(data_, &part1, 8);
    std::memcpy(data_ + 8, &part2, 4);
}

STUNTxID::STUNTxID(const uint8_t* data) {
    std::memcpy(data_, data, 12);
}

bool STUNTxID::operator<(const STUNTxID& other) const {
    return std::memcmp(data_, other.data_, 12) < 0;
}

bool STUNTxID::operator==(const STUNTxID& other) const {
    return std::memcmp(data_, other.data_, 12) == 0;
}

namespace stun {

inline void write_u16(uint8_t* buf, uint16_t val) {
    buf[0] = (val >> 8) & 0xFF;
    buf[1] = val & 0xFF;
}

inline void write_u32(uint8_t* buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

inline uint16_t read_u16(const uint8_t* buf) {
    return (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
}

inline uint32_t read_u32(const uint8_t* buf) {
    return (static_cast<uint32_t>(buf[0]) << 24) |
           (static_cast<uint32_t>(buf[1]) << 16) |
           (static_cast<uint32_t>(buf[2]) << 8) |
           buf[3];
}

// CRC32 calculation for STUN FINGERPRINT
// Uses standard CRC32 polynomial (0xEDB88320)
inline uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc = crc >> 1;
            }
        }
    }
    
    return crc ^ 0xFFFFFFFF;
}

// Create a STUN binding request
// Tailscale includes SOFTWARE ("tailnode") and FINGERPRINT attributes
std::vector<uint8_t> CreateRequest(const STUNTxID& tx_id) {
    const char* software_str = tailscale_software;
    const size_t software_len = std::strlen(software_str); // "tailnode" = 8 bytes
    
    // Calculate padded lengths (align to 4-byte boundary)
    const uint16_t software_padded = ((software_len + 3) & ~3); // 8 bytes (no padding needed)
    
    // Message length includes ALL attributes (SOFTWARE + FINGERPRINT)
    // SOFTWARE: 4 bytes header + 8 bytes value = 12 bytes
    // FINGERPRINT: 4 bytes header + 4 bytes value = 8 bytes
    // Total: 20 bytes
    const uint16_t msg_length = 4 + software_padded + 8;
    
    // Total packet size: header + attributes
    const size_t total_packet_size = 20 + msg_length;
    
    std::vector<uint8_t> packet(total_packet_size);
    
    // Message type (Binding Request)
    write_u16(packet.data(), stun_types::binding_request);
    
    // Message length (includes all attributes - this stays as-is for CRC!)
    write_u16(packet.data() + 2, msg_length);
    
    // Magic cookie
    write_u32(packet.data() + 4, stun_magic_cookie);
    
    // Transaction ID (12 bytes)
    std::memcpy(packet.data() + 8, tx_id.data(), 12);
    
    size_t offset = 20;
    
    // Add SOFTWARE attribute
    write_u16(packet.data() + offset, stun_attrs::software);
    offset += 2;
    write_u16(packet.data() + offset, static_cast<uint16_t>(software_len));
    offset += 2;
    std::memcpy(packet.data() + offset, software_str, software_len);
    offset += software_len;
    
    // Add padding if needed (for "tailnode", no padding needed as it's 8 bytes)
    size_t padding = software_padded - software_len;
    offset += padding;
    
    // Now offset should be at 32 (20 header + 4 attr header + 8 value)
    
    // Calculate FINGERPRINT
    // Per RFC 5389, CRC-32 is computed over the message up to (but excluding)
    // the FINGERPRINT attribute itself, using the CURRENT length field value
    // (which already includes the FINGERPRINT attribute in the count).
    //
    // Key insight: We do NOT adjust the length field!
    
    uint32_t crc = crc32(packet.data(), offset);
    
    // XOR with STUN magic value per RFC 5389
    uint32_t fingerprint = crc ^ fingerprint_xor;
    
    // Add FINGERPRINT attribute
    write_u16(packet.data() + offset, stun_attrs::fingerprint);
    offset += 2;
    write_u16(packet.data() + offset, 4); // FINGERPRINT value is always 4 bytes
    offset += 2;
    write_u32(packet.data() + offset, fingerprint);
    
    return packet;
}

// Parse a STUN binding response
// Returns true if successful and sets out_tx_id and out_endpoint
// Tailscale DERP servers may include SOFTWARE attribute in responses
bool ParseResponse(const uint8_t* data, size_t size,
                   STUNTxID& out_tx_id,
                   asio::ip::udp::endpoint& out_endpoint) {
    if (size < 20) {
        return false;
    }
    
    // Check message type
    uint16_t msg_type = read_u16(data);
    if (msg_type != stun_types::binding_response) {
        return false;
    }
    
    // Check magic cookie
    uint32_t cookie = read_u32(data + 4);
    if (cookie != stun_magic_cookie) {
        return false;
    }
    
    // Extract transaction ID
    out_tx_id = STUNTxID(data + 8);
    
    // Parse message length
    uint16_t msg_length = read_u16(data + 2);
    if (size < 20 + msg_length) {
        return false;
    }
    
    // Parse attributes
    size_t offset = 20;
    bool found_address = false;
    
    while (offset + 4 <= size && offset < 20 + msg_length) {
        uint16_t attr_type = read_u16(data + offset);
        uint16_t attr_length = read_u16(data + offset + 2);
        
        // Ensure we have enough data
        if (offset + 4 + attr_length > size) {
            break;
        }
        
        const uint8_t* attr_data = data + offset + 4;
        
        if (attr_type == stun_attrs::xor_mapped_address) {
            // XOR-MAPPED-ADDRESS
            if (attr_length >= 8) {
                uint8_t family = attr_data[1];
                uint16_t xor_port = read_u16(attr_data + 2);
                uint16_t port = xor_port ^ (stun_magic_cookie >> 16);
                
                if (family == 0x01) { // IPv4
                    uint32_t xor_addr = read_u32(attr_data + 4);
                    uint32_t addr = xor_addr ^ stun_magic_cookie;
                    
                    asio::ip::address_v4::bytes_type bytes;
                    bytes[0] = (addr >> 24) & 0xFF;
                    bytes[1] = (addr >> 16) & 0xFF;
                    bytes[2] = (addr >> 8) & 0xFF;
                    bytes[3] = addr & 0xFF;
                    
                    out_endpoint = asio::ip::udp::endpoint(
                        asio::ip::make_address_v4(bytes), port);
                    found_address = true;
                    break;
                } else if (family == 0x02 && attr_length >= 20) { // IPv6
                    uint8_t xor_key[16];
                    write_u32(xor_key, stun_magic_cookie);
                    std::memcpy(xor_key + 4, out_tx_id.data(), 12);
                    
                    asio::ip::address_v6::bytes_type bytes;
                    for (int i = 0; i < 16; i++) {
                        bytes[i] = attr_data[4 + i] ^ xor_key[i];
                    }

                    auto ipv6_address = asio::ip::make_address_v6(bytes);

                    if (ipv6_address.is_v4_mapped()) {

                        asio::ip::address_v4 v4_addr(
                            (uint32_t(bytes[12]) << 24) |
                            (uint32_t(bytes[13]) << 16) |
                            (uint32_t(bytes[14]) << 8) |
                            uint32_t(bytes[15])
                        );

                        out_endpoint = asio::ip::udp::endpoint(
                            v4_addr, port);
                    }
                    else {      
                        out_endpoint = asio::ip::udp::endpoint(
                            ipv6_address, port);
                    }                    

                    found_address = true;
                    break;
                }
            }
        } else if (attr_type == stun_attrs::mapped_address) {
            // MAPPED-ADDRESS (fallback, less common)
            if (attr_length >= 8) {
                uint8_t family = attr_data[1];
                uint16_t port = read_u16(attr_data + 2);
                
                if (family == 0x01) { // IPv4
                    asio::ip::address_v4::bytes_type bytes;
                    std::memcpy(bytes.data(), attr_data + 4, 4);
                    
                    out_endpoint = asio::ip::udp::endpoint(
                        asio::ip::make_address_v4(bytes), port);
                    found_address = true;
                    break;
                } else if (family == 0x02 && attr_length >= 20) { // IPv6
                    asio::ip::address_v6::bytes_type bytes;
                    std::memcpy(bytes.data(), attr_data + 4, 16);
                    
                    out_endpoint = asio::ip::udp::endpoint(
                        asio::ip::make_address_v6(bytes), port);
                    found_address = true;
                    break;
                }
            }
        }
        
        // Move to next attribute (with padding to 4-byte boundary)
        offset += 4 + ((attr_length + 3) & ~3);
    }
    
    return found_address;
}

} // namespace stun
} // namespace netcheck
