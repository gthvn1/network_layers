const std = @import("std");

const h = @import("helper.zig");

// +--------------------------------------------------------+
// | Ethernet Header (14 bytes standard)                    |
// |--------------------------------------------------------|
// | Destination MAC (6) | Source MAC (6) | EtherType (2)   |
// +--------------------------------------------------------+
//
// +--------------------------------------------------------+
// | ARP Payload (28 bytes standard for Ethernet/IPv4)      |
// |--------------------------------------------------------|
// | HTYPE (2) | PTYPE (2) | HLEN (1) | PLEN (1) | OPER (2) |
// | SHA (6) | SPA (4) | THA (6) | TPA (4)                  |
// +--------------------------------------------------------+
//
// Ethernet II layout begins with:
//   Destination MAC: 6 bytes
//   Source MAC: 6 bytes
//   EtherType: 2 bytes (0x0806 -> ARP)
//
// [RFC ARP] https://datatracker.ietf.org/doc/html/rfc826
//
// Here is an example of what we are receiving from arping:
// ff ff ff ff ff ff  -> ETHERNET: broadcast
// f2 4e 68 82 e2 1b  -> ETHERNET: sender's MAC address
// 08 06              -> ETHERNET: ARP protocol
//
// 00 01              -> ARP: Hardware type
// 08 00              -> ARP: Protocl type
// 06                 -> ARP: Hardware size
// 04                 -> ARP: Protocol size
// 00 01              -> ARP: Opcode
// f2 4e 68 82 e2 1b  -> ARP: Sender MAC
// c0 a8 26 02        -> ARP: Sender IP
// ff ff ff ff ff ff  -> ARP: Target MAC
// c0 a8 26 03        -> ARP: Target IP
//
// https://en.wikipedia.org/wiki/Address_Resolution_Protocol
pub const ArpOper = enum(u16) {
    request = 1,
    reply = 2,
};

pub const ArpPacket = struct {
    hw_type: u16, // Hardware type (1 = Ethernet)
    proto_type: u16, // Protocol type (0x0800 = IPv4)
    hw_addr_len: u8, // Hardware address length (6 for MAC)
    proto_addr_len: u8, // Protocol address length (4 for IPv4)
    operation: ArpOper,
    sender_mac: [6]u8, // Sender MAC address
    sender_ip: [4]u8, // Sender IP address
    target_mac: [6]u8, // Target MAC address
    target_ip: [4]u8, // Target IP address

    const ARPSIZE: comptime_int = 28;

    pub fn parse(buf: []const u8) !ArpPacket {
        if (buf.len < ARPSIZE) return error.BufferTooSmall;

        var offset: usize = 0;

        const hw_type = std.mem.readInt(u16, buf[offset..][0..2], .big);
        offset += 2;

        const proto_type = std.mem.readInt(u16, buf[offset..][0..2], .big);
        offset += 2;

        const hw_addr_len = buf[offset];
        offset += 1;

        const proto_addr_len = buf[offset];
        offset += 1;

        const operation: ArpOper = @enumFromInt(std.mem.readInt(u16, buf[offset..][0..2], .big));
        offset += 2;

        var sender_mac: [6]u8 = undefined;
        @memcpy(&sender_mac, buf[offset..][0..6]);
        offset += 6;

        var sender_ip: [4]u8 = undefined;
        @memcpy(&sender_ip, buf[offset..][0..4]);
        offset += 4;

        var target_mac: [6]u8 = undefined;
        @memcpy(&target_mac, buf[offset..][0..6]);
        offset += 6;

        var target_ip: [4]u8 = undefined;
        @memcpy(&target_ip, buf[offset..][0..4]);

        return ArpPacket{
            .hw_type = hw_type,
            .proto_type = proto_type,
            .hw_addr_len = hw_addr_len,
            .proto_addr_len = proto_addr_len,
            .operation = operation,
            .sender_mac = sender_mac, // here sender_mac is copied into .sender_mac
            .sender_ip = sender_ip,
            .target_mac = target_mac,
            .target_ip = target_ip,
        };
    }

    pub fn serialize(self: ArpPacket, buf: []u8) !void {
        if (buf.len < 28) return error.BufferTooSmall;

        var offset: usize = 0;

        std.mem.writeInt(u16, buf[offset..][0..2], self.hw_type, .big);
        offset += 2;

        std.mem.writeInt(u16, buf[offset..][0..2], self.proto_type, .big);
        offset += 2;

        buf[offset] = self.hw_addr_len;
        offset += 1;

        buf[offset] = self.proto_addr_len;
        offset += 1;

        std.mem.writeInt(u16, buf[offset..][0..2], @intFromEnum(self.operation), .big);
        offset += 2;

        @memcpy(buf[offset..][0..6], &self.sender_mac);
        offset += 6;

        @memcpy(buf[offset..][0..4], &self.sender_ip);
        offset += 4;

        @memcpy(buf[offset..][0..6], &self.target_mac);
        offset += 6;

        @memcpy(buf[offset..][0..4], &self.target_ip);
    }

    // Allow to create a reply with our MAC and IP
    pub fn createReply(request: ArpPacket, my_mac: [6]u8, my_ip: [4]u8) ArpPacket {
        return ArpPacket{
            .hw_type = request.hw_type,
            .proto_type = request.proto_type,
            .hw_addr_len = request.hw_addr_len,
            .proto_addr_len = request.proto_addr_len,
            .operation = .reply,
            // I am now the sender
            .sender_mac = my_mac,
            .sender_ip = my_ip,
            // Original sender becomes target
            .target_mac = request.sender_mac,
            .target_ip = request.sender_ip,
        };
    }
};
