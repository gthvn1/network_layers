const std = @import("std");

const e = @import("ethernet.zig");

// +--------------------------------------------------------+
// | Ethernet Header (14 bytes standard)                    |
// |--------------------------------------------------------|
// | Destination MAC (6) | Source MAC (6) | EtherType (2)   |
// +--------------------------------------------------------+
// | VLAN Tag (optional, 4 bytes)                           |
// |--------------------------------------------------------|
// | TPID (2) | TCI (2)                                     |
// +--------------------------------------------------------+
// | ARP Payload (28 bytes standard for Ethernet/IPv4)      |
// |--------------------------------------------------------|
// | HTYPE (2) | PTYPE (2) | HLEN (1) | PLEN (1) | OPER (2) |
// | SHA (6) | SPA (4) | THA (6) | TPA (4)                  |
// +--------------------------------------------------------+
// | Frame Check Sequence (FCS, 4 bytes, added by NIC)      |
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
// ff ff ff ff ff ff f2 4e 68 82
// e2 1b 08 06 00 01 08 00 06 04
// 00 01 f2 4e 68 82 e2 1b c0 a8
// 26 02 ff ff ff ff ff ff c0 a8
// 26 03
//
// We are expecting 42 bytes
// ARP is 28 bytes -> 224 bits
//
// https://en.wikipedia.org/wiki/Address_Resolution_Protocol
pub const ArpPacket = packed struct {
    hw_type: u16, // Hardware type (1 = Ethernet)
    proto_type: u16, // Protocol type (0x0800 = IPv4)
    hw_addr_len: u8, // Hardware address length (6 for MAC)
    proto_addr_len: u8, // Protocol address length (4 for IPv4)
    operation: u16, // 1 = request, 2 = reply
    sender_mac: [6]u8, // Sender MAC address
    sender_ip: [4]u8, // Sender IP address
    target_mac: [6]u8, // Target MAC address
    target_ip: [4]u8, // Target IP address
};

pub fn dumpArp(frame: *const [42]u8) void {
    var tmp_buf: [17]u8 = undefined;
    std.log.info("DestMac: {s}", .{e.macToString(frame[0..6], &tmp_buf)});
    std.log.info("SrcMac : {s}", .{e.macToString(frame[6..12], &tmp_buf)});
}

// TODO: check code for handling arp and ip and use it...
//fn handleArp(sock: posix.fd_t, frame: []u8, n: usize, my_mac: []const u8, my_ip: []const u8) void {
//if (n < 42) return;
//
//const op = std.mem.readIntBig(u16, frame[20..22]);
//const target_ip = frame[38..42];
//
//if (op == 1 and std.mem.eql(u8, target_ip, my_ip)) {
//var reply = frame[0..42].*; // copy base
//// Swap MACs
//std.mem.copy(u8, reply[0..6], frame[6..12]); // dst
//std.mem.copy(u8, reply[6..12], my_mac); // src
//// Ethernet type stays 0x0806
//std.mem.writeIntBig(u16, reply[20..22], 2); // ARP reply
//std.mem.copy(u8, reply[22..28], my_mac); // sender MAC
//std.mem.copy(u8, reply[28..32], my_ip); // sender IP
//std.mem.copy(u8, reply[32..38], frame[22..28]); // target MAC
//std.mem.copy(u8, reply[38..42], frame[28..32]); // target IP
//
//_ = posix.write(sock, &reply);
//std.debug.print("Replied to ARP from {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}\n", .{ frame[6], frame[7], frame[8], frame[9], frame[10], frame[11] });
//}
//}

// const std = @import("std");
// const posix = std.posix;

// Ethernet frame structure (14 bytes header)
// const EthernetHeader = packed struct {
//     dest_mac: [6]u8,      // Destination MAC
//     src_mac: [6]u8,       // Source MAC
//     ethertype: u16,       // Protocol type (big-endian)

//     const ETHERTYPE_ARP: u16 = 0x0806;
//     const ETHERTYPE_IPV4: u16 = 0x0800;
//     const ETHERTYPE_IPV6: u16 = 0x86DD;
// };

// // ARP packet structure (28 bytes)
// const ArpPacket = packed struct {
//     hw_type: u16,         // Hardware type (1 = Ethernet)
//     proto_type: u16,      // Protocol type (0x0800 = IPv4)
//     hw_addr_len: u8,      // Hardware address length (6 for MAC)
//     proto_addr_len: u8,   // Protocol address length (4 for IPv4)
//     operation: u16,       // 1 = request, 2 = reply
//     sender_mac: [6]u8,    // Sender MAC address
//     sender_ip: [4]u8,     // Sender IP address
//     target_mac: [6]u8,    // Target MAC address
//     target_ip: [4]u8,     // Target IP address

//     const OP_REQUEST: u16 = 1;
//     const OP_REPLY: u16 = 2;
// };

// fn formatMac(mac: [6]u8) [17]u8 {
//     var buf: [17]u8 = undefined;
//     _ = std.fmt.bufPrint(&buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
//         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
//     }) catch unreachable;
//     return buf;
// }

// fn formatIp(ip: [4]u8) [15]u8 {
//     var buf: [15]u8 = undefined;
//     const len = std.fmt.bufPrint(&buf, "{}.{}.{}.{}", .{ ip[0], ip[1], ip[2], ip[3] }) catch unreachable;
//     @memset(buf[len.len..], ' ');
//     return buf;
// }

// pub fn main() !void {
//     const stdout = std.io.getStdOut().writer();

//     // Open raw socket on specific interface
//     const socket_fd = try posix.socket(posix.AF.PACKET, posix.SOCK.RAW, @bitCast(@as(u16, @byteSwap(0x0003)))); // ETH_P_ALL
//     defer posix.close(socket_fd);

//     try stdout.print("Listening for packets on veth0-peer...\n\n", .{});

//     var buffer: [1024]u8 = undefined;

//     while (true) {
//         const bytes_read = try posix.read(socket_fd, &buffer);

//         if (bytes_read < @sizeOf(EthernetHeader)) continue;

//         // Parse Ethernet header
//         const eth_header = @as(*const EthernetHeader, @ptrCast(@alignCast(&buffer[0])));
//         const ethertype = @byteSwap(eth_header.ethertype);

//         try stdout.print("─────────────────────────────────────\n", .{});
//         try stdout.print("Ethernet Frame ({} bytes)\n", .{bytes_read});
//         try stdout.print("  Dest MAC: {s}\n", .{formatMac(eth_header.dest_mac)});
//         try stdout.print("  Src MAC:  {s}\n", .{formatMac(eth_header.src_mac)});
//         try stdout.print("  EtherType: 0x{x:0>4} ", .{ethertype});

//         // Decode payload based on EtherType
//         switch (ethertype) {
//             EthernetHeader.ETHERTYPE_ARP => {
//                 try stdout.print("(ARP)\n", .{});

//                 if (bytes_read < @sizeOf(EthernetHeader) + @sizeOf(ArpPacket)) {
//                     try stdout.print("  [Incomplete ARP packet]\n", .{});
//                     continue;
//                 }

//                 const arp_offset = @sizeOf(EthernetHeader);
//                 const arp = @as(*const ArpPacket, @ptrCast(@alignCast(&buffer[arp_offset])));

//                 const operation = @byteSwap(arp.operation);
//                 try stdout.print("\n  ARP Packet:\n", .{});
//                 try stdout.print("    Operation: {s}\n", .{
//                     if (operation == ArpPacket.OP_REQUEST) "REQUEST" else if (operation == ArpPacket.OP_REPLY) "REPLY" else "UNKNOWN"
//                 });
//                 try stdout.print("    Sender: {s} -> {s}\n", .{
//                     formatMac(arp.sender_mac),
//                     formatIp(arp.sender_ip),
//                 });
//                 try stdout.print("    Target: {s} -> {s}\n", .{
//                     formatMac(arp.target_mac),
//                     formatIp(arp.target_ip),
//                 });
//             },
//             EthernetHeader.ETHERTYPE_IPV4 => {
//                 try stdout.print("(IPv4)\n", .{});
//                 try stdout.print("  [IPv4 payload - not parsed]\n", .{});
//             },
//             EthernetHeader.ETHERTYPE_IPV6 => {
//                 try stdout.print("(IPv6)\n", .{});
//                 try stdout.print("  [IPv6 payload - not parsed]\n", .{});
//             },
//             else => {
//                 try stdout.print("(Unknown)\n", .{});
//             },
//         }

//         try stdout.print("\n", .{});
//     }
// }
