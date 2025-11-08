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

// We are expecting 42 bytes
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
