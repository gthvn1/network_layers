const std = @import("std");

// https://en.wikipedia.org/wiki/Ethernet_frame
// https://en.wikipedia.org/wiki/EtherType

pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    arp = 0x0806,
    ipv6 = 0x86dd,
    unknown = 0xffff,
};

pub fn getEtherType(packet: []const u8) ?EtherType {
    if (packet.len < 14) return null;

    // At offset 12 we have either the ethertype or a vlan tagged
    var offset: usize = 12;
    var bytes = std.mem.readInt(u16, @ptrCast(packet[offset .. offset + 2]), .big);

    const vlan_tagged = 0x8100;
    if (bytes == vlan_tagged) {
        // In this case we need to skip the next two bytes (802.1Q tag is 4 bytes)
        offset += 4;
        if (packet.len < offset + 2) return null;
        bytes = std.mem.readInt(u16, @ptrCast(packet[offset .. offset + 2]), .big);
    }

    return switch (bytes) {
        0x0800 => .ipv4,
        0x0806 => .arp,
        0x86dd => .ipv6,
        else => .unknown,
    };
}

// Since MAC addresses are always 6 bytes and the string
// representation is always xx:xx:xx:xx:xx:xx we need
// 17 chars.
// We accept slice at least of 6 bytes and convert the first
// 6 bytes.
pub fn macToString(mac: []const u8, buf: *[17]u8) []const u8 {
    if (mac.len < 6) return "??:??:??:??:??:??";
    return std.fmt.bufPrint(
        buf[0..],
        "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}",
        .{ mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] },
    ) catch "??:??:??:??:??:??";
}

const MacError = error{
    TooManyBytes,
    TooFewBytes,
};

pub fn stringToMac(mac_str: []const u8, mac_buf: *[6]u8) !void {
    var it = std.mem.splitScalar(u8, mac_str, ':');
    var idx: usize = 0;

    while (it.next()) |str| {
        if (idx >= 6) return MacError.TooManyBytes;

        const v = try std.fmt.parseInt(u8, str, 16);
        mac_buf[idx] = v;
        idx += 1;
    }

    if (idx != 6) return MacError.TooFewBytes;
}

test "macToString_failed" {
    var buf: [17]u8 = undefined;

    const resp = macToString("hello", &buf);
    try std.testing.expectEqualStrings(resp, "??:??:??:??:??:??");
}

test "macToString_succeded" {
    var buf: [17]u8 = undefined;
    const mac: []const u8 = &[_]u8{ 0x1, 0x2, 0x3, 0x4, 0x5, 0x6 };

    const resp = macToString(mac[0..], &buf);
    try std.testing.expectEqualStrings(resp, "01:02:03:04:05:06");
}

// TODO: test cases that failed
test "stringToMac_succeded" {
    var mac: [6]u8 = undefined;
    const mac_str = "01:02:03:04:05:A6";
    const expected: [6]u8 = [_]u8{ 0x1, 0x2, 0x3, 0x4, 0x5, 0xa6 };

    try stringToMac(mac_str, &mac);
    try std.testing.expectEqualSlices(u8, mac[0..], expected[0..]);
}
