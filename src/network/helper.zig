const std = @import("std");

// IPv4: xxx.xxx.xxx.xxx = max 15 chars
pub fn ipv4ToString(ip: []const u8, str_buf: *[15]u8) []const u8 {
    if (ip.len < 4) return "?.?.?.?";
    return std.fmt.bufPrint(
        str_buf[0..],
        "{d}.{d}.{d}.{d}",
        .{ ip[0], ip[1], ip[2], ip[3] },
    ) catch "?.?.?.?";
}

const IpError = error{
    TooManyOctets,
    TooFewOctets,
    InvalidOctet,
};

pub fn stringToIpv4(ip_str: []const u8, ip_buf: *[4]u8) !void {
    var it = std.mem.splitScalar(u8, ip_str, '.');
    var idx: usize = 0;

    while (it.next()) |str| {
        if (idx >= 4) return IpError.TooManyOctets;

        const v = std.fmt.parseInt(u8, str, 10) catch return IpError.InvalidOctet;
        ip_buf[idx] = v;
        idx += 1;
    }

    if (idx != 4) return IpError.TooFewOctets;
}

// Since MAC addresses are always 6 bytes and the string
// representation is always xx:xx:xx:xx:xx:xx we need
// 17 chars.
// We accept slice at least of 6 bytes and convert the first
// 6 bytes.
pub fn macToString(mac: []const u8, str_buf: *[17]u8) []const u8 {
    if (mac.len < 6) return "??:??:??:??:??:??";
    return std.fmt.bufPrint(
        str_buf[0..],
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
