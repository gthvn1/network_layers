const std = @import("std");

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
