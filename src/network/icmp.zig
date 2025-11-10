const std = @import("std");

// https://datatracker.ietf.org/doc/html/rfc792
// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
//
// Here is an example of raw payload:
// 08          -> Type
// 00          -> Code
// 12 76       -> checksum
// 0a e3 00 01 -> Rest of the header
// db 10 12 69 00 00 00 00 29 59
// 05 00 00 00 00 00 10 11 12 13
// 14 15 16 17 18 19 1a 1b 1c 1d
// 1e 1f 20 21 22 23 24 25 26 27
// 28 29 2a 2b 2c 2d 2e 2f 30 31
// 32 33 34 35 36 37

// TODO: manage more control message
pub const IcmpType = enum(u8) {
    echo_reply = 0,
    echo_request = 8,
    _,
};

pub const IcmpPacket = struct {
    icmp_type: IcmpType,
    code: u8,
    checksum: u16,
    rest_of_header: []const u8,

    // TODO: we are focusing on echo
    const ICMPSIZE: comptime_int = 8;

    pub fn parse(buf: []const u8) !IcmpPacket {
        if (buf.len < ICMPSIZE) return error.BufferTooSmall;

        const icmp_type: IcmpType = @enumFromInt(buf[0]);
        const code = buf[1];
        const checksum = std.mem.readInt(u16, buf[2..4], .big);

        return IcmpPacket{
            .icmp_type = icmp_type,
            .code = code,
            .checksum = checksum,
            .rest_of_header = buf[4..],
        };
    }
};

pub fn handle(payload: []const u8) void {
    std.log.debug("TODO: Handling ICMP", .{});
    std.debug.print("--- Raw payload\n", .{});
    for (payload, 1..) |b, i| {
        std.debug.print("{x:0>2} ", .{b});
        if (@mod(i, 10) == 0) {
            std.debug.print("\n", .{});
        }
    }
    std.debug.print("\n---\n", .{});
}
