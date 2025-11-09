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
