const std = @import("std");

// https://en.wikipedia.org/wiki/EtherType
pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    arp = 0x0806,
    ipv6 = 0x86dd,
    unknown = 0xffff,
};

// https://en.wikipedia.org/wiki/Ethernet_frame
pub const EthernetFrame = struct {
    ether_type: EtherType,
    header_len: usize, // Length of ethernet header (14 or 18 with VLAN)
    payload: []const u8,

    pub fn parse(packet: []const u8) ?EthernetFrame {
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

        const header_len = offset + 2; // ether field + 2 (the ether type itself)

        const ether_type: EtherType = switch (bytes) {
            0x0800 => .ipv4,
            0x0806 => .arp,
            0x86dd => .ipv6,
            else => .unknown,
        };

        return EthernetFrame{
            .ether_type = ether_type,
            .header_len = header_len,
            .payload = packet[header_len..],
        };
    }
};
