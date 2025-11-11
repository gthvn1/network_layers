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

    // It takes a payload and encapsulate it in an ethernet frame.
    pub fn build(
        buf: []u8,
        dest_mac: [6]u8,
        src_mac: [6]u8,
        ether_type: EtherType,
        payload: []const u8,
    ) ?usize {
        const header_len = 14;
        const total_len = header_len + payload.len;

        if (buf.len < total_len) {
            std.log.err("buffer too small", .{});
            return null;
        }

        // Destination MAC
        @memcpy(buf[0..6], &dest_mac);

        // Source MAC
        @memcpy(buf[6..12], &src_mac);

        // EtherType
        std.mem.writeInt(u16, buf[12..14], @intFromEnum(ether_type), .big);

        // Payload
        @memcpy(buf[header_len..total_len], payload);

        return total_len;
    }

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
