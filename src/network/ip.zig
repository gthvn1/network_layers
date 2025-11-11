const std = @import("std");
const NetworkError = @import("error.zig").NetworkError;

// +--------------------------------------------------------+
// | IPv4 Header (20-60 bytes, typically 20)                |
// |--------------------------------------------------------|
// | Ver/IHL (1) | DSCP/ECN (1) | Total Length (2)          |
// | Identification (2) | Flags/Fragment Offset (2)         |
// | TTL (1) | Protocol (1) | Header Checksum (2)           |
// | Source IP (4) | Destination IP (4)                     |
// | Options (0-40 bytes, optional if IHL > 5)              |
// +--------------------------------------------------------+
//
// [RFC 791] https://datatracker.ietf.org/doc/html/rfc791
// Here is a raw ethernet frame that we received
//   -> ping from 192.168.38.2 to 192.168.38.3:
//
// ETH: 06 2b 41 e7 ae 3c
// ETH: 22 74 85 fe 7e 04
// ETH: 08 00  --> This is IP
// IP: 45            -> Version:4 (it is ipv4), Internet Header Length (IHL): 5
// IP: 00
// IP: 00 54         -> total length: 84 bytes (entire packet size in bytes, including header and data)
// IP: dd 7c         -> Identification: 22364
// IP: 40 00         -> Flags: Don't Fragment, Fragment Offset: 0
// IP: 40            -> TTL: 64
// IP: 01            -> Protocol: ICMP
// IP: 8f d6         -> Header Checksum: 36798
// IP: c0 a8 26 02   -> Source IP: 192.168.38.2
// IP: c0 a8 26 03   -> Destination IP: 192.168.38.3
// IP: 08 00 54 93 04 2b 00 01 29 f9
// IP: 11 69 00 00 00 00 a0 0b 05 00
// IP: 00 00 00 00 10 11 12 13 14 15
// IP: 16 17 18 19 1a 1b 1c 1d 1e 1f
// IP: 20 21 22 23 24 25 26 27 28 29
// IP: 2a 2b 2c 2d 2e 2f 30 31 32 33
// IP: 34 35 36 37

// https://en.wikipedia.org/wiki/IPv4#header
pub const IpProtocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    _,
};

pub const IpError = NetworkError || error{
    InvalidVersion,
    InvalidIHL,
};

pub const Ipv4Packet = struct {
    version: u4, // Should be 4
    ihl: u4, // Header length in 32-bit words (typically 5)
    dscp: u6, // Differentiated Services Code Point
    ecn: u2, // Explicit Congestion Notification
    total_length: u16, // Total packet length (header + data)
    identification: u16, // Fragment identification
    flags: u3, // Flags (bit 0: reserved, bit 1: DF, bit 2: MF)
    fragment_offset: u13, // Fragment offset
    ttl: u8, // Time to live
    protocol: IpProtocol, // Protocol (1=ICMP, 6=TCP, 17=UDP)
    header_checksum: u16, // Header checksum
    source_ip: [4]u8, // Source IP address
    dest_ip: [4]u8, // Destination IP address
    options: []const u8, // Options (if IHL > 5)
    payload: []const u8, // Payload data

    const MIN_HEADER_SIZE: comptime_int = 20;

    pub fn parse(buf: []const u8) IpError!Ipv4Packet {
        if (buf.len < MIN_HEADER_SIZE) return IpError.BufferTooSmall;

        // Byte 0: Version (4 bits) + IHL (4 bits)
        const version_ihl = buf[0];
        const version: u4 = @truncate(version_ihl >> 4);
        const ihl: u4 = @truncate(version_ihl & 0x0F);

        if (version != 4) return IpError.InvalidVersion;
        if (ihl < 5) return IpError.InvalidIHL;

        const header_len: usize = @as(usize, ihl) * 4;
        if (buf.len < header_len) return IpError.BufferTooSmall;

        // Byte 1: DSCP (6 bits) + ECN (2 bits)
        const dscp_ecn = buf[1];
        const dscp: u6 = @truncate(dscp_ecn >> 2);
        const ecn: u2 = @truncate(dscp_ecn & 0x03);

        // Bytes 2-3: Total Length
        const total_length = std.mem.readInt(u16, buf[2..4], .big);

        // Bytes 4-5: Identification
        const identification = std.mem.readInt(u16, buf[4..6], .big);

        // Bytes 6-7: Flags (3 bits) + Fragment Offset (13 bits)
        const flags_offset = std.mem.readInt(u16, buf[6..8], .big);
        const flags: u3 = @truncate(flags_offset >> 13);
        const fragment_offset: u13 = @truncate(flags_offset & 0x1FFF);

        // Byte 8: TTL
        const ttl = buf[8];

        // Byte 9: Protocol
        const protocol: IpProtocol = @enumFromInt(buf[9]);

        // Bytes 10-11: Header Checksum
        const header_checksum = std.mem.readInt(u16, buf[10..12], .big);

        // Bytes 12-15: Source IP
        var source_ip: [4]u8 = undefined;
        @memcpy(&source_ip, buf[12..16]);

        // Bytes 16-19: Destination IP
        var dest_ip: [4]u8 = undefined;
        @memcpy(&dest_ip, buf[16..20]);

        // Options (if IHL > 5)
        const options = if (ihl > 5) buf[20..header_len] else &[_]u8{};

        // Payload
        const payload = buf[header_len..];

        return Ipv4Packet{
            .version = version,
            .ihl = ihl,
            .dscp = dscp,
            .ecn = ecn,
            .total_length = total_length,
            .identification = identification,
            .flags = flags,
            .fragment_offset = fragment_offset,
            .ttl = ttl,
            .protocol = protocol,
            .header_checksum = header_checksum,
            .source_ip = source_ip,
            .dest_ip = dest_ip,
            .options = options,
            .payload = payload,
        };
    }

    pub fn getHeaderLength(self: Ipv4Packet) usize {
        return @as(usize, self.ihl) * 4;
    }

    // Calculate IPv4 header checksum
    // The checksum field should be set to 0 before calculation
    pub fn calculateChecksum(header: []const u8) u16 {
        var sum: u32 = 0;
        var i: usize = 0;

        // Sum all 16-bit words
        while (i < header.len) : (i += 2) {
            const word = std.mem.readInt(u16, header[i..][0..2], .big);
            sum += word;
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16 != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        return @truncate(~sum);
    }

    pub fn serialize(self: Ipv4Packet, buf: []u8) IpError!void {
        const header_len = self.getHeaderLength();
        const total_len = header_len + self.payload.len;

        if (buf.len < total_len) return IpError.BufferTooSmall;

        // Byte 0: Version + IHL
        buf[0] = (@as(u8, self.version) << 4) | @as(u8, self.ihl);

        // Byte 1: DSCP + ECN
        buf[1] = (@as(u8, self.dscp) << 2) | @as(u8, self.ecn);

        // Bytes 2-3: Total Length
        std.mem.writeInt(u16, buf[2..4], self.total_length, .big);

        // Bytes 4-5: Identification
        std.mem.writeInt(u16, buf[4..6], self.identification, .big);

        // Bytes 6-7: Flags + Fragment Offset
        const flags_offset = (@as(u16, self.flags) << 13) | @as(u16, self.fragment_offset);
        std.mem.writeInt(u16, buf[6..8], flags_offset, .big);

        // Byte 8: TTL
        buf[8] = self.ttl;

        // Byte 9: Protocol
        buf[9] = @intFromEnum(self.protocol);

        // Bytes 10-11: Header Checksum (will be calculated after)
        std.mem.writeInt(u16, buf[10..12], self.header_checksum, .big);

        // Bytes 12-15: Source IP
        @memcpy(buf[12..16], &self.source_ip);

        // Bytes 16-19: Destination IP
        @memcpy(buf[16..20], &self.dest_ip);

        // Options
        if (self.options.len > 0) {
            @memcpy(buf[20..][0..self.options.len], self.options);
        }

        // Payload
        @memcpy(buf[header_len..total_len], self.payload);
    }

    // Create a reply packet (swap source/dest, adjust TTL)
    pub fn createReply(request: Ipv4Packet, payload: []const u8) Ipv4Packet {
        return Ipv4Packet{
            .version = 4,
            .ihl = 5, // No options in reply
            .dscp = 0,
            .ecn = 0,
            .total_length = 20 + @as(u16, @intCast(payload.len)),
            .identification = request.identification,
            .flags = 0b010, // Don't Fragment
            .fragment_offset = 0,
            .ttl = 64,
            .protocol = request.protocol,
            .header_checksum = 0, // Will be calculated
            .source_ip = request.dest_ip, // Swap
            .dest_ip = request.source_ip, // Swap
            .options = &[_]u8{},
            .payload = payload,
        };
    }
};
