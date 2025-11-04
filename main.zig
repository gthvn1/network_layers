const std = @import("std");
const posix = std.posix;

pub fn main() !void {
    const iface = "veth0-peer";
    const mac: []const u8 = &[_]u8{ 0x96, 0x6a, 0x35, 0x42, 0xad, 0x06 };
    const ip = [_]u8{ 192, 168, 0, 3 };

    _ = ip;

    // Sock create an endpoint for communication
    // Domain: It is a communication domain, AF.PACKET == Low-level packet interface
    // Socket Type: specifies the communication semantic, SOCK.RAW == raw network protocol access
    // Protocol: specifies a protocol to be used. Normally one protocol matches a particular socket,
    //           so 0 should be fine.
    const family = posix.AF.PACKET;
    const sock = try posix.socket(family, posix.SOCK.RAW, 0);
    defer posix.close(sock);

    std.log.info("Socket created", .{});
    // Now we need to assign an address to it

    // Packet socket address
    // https://www.man7.org/linux/man-pages/man7/packet.7.html
    // TODO:  Set physical layer protocol to htons(ETH_P_ALL), so all protocols are received.
    // But we didn't find it in Zig Lib
    const phys_layer_protocol = 0;
    const iface_number = std.c.if_nametoindex(iface);
    const arp_hw_type = 0;
    const packet_type = std.os.linux.PACKET.BROADCAST;
    const size_of_addr = mac.len;

    var addr_copy = [_]u8{0} ** 8;
    std.mem.copyForwards(u8, addr_copy[0..mac.len], mac);

    const addr: posix.sockaddr.ll = .{
        .family = family,
        .protocol = phys_layer_protocol,
        .ifindex = iface_number,
        .hatype = arp_hw_type,
        .pkttype = packet_type,
        .halen = size_of_addr,
        .addr = addr_copy,
    };

    try posix.bind(sock, @ptrCast(&addr), @sizeOf(std.os.linux.sockaddr.ll));
    std.log.info("Bound to interface {s}", .{iface});

    const buf_size: comptime_int = 2048;
    var buf: [buf_size]u8 = undefined;

    while (true) {
        const n = try posix.read(sock, &buf);
        if (n > 0) {
            std.debug.print("Received {d} bytes: ", .{n});
            for (buf[0..n]) |b| {
                std.debug.print("{x:0>4} ", .{b});
            }
            std.debug.print("\n", .{});
        }
    }
}
