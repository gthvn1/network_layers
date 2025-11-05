const std = @import("std");
const posix = std.posix;
const p = @import("params.zig");

pub fn main() void {
    // Sock create an endpoint for communication
    // Domain: It is a communication domain, AF.PACKET == Low-level packet interface
    // Socket Type: specifies the communication semantic, SOCK.RAW == raw network protocol access
    // Protocol: specifies a protocol to be used. Normally one protocol matches a particular socket,
    //           so 0 should be fine.
    const family = posix.AF.PACKET;
    const sock = posix.socket(family, posix.SOCK.RAW, 0) catch |err| {
        std.log.err("Failed to create endpoint: {s}", .{@errorName(err)});
        return;
    };
    defer posix.close(sock);

    std.log.info("Socket created", .{});
    // Now we need to assign an address to it

    // Packet socket address: we are testing on Linux
    // https://www.man7.org/linux/man-pages/man7/packet.7.html
    const phys_layer_protocol = std.os.linux.ETH.P.ALL; // Every packet !!!
    const iface_number = std.c.if_nametoindex(p.iface);
    const arp_hw_type = 0;
    const packet_type = std.os.linux.PACKET.BROADCAST;
    const size_of_addr = p.mac.len;

    var addr_copy = [_]u8{0} ** 8;
    std.mem.copyForwards(u8, addr_copy[0..p.mac.len], p.mac);

    const addr: posix.sockaddr.ll = .{
        .family = family,
        .protocol = phys_layer_protocol,
        .ifindex = iface_number,
        .hatype = arp_hw_type,
        .pkttype = packet_type,
        .halen = size_of_addr,
        .addr = addr_copy,
    };

    posix.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.ll)) catch |err| {
        std.log.err("Failed to bound endpoint: {s}", .{@errorName(err)});
        return;
    };
    std.log.info("Bound to interface {s}", .{p.iface});

    const buf_size: comptime_int = 2048;
    var buf: [buf_size]u8 = undefined;

    while (true) {
        const n = posix.read(sock, &buf) catch |err| {
            std.log.err("Failed to read data: {s}", .{@errorName(err)});
            return;
        };

        if (n > 0) {
            std.debug.print("Received {d} bytes: ", .{n});
            for (buf[0..n]) |b| {
                std.debug.print("{x:0>4} ", .{b});
            }
            std.debug.print("\n", .{});
        }
    }
}
