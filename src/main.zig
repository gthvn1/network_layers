const std = @import("std");
const posix = std.posix;

const e = @import("ethernet.zig");
const p = @import("params.zig");

fn check_veth(allocator: std.mem.Allocator) !void {
    const Child = std.process.Child;
    const argv = [_][]const u8{
        "ip",
        "link",
    };

    // Child inherir stdout & stderr
    var child = Child.init(&argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    var stdout: std.array_list.Aligned(u8, null) = .empty;
    defer stdout.deinit(allocator);
    var stderr: std.array_list.Aligned(u8, null) = .empty;
    defer stderr.deinit(allocator);

    try child.spawn();
    try child.collectOutput(allocator, &stdout, &stderr, 1024);
    const term = try child.wait();

    try std.testing.expectEqual(term.Exited, 0);

    // convert to strings
    std.log.debug("stdout: {s}", .{stdout.items});
    std.log.err("stderr: {s}", .{stderr.items});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer std.debug.assert(gpa.deinit() == .ok);

    var args_it = try std.process.argsWithAllocator(allocator);
    defer args_it.deinit();

    try check_veth(allocator);

    const params = p.Args.parse(&args_it) catch |err| {
        switch (err) {
            p.ArgsError.Help => {},
            p.ArgsError.IfaceMissing => std.log.err("Interface is missing", .{}),
            p.ArgsError.IfaceArgMissing => std.log.err("Interface requires an argument", .{}),
            p.ArgsError.MacMissing => std.log.err("MAC address is missing", .{}),
            p.ArgsError.MacArgMissing => std.log.err("MAC address requires an argument", .{}),
            p.ArgsError.NoParams => std.log.err("Interface and MAC address are missing", .{}),
        }
        return;
    };

    std.log.info("iface: {s}", .{params.iface});
    std.log.info("mac  : {s}", .{params.mac});

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

    var mac = [_]u8{0} ** 8;
    try e.stringToMac(params.mac, mac[0..6]);
    const phys_layer_protocol = std.mem.nativeToBig(u16, std.os.linux.ETH.P.ALL); // Every packet !!!
    const iface_number = std.c.if_nametoindex(params.iface);
    const arp_hw_type = 0;
    const packet_type = std.os.linux.PACKET.BROADCAST;
    const size_of_addr = mac.len;

    const addr: posix.sockaddr.ll = .{
        .family = family,
        .protocol = phys_layer_protocol,
        .ifindex = iface_number,
        .hatype = arp_hw_type,
        .pkttype = packet_type,
        .halen = size_of_addr,
        .addr = mac,
    };

    std.log.info("Interface index: {}", .{iface_number});

    posix.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.ll)) catch |err| {
        std.log.err("Failed to bound endpoint: {s}", .{@errorName(err)});
        return;
    };
    std.log.info("Bound to interface {s}", .{params.iface});

    var frame_buf: [1024]u8 = undefined;

    while (true) {
        const n = posix.read(sock, &frame_buf) catch |err| {
            std.log.err("Failed to read data: {s}", .{@errorName(err)});
            return;
        };

        if (n > 0) {
            std.debug.print("--- Received {d} bytes:\n", .{n});
            for (frame_buf[0..n], 1..) |b, i| {
                std.debug.print("{x:0>2} ", .{b});
                if (@mod(i, 10) == 0) {
                    std.debug.print("\n", .{});
                }
            }
            std.debug.print("\n--- Done\n", .{});
        }

        if (n != 42) {
            std.log.warn("We are currently dealing with 42 bytes frame", .{});
            std.log.warn(" -> 14 bytes header + 28 bytes ARP payload", .{});
            // TODO: handle more things...
            continue;
        }

        // +--------------------------------------------------------+
        // | Ethernet Header (14 bytes standard)                    |
        // |--------------------------------------------------------|
        // | Destination MAC (6) | Source MAC (6) | EtherType (2)   |
        // +--------------------------------------------------------+
        // | VLAN Tag (optional, 4 bytes)                           |
        // |--------------------------------------------------------|
        // | TPID (2) | TCI (2)                                     |
        // +--------------------------------------------------------+
        // | ARP Payload (28 bytes standard for Ethernet/IPv4)      |
        // |--------------------------------------------------------|
        // | HTYPE (2) | PTYPE (2) | HLEN (1) | PLEN (1) | OPER (2) |
        // | SHA (6) | SPA (4) | THA (6) | TPA (4)                  |
        // +--------------------------------------------------------+
        // | Frame Check Sequence (FCS, 4 bytes, added by NIC)      |
        // +--------------------------------------------------------+
        //
        // Ethernet II layout begins with:
        //   Destination MAC: 6 bytes
        //   Source MAC: 6 bytes
        //   EtherType: 2 bytes (0x0806 -> ARP)
        //
        // [RFC ARP] https://datatracker.ietf.org/doc/html/rfc826

        var tmp_buf: [17]u8 = undefined;
        std.log.info(
            "DestMac: {s}",
            .{e.macToString(frame_buf[0..6], &tmp_buf)},
        );
        std.log.info(
            "SrcMac : {s}",
            .{e.macToString(frame_buf[6..12], &tmp_buf)},
        );
    }
}
