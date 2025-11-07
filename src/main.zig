const std = @import("std");
const posix = std.posix;

const e = @import("ethernet.zig");
const p = @import("params.zig");
const s = @import("setup_net.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer std.debug.assert(gpa.deinit() == .ok);

    var args_it = try std.process.argsWithAllocator(allocator);
    defer args_it.deinit();

    const params = p.Args.parse(&args_it) catch |err| {
        switch (err) {
            p.ArgsError.Help => {},
            p.ArgsError.IfaceMissing => std.log.err("Interface is missing", .{}),
            p.ArgsError.IfaceArgMissing => std.log.err("Interface requires an argument", .{}),
            p.ArgsError.NoParams => std.log.err("Interface and MAC address are missing", .{}),
        }
        return;
    };

    std.log.info("params: iface: {s}", .{params.iface});

    // --------------------------- SETUP ---------------------------------------
    var mac_buf: [17]u8 = undefined;
    const vp: s.VirtPair = try s.getOrCreateVeth(allocator, params.iface);
    std.log.info("found mac: {s}", .{e.macToString(&vp.mac, &mac_buf)});
    std.log.info("found mac peer: {s}", .{e.macToString(&vp.mac_peer, &mac_buf)});

    try s.setIp(allocator, params.iface, "192.168.38.2/24");
    try s.linkUp(allocator, params.iface);
    defer {
        s.cleanup(allocator, params.iface) catch {
            std.log.err("failed to cleanup interface {s}", .{params.iface});
        };
    }

    // ------------------------------------------------------------------------
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

    const phys_layer_protocol = std.mem.nativeToBig(u16, std.os.linux.ETH.P.ALL); // Every packet !!!
    const iface_number = std.c.if_nametoindex(params.iface);
    const arp_hw_type = 0;
    const packet_type = std.os.linux.PACKET.BROADCAST;
    const size_of_addr = vp.mac.len;

    // for sockaddr.ll addr is [8]u8
    var mac = [_]u8{0} ** 8;
    std.mem.copyForwards(u8, &mac, &vp.mac);

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
        std.log.info("DestMac: {s}", .{e.macToString(frame_buf[0..6], &tmp_buf)});
        std.log.info("SrcMac : {s}", .{e.macToString(frame_buf[6..12], &tmp_buf)});
    }
}

// TODO: check code for handling arp and ip and use it...
fn handleArp(sock: posix.fd_t, frame: []u8, n: usize, my_mac: []const u8, my_ip: []const u8) void {
    if (n < 42) return;

    const op = std.mem.readIntBig(u16, frame[20..22]);
    const target_ip = frame[38..42];

    if (op == 1 and std.mem.eql(u8, target_ip, my_ip)) {
        var reply = frame[0..42].*; // copy base
        // Swap MACs
        std.mem.copy(u8, reply[0..6], frame[6..12]); // dst
        std.mem.copy(u8, reply[6..12], my_mac); // src
        // Ethernet type stays 0x0806
        std.mem.writeIntBig(u16, reply[20..22], 2); // ARP reply
        std.mem.copy(u8, reply[22..28], my_mac); // sender MAC
        std.mem.copy(u8, reply[28..32], my_ip); // sender IP
        std.mem.copy(u8, reply[32..38], frame[22..28]); // target MAC
        std.mem.copy(u8, reply[38..42], frame[28..32]); // target IP

        _ = posix.write(sock, &reply);
        std.debug.print("Replied to ARP from {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}\n", .{ frame[6], frame[7], frame[8], frame[9], frame[10], frame[11] });
    }
}

fn handleIp(sock: posix.fd_t, frame: []u8, n: usize, my_mac: []const u8, my_ip: []const u8) void {
    if (n < 42) return;
    const proto = frame[23];
    const dst_ip = frame[30..34];
    if (!std.mem.eql(u8, dst_ip, my_ip)) return;

    if (proto == 1) { // ICMP
        const icmp_type = frame[34];
        if (icmp_type == 8) { // echo request
            var reply = frame[0..n].*;
            // swap MACs
            std.mem.copy(u8, reply[0..6], frame[6..12]);
            std.mem.copy(u8, reply[6..12], my_mac);
            // swap IPs
            std.mem.copy(u8, reply[26..30], frame[30..34]);
            std.mem.copy(u8, reply[30..34], frame[26..30]);
            reply[34] = 0; // type = echo reply
            // recalc checksum (quick fix)
            reply[36] = 0;
            reply[37] = 0;
            _ = posix.write(sock, &reply);
            std.debug.print("Replied to ICMP echo from {d}.{d}.{d}.{d}\n", .{ frame[26], frame[27], frame[28], frame[29] });
        }
    }
}
