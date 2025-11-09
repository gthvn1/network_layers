const std = @import("std");
const os = std.os;
const posix = std.posix;

const p = @import("params.zig");

const network = @import("network.zig");
const a = network.arp;
const e = network.ethernet;
const h = network.helper;
const s = network.setup;

var should_quit = std.atomic.Value(bool).init(false);

fn handleSigint(sig: c_int) callconv(.c) void {
    _ = sig;
    should_quit.store(true, .release);
}

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
            p.ArgsError.IpMissing => std.log.err("IP is missing", .{}),
            p.ArgsError.IpArgMissing => std.log.err("IP requires an argument", .{}),
            p.ArgsError.NoParams => std.log.err("All parameters are missing", .{}),
        }
        return;
    };

    // We will use it as virtual pair so we need to have place to add "-peer\x00".
    if (params.iface.len >= std.posix.IFNAMESIZE + 6) {
        std.log.err("Name of interface too long", .{});
        return error.IfaceNameTooLong;
    }

    std.log.info("params: iface: {s}", .{params.iface});

    // --------------------------- SETUP ---------------------------------------
    var mac_buf: [17]u8 = undefined;
    const vp: s.VirtPair = try s.getOrCreateVeth(allocator, params.iface);
    std.log.info("found mac: {s}", .{h.macToString(&vp.mac, &mac_buf)});
    std.log.info("found mac peer: {s}", .{h.macToString(&vp.mac_peer, &mac_buf)});

    try s.setIp(allocator, params.iface, params.ip);
    // It also link up the peer
    try s.linkUpVeth(allocator, params.iface);
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
    // Raw packets include the link-layer header. We don't have the preambule and start frame
    // delimiter.
    const family = posix.AF.PACKET;
    const sockfd = posix.socket(family, posix.SOCK.RAW, 0) catch |err| {
        std.log.err("Failed to create endpoint: {s}", .{@errorName(err)});
        return;
    };
    defer posix.close(sockfd);
    std.log.info("Socket created", .{});

    // Now we need to assign an address to it. We will bind to the peer interface.
    // Packet socket address: we are testing on Linux
    // https://www.man7.org/linux/man-pages/man7/packet.7.html
    var peer_iface_buf: [std.posix.IFNAMESIZE:0]u8 = undefined;
    const peer_iface = try std.fmt.bufPrintZ(&peer_iface_buf, "{s}-peer\x00", .{params.iface});

    const phys_layer_protocol = std.mem.nativeToBig(u16, os.linux.ETH.P.ALL); // Every packet !!!
    const iface_number = std.c.if_nametoindex(@ptrCast(peer_iface));
    const arp_hw_type = 0;
    const packet_type = os.linux.PACKET.BROADCAST;
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

    posix.bind(sockfd, @ptrCast(&addr), @sizeOf(posix.sockaddr.ll)) catch |err| {
        std.log.err("Failed to bound endpoint: {s}", .{@errorName(err)});
        return;
    };
    std.log.info("Bound to interface {s}", .{peer_iface});

    var frame_buf: [1024]u8 = undefined;

    // Set up signal handler for SIGINT (Ctrl-C)
    const signal_action = posix.Sigaction{
        .handler = .{ .handler = handleSigint },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    // Change the signal action
    posix.sigaction(posix.SIG.INT, &signal_action, null);

    std.debug.print("Listening on socket... Press Ctrl-C to stop\n", .{});

    // ------------------------------------------------------------------------
    // Main loop
    loop: while (!should_quit.load(.acquire)) {
        var fds = [_]posix.pollfd{
            .{
                .fd = sockfd,
                .events = posix.POLL.IN,
                .revents = 0,
            },
        };

        // We are waiting for events on the socket or timeout after 100ms so if ctrl-c is pressed
        // we will be able to stop quickly. Otherwise we wait for packets coming in to trigger the
        // loop condition and quit.
        const ret = posix.poll(&fds, 100) catch continue;

        if (ret == 0) {
            // We hit the timeout, continue
            continue :loop;
        }

        const n = posix.read(sockfd, &frame_buf) catch |err| {
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

        // To get the ethertype we need the first 18th bytes.
        const ether_type = e.getEtherType(frame_buf[0..18]) orelse {
            std.log.err("Something goes wrong when reading ether type", .{});
            continue :loop;
        };

        switch (ether_type) {
            .arp => {
                if (n != 42) {
                    std.log.warn("We are expecting 42 bytes for arp", .{});
                    std.log.warn(" -> 14 bytes header + 28 bytes ARP payload", .{});
                    continue :loop;
                }

                a.dumpArp(frame_buf[0..42]);
            },
            .ipv4 => std.log.warn("IPv4 is not yet supported", .{}),
            .ipv6 => std.log.warn("IPv6 is not yet supported", .{}),
            .unknown => std.log.warn("Unkown ethertype", .{}),
        }
    }

    std.debug.print("Cleaning in progress...\n", .{});
}

fn handleIp(sockfd: posix.fd_t, frame: []u8, n: usize, my_mac: []const u8, my_ip: []const u8) void {
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
            _ = posix.write(sockfd, &reply);
            std.debug.print("Replied to ICMP echo from {d}.{d}.{d}.{d}\n", .{ frame[26], frame[27], frame[28], frame[29] });
        }
    }
}
