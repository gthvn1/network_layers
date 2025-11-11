const std = @import("std");
const os = std.os;
const posix = std.posix;

const p = @import("params.zig");

const network = @import("network.zig");
const h = network.helper;

const s = network.setup;

const arp = network.arp;
const eth = network.ethernet;
const icmp = network.icmp;
const ip = network.ip;

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
    std.log.info("found mac: {s}", .{h.macToString(vp.mac[0..6], &mac_buf)});
    std.log.info("found mac peer: {s}", .{h.macToString(vp.mac_peer[0..6], &mac_buf)});

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
    std.mem.copyForwards(u8, mac[0..], vp.mac[0..6]);

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
        var frame_buf: [1024]u8 = undefined;
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

        // ret 0 means we hit the timeout, continue
        if (ret == 0) continue :loop;

        const n = posix.read(sockfd, frame_buf[0..]) catch |err| {
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

        const ether_frame = eth.EthernetFrame.parse(frame_buf[0..n]) catch |err| {
            std.log.err("Failed to parse ethernet frame", .{});
            switch (err) {
                eth.EthernetError.BufferTooSmall => std.log.err("-> buffer is too small", .{}),
                eth.EthernetError.PacketTooSmall => std.log.err("-> packet is too small", .{}),
                eth.EthernetError.PacketTooSmallForVlan => std.log.err("-> packet is too small to contain vlan", .{}),
            }
            continue :loop;
        };

        // Check the ethertype
        switch (ether_frame.ether_type) {
            .arp => try handleArp(sockfd, ether_frame, vp.mac_peer),
            .ipv4 => try handleIpv4(sockfd, ether_frame),
            .ipv6 => std.log.warn("IPv6 is not yet supported", .{}),
            .unknown => std.log.warn("Unkown ethertype", .{}),
        }
    }

    std.debug.print("Cleaning in progress...\n", .{});
}

fn handleIpv4(sockfd: std.posix.fd_t, frame: eth.EthernetFrame) !void {
    _ = sockfd;

    const ipv4_packet = try ip.Ipv4Packet.parse(frame.payload);
    switch (ipv4_packet.protocol) {
        .icmp => {
            const icmp_packet = try icmp.IcmpPacket.parse(ipv4_packet.payload);
            switch (icmp_packet.icmp_type) {
                .echo_request => icmp.dump(ipv4_packet.payload),
                else => std.log.warn("Only ICMP echo are supported", .{}),
            }
        },
        .tcp => std.log.warn("TCP is not yet supported", .{}),
        .udp => std.log.warn("UDP is not yet supported", .{}),
        _ => |protocol| std.log.err("{d} is an unknown protocol", .{protocol}),
    }
}

fn handleArp(sockfd: std.posix.fd_t, frame: eth.EthernetFrame, mac_peer: [6]u8) !void {
    const arp_frame = try arp.ArpPacket.parse(frame.payload);

    var buf_mac: [17]u8 = undefined;
    std.log.debug("Sender mac : {s}", .{h.macToString(arp_frame.sender_mac[0..], &buf_mac)});
    std.log.debug("Target mac : {s}", .{h.macToString(arp_frame.target_mac[0..], &buf_mac)});

    var buf_ip: [15]u8 = undefined;
    std.log.debug("Sender ip  : {s}", .{h.ipv4ToString(arp_frame.sender_ip[0..], &buf_ip)});
    std.log.debug("Target ip  : {s}", .{h.ipv4ToString(arp_frame.target_ip[0..], &buf_ip)});

    if (arp_frame.operation == .request) {
        // We reply to all IPs
        var reply_buf: [42]u8 = undefined;
        var arp_payload: [28]u8 = undefined;
        const arp_reply = arp_frame.createReply(mac_peer, arp_frame.target_ip);
        try arp_reply.serialize(arp_payload[0..]);
        _ = try eth.EthernetFrame.build(
            reply_buf[0..],
            arp_frame.sender_mac,
            mac_peer,
            eth.EtherType.arp,
            arp_payload[0..],
        );

        const bytes_written = posix.write(sockfd, reply_buf[0..]) catch |err| {
            std.log.err("Failed to write arp reply: {s}", .{@errorName(err)});
            return;
        };
        std.log.debug("Send ARP reply: {d} bytes", .{bytes_written});
    }
}
