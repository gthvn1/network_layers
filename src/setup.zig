const std = @import("std");
const helper = @import("network.zig").helper;

const SetupError = error{
    Command,
    ChildCollectOutput,
    ChildSpawn,
    ChildWait,
    DupSlice,
    FailedConvertMac,
    IpLinkUp,
    IpLinkAdd,
    IpLinkDel,
    IpAddrAdd,
    MacNotFoundAfterCreation,
    ParseInterface,
    PeerMacNotFoundAfterCreation,
    PeerNameCreate,
    PeerNotFound,
    VethMac,
};

const Interface = struct {
    ifindex: i32,
    ifname: []const u8,
    flags: []const []const u8,
    mtu: i32,
    qdisc: []const u8,
    operstate: []const u8,
    linkmode: []const u8,
    group: []const u8,
    link_type: []const u8,
    link: ?[]const u8 = null,
    master: ?[]const u8 = null,
    txqlen: ?i32 = null,
    address: ?[]const u8 = null,
    broadcast: ?[]const u8 = null,
    altnames: ?[]const []const u8 = null,
};

const CmdOutput = struct {
    stdout: []u8,
    stderr: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *CmdOutput) void {
        self.allocator.free(self.stdout);
        self.allocator.free(self.stderr);
    }
};

pub const VirtPair = struct {
    mac: [6]u8,
    mac_peer: [6]u8,
};

pub fn linkUpVeth(allocator: std.mem.Allocator, name: []const u8) SetupError!void {
    var peer_iface_buf: [std.posix.IFNAMESIZE:0]u8 = undefined;
    const peer_iface = std.fmt.bufPrintZ(
        &peer_iface_buf,
        "{s}-peer\x00",
        .{name},
    ) catch return SetupError.PeerNameCreate;

    const cmd1 = [_][]const u8{ "ip", "link", "set", name, "up" };

    var res1 = try runCmd(allocator, &cmd1);
    defer res1.deinit();

    if (res1.stderr.len > 0) {
        std.log.err("ip link up failed: {s}", .{res1.stderr});
        return SetupError.IpLinkUp;
    }

    std.log.info("ip link set {s} up", .{name});
    const cmd2 = [_][]const u8{ "ip", "link", "set", peer_iface, "up" };

    var res2 = try runCmd(allocator, &cmd2);
    defer res2.deinit();

    if (res2.stderr.len > 0) {
        std.log.err("ip link up failed: {s}", .{res2.stderr});
        return SetupError.IpLinkUp;
    }

    std.log.info("ip link set {s} up", .{peer_iface});
}

// TODO: we probably want to keep the name of the peer somewhere instead
// of reallocating every time.
pub fn setIp(allocator: std.mem.Allocator, name: []const u8, ip: []const u8) SetupError!void {
    // TODO: check that IP is XX.XX.XX.XX/YY
    const cmd = [_][]const u8{ "ip", "addr", "add", ip, "dev", name };

    var res = try runCmd(allocator, &cmd);
    defer res.deinit();

    if (res.stderr.len > 0) {
        std.log.err("ip addr add failed: {s}", .{res.stderr});
        return SetupError.IpAddrAdd;
    }

    std.log.info("ip addr add {s} dev {s}", .{ ip, name });
}

pub fn getOrCreateVeth(allocator: std.mem.Allocator, name: []const u8) SetupError!VirtPair {
    const peer_name = std.fmt.allocPrint(
        allocator,
        "{s}-peer",
        .{name},
    ) catch return SetupError.PeerNameCreate;
    defer allocator.free(peer_name);

    var vp = VirtPair{
        .mac = [_]u8{0} ** 6,
        .mac_peer = [_]u8{0} ** 6,
    };

    // First check if it exists
    if (getDeviceMac(allocator, name, &vp.mac) catch false) {
        // If we found interface "name" we are expecting to find its peer
        if (getDeviceMac(allocator, peer_name, &vp.mac_peer) catch false) {
            return vp;
        }
        return SetupError.PeerNotFound;
    }

    // We need to create virtual pair
    const cmd = [_][]const u8{ "ip", "link", "add", name, "type", "veth", "peer", "name", peer_name };

    var res = try runCmd(allocator, &cmd);
    defer res.deinit();

    if (res.stderr.len > 0) {
        std.log.err("ip link add failed: {s}", .{res.stderr});
        return SetupError.IpLinkAdd;
    }

    std.log.info("ip link add {s} type veth peer name {s}", .{ name, peer_name });

    // Now we can get the MAC
    if (getDeviceMac(allocator, name, &vp.mac) catch return SetupError.MacNotFoundAfterCreation) {
        if (getDeviceMac(allocator, peer_name, &vp.mac_peer) catch return SetupError.PeerMacNotFoundAfterCreation) {
            return vp;
        }
    }

    // If we are here we don't find valid virtual pair so creation failed.
    return SetupError.VethMac;
}

// Peer is automatically removed by kernel
pub fn cleanup(allocator: std.mem.Allocator, name: []const u8) SetupError!void {
    const cmd = [_][]const u8{ "ip", "link", "del", name };

    var res = try runCmd(allocator, &cmd);
    defer res.deinit();

    if (res.stderr.len > 0) {
        std.log.err("ip link del failed: {s}", .{res.stderr});
        return SetupError.IpLinkDel;
    }

    std.log.info("ip link del {s}", .{name});
}

fn getDeviceMac(allocator: std.mem.Allocator, name: []const u8, buf: *[6]u8) SetupError!bool {
    const cmd = [_][]const u8{ "ip", "-j", "link", "show", name };
    var res = try runCmd(allocator, &cmd);
    defer res.deinit();

    const interfaces = std.json.parseFromSlice(
        []Interface,
        allocator,
        res.stdout,
        .{},
    ) catch return SetupError.ParseInterface;
    defer interfaces.deinit();

    if (interfaces.value.len == 0) return false;
    if (interfaces.value.len > 1) {
        std.log.err("we found {d} devices for {s}", .{ interfaces.value.len, name });
        return false;
    }

    const iface = interfaces.value[0];
    if (std.mem.eql(u8, name, iface.ifname)) {
        if (iface.address) |addr| {
            helper.stringToMac(addr, buf) catch return SetupError.FailedConvertMac;
            return true;
        }
    }

    return false;
}

fn runCmd(allocator: std.mem.Allocator, command: []const []const u8) SetupError!CmdOutput {
    const Child = std.process.Child;

    // Child inherits stdout & stderr so redirect them.
    var child = Child.init(command, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    var stdout: std.array_list.Aligned(u8, null) = .empty;
    defer stdout.deinit(allocator);
    var stderr: std.array_list.Aligned(u8, null) = .empty;
    defer stderr.deinit(allocator);

    child.spawn() catch return SetupError.ChildSpawn;
    child.collectOutput(allocator, &stdout, &stderr, 4096) catch return SetupError.ChildCollectOutput;
    const term = child.wait() catch return SetupError.ChildWait;

    if (term.Exited != 0) {
        std.log.debug("Command exited with code {}", .{term.Exited});
        return SetupError.Command;
    }

    // Duplicate slice so the caller will own them since array_list are
    // deallocated.
    const stdout_dup = stdout.toOwnedSlice(allocator) catch return SetupError.DupSlice;
    const stderr_dup = stderr.toOwnedSlice(allocator) catch return SetupError.DupSlice;

    return .{
        .stdout = stdout_dup,
        .stderr = stderr_dup,
        .allocator = allocator,
    };
}
