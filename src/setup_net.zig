const std = @import("std");
const ethernet = @import("ethernet.zig");

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

pub fn getOrCreateVeth(allocator: std.mem.Allocator, name: []const u8) !VirtPair {
    const peer_name = try std.fmt.allocPrint(allocator, "{s}-peer", .{name});
    defer allocator.free(peer_name);

    var vp = VirtPair{
        .mac = [_]u8{0} ** 6,
        .mac_peer = [_]u8{0} ** 6,
    };

    // First check if it exists
    if (try getDeviceMac(allocator, name, &vp.mac)) {
        // If we found interface "name" we are expecting to find its peer
        if (try getDeviceMac(allocator, peer_name, &vp.mac_peer)) {
            return vp;
        }
        return error.PeerNotFound;
    }

    // We need to create virtual pair first
    const cmd = [_][]const u8{
        "ip",
        "link",
        "add",
        name,
        "type",
        "veth",
        "peer",
        "name",
        peer_name,
    };

    var res = try runCmd(allocator, &cmd);
    defer res.deinit();

    if (res.stderr.len != 0) {
        std.log.err("{s}", .{res.stderr});
    }

    // Now we can get the MAC
    if (try getDeviceMac(allocator, name, &vp.mac)) {
        // If we found interface "name" we are expecting to find its peer
        if (try getDeviceMac(allocator, peer_name, &vp.mac_peer)) {
            return vp;
        }
        return error.PeerNotFoundAndNotExpected;
    }

    return error.VethMacFailed;
}

fn getDeviceMac(allocator: std.mem.Allocator, name: []const u8, buf: *[6]u8) !bool {
    const cmd = [_][]const u8{ "ip", "-j", "link", "show", name };
    var res = try runCmd(allocator, &cmd);
    defer res.deinit();

    const interfaces = try std.json.parseFromSlice([]Interface, allocator, res.stdout, .{});
    defer interfaces.deinit();

    if (interfaces.value.len == 0) return false;
    if (interfaces.value.len > 1) {
        std.log.err("we found {d} devices for {s}", .{ interfaces.value.len, name });
        return false;
    }

    const iface = interfaces.value[0];
    if (std.mem.eql(u8, name, iface.ifname)) {
        if (iface.address) |addr| {
            try ethernet.stringToMac(addr, buf);
            return true;
        }
    }

    return false;
}

fn runCmd(allocator: std.mem.Allocator, command: []const []const u8) !CmdOutput {
    const Child = std.process.Child;

    // Child inherir stdout & stderr
    var child = Child.init(command, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    var stdout: std.array_list.Aligned(u8, null) = .empty;
    defer stdout.deinit(allocator);
    var stderr: std.array_list.Aligned(u8, null) = .empty;
    defer stderr.deinit(allocator);

    try child.spawn();
    try child.collectOutput(allocator, &stdout, &stderr, 4096);
    const term = try child.wait();

    if (term.Exited != 0) {
        std.log.err("Command exited with code {}", .{term.Exited});
        return error.CommandFailed;
    }

    // Duplicate slice so the caller will own them since array_list are
    // deallocated.
    const stdout_dup = try stdout.toOwnedSlice(allocator);
    const stderr_dup = try stderr.toOwnedSlice(allocator);

    return .{
        .stdout = stdout_dup,
        .stderr = stderr_dup,
        .allocator = allocator,
    };
}
