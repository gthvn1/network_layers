const std = @import("std");

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

pub fn createVeth(allocator: std.mem.Allocator, name: []const u8) !void {
    if (try checkVeth(allocator, name)) return;

    const peer_name = try std.fmt.allocPrint(allocator, "{s}-peer", .{name});
    defer allocator.free(peer_name);

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
}

pub fn checkVeth(allocator: std.mem.Allocator, name: []const u8) !bool {
    const cmd = [_][]const u8{ "ip", "-j", "link" };
    var res = try runCmd(allocator, &cmd);
    defer res.deinit();

    const interfaces = try std.json.parseFromSlice([]Interface, allocator, res.stdout, .{});
    defer interfaces.deinit();

    for (interfaces.value) |iface| {
        if (std.mem.eql(u8, name, iface.ifname)) {
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
