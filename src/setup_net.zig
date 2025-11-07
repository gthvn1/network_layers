const std = @import("std");

const Interface = struct {
    ifindex: i32,
    ifname: []const u8,
    flags: []const []const u8,
    mtu: i32,
    qdisc: []const u8,
    master: ?[]const u8 = null,
    operstate: []const u8,
    linkmode: []const u8,
    group: []const u8,
    txqlen: ?i32 = null,
    link_type: []const u8,
    address: ?[]const u8 = null,
    broadcast: ?[]const u8 = null,
    altnames: ?[]const []const u8 = null,
};

pub fn check_veth(allocator: std.mem.Allocator) !void {
    const Child = std.process.Child;
    const argv = [_][]const u8{
        "ip",
        "-j",
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
    try child.collectOutput(allocator, &stdout, &stderr, 4096);
    const term = try child.wait();

    try std.testing.expectEqual(term.Exited, 0);

    // Try to parse the output
    const interfaces = try std.json.parseFromSlice([]Interface, allocator, stdout.items, .{});
    defer interfaces.deinit();

    for (interfaces.value) |iface| {
        std.log.debug("iface:{s}", .{iface.ifname});
    }
}
