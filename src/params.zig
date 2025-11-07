const std = @import("std");

const Opt = enum { help, iface };

pub fn getArg(str: []const u8) ?Opt {
    const args_map = std.StaticStringMap(Opt).initComptime(.{
        .{ "--help", .help },
        .{ "--iface", .iface },
    });
    return args_map.get(str);
}

pub const ArgsError = error{
    IfaceMissing,
    IfaceArgMissing,
    NoParams,
    Help,
};

pub const Args = struct {
    iface: [:0]const u8,

    pub fn parse(it: *std.process.ArgIterator) ArgsError!Args {
        // First argument is the program name
        const progname = it.next() orelse unreachable;

        var iface_opt: ?[:0]const u8 = null;

        while (it.next()) |arg| {
            switch (getArg(arg) orelse {
                usage(progname);
                return ArgsError.NoParams;
            }) {
                .help => {
                    usage(progname);
                    return ArgsError.Help;
                },
                .iface => iface_opt = it.next() orelse {
                    usage(progname);
                    return ArgsError.IfaceArgMissing;
                },
            }
        }

        if (iface_opt == null) {
            usage(progname);
            return ArgsError.IfaceMissing;
        }

        return .{
            .iface = iface_opt.?,
        };
    }
};

fn usage(prog: []const u8) void {
    std.debug.print(
        \\USAGE:
        \\  {s} --iface <interface>
        \\
        \\DESCRIPTION:
        \\  If <interface> does not exist, a virtual Ethernet pair will be created:
        \\    <interface> <-> <interface>-peer
        \\
        \\  The program will then listen on <interface>-peer for incoming Ethernet frames.
        \\  The MAC addresses are discovered automatically.
        \\
        \\EXAMPLES:
        \\  sudo {s} --iface veth0
        \\
        \\NOTES:
        \\  - Requires CAP_NET_ADMIN and CAP_NET_RAW privileges.
        \\  - The virtual pair is created using:
        \\        ip link add <iface> type veth peer name <iface>-peer
        \\  - This is useful for testing or simulating low-level networking (e.g., ARP, ICMP).
        \\
    ,
        .{ prog, prog },
    );
}
