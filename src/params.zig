const std = @import("std");

const Opt = enum { help, iface, mac };

pub fn getArg(str: []const u8) ?Opt {
    const args_map = std.StaticStringMap(Opt).initComptime(.{
        .{ "--help", .help },
        .{ "--iface", .iface },
        .{ "--mac", .mac },
    });
    return args_map.get(str);
}

pub const ArgsError = error{ IfaceMissing, IfaceArgMissing, MacMissing, MacArgMissing, NoArgs, Help };

pub const Args = struct {
    iface: [:0]const u8,
    mac: [:0]const u8,

    pub fn parse(it: *std.process.ArgIterator) ArgsError!Args {
        // First argument is the program name
        const progname = it.next() orelse unreachable;

        var iface_opt: ?[:0]const u8 = null;
        var mac_opt: ?[:0]const u8 = null;

        while (it.next()) |arg| {
            switch (getArg(arg) orelse {
                usage(progname);
                return ArgsError.NoArgs;
            }) {
                .help => {
                    usage(progname);
                    return ArgsError.Help;
                },
                .iface => iface_opt = it.next() orelse {
                    usage(progname);
                    return ArgsError.IfaceArgMissing;
                },
                .mac => mac_opt = it.next() orelse {
                    usage(progname);
                    return ArgsError.MacArgMissing;
                },
            }
        }

        if (iface_opt == null) {
            usage(progname);
            return ArgsError.IfaceMissing;
        }

        if (mac_opt == null) {
            usage(progname);
            return ArgsError.MacMissing;
        }

        return .{
            .iface = iface_opt.?,
            .mac = mac_opt.?,
        };
    }
};

fn usage(prog: []const u8) void {
    std.debug.print(
        "USAGE: {s} --iface <interface> --mac <mac address>\n",
        .{prog},
    );
}
