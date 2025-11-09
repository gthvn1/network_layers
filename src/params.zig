const std = @import("std");

const Opt = enum { help, iface, ip };

pub fn getArg(str: []const u8) ?Opt {
    const args_map = std.StaticStringMap(Opt).initComptime(.{
        .{ "--help", .help },
        .{ "--iface", .iface },
        .{ "--ip", .ip },
    });
    return args_map.get(str);
}

pub const ArgsError = error{
    IfaceMissing,
    IfaceArgMissing,
    IpMissing,
    IpArgMissing,
    NoParams,
    Help,
};

pub const Args = struct {
    iface: [:0]const u8,
    ip: [:0]const u8,

    pub fn parse(it: *std.process.ArgIterator) ArgsError!Args {
        // First argument is the program name
        const progname = it.next() orelse unreachable;

        var iface_opt: ?[:0]const u8 = null;
        var ip_opt: ?[:0]const u8 = null;

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
                .ip => ip_opt = it.next() orelse {
                    usage(progname);
                    return ArgsError.IpArgMissing;
                },
            }
        }

        if (iface_opt == null and ip_opt == null) {
            usage(progname);
            return ArgsError.NoParams;
        }

        if (iface_opt == null) {
            usage(progname);
            return ArgsError.IfaceMissing;
        }

        if (ip_opt == null) {
            usage(progname);
            return ArgsError.IpMissing;
        }

        return .{
            .iface = iface_opt.?,
            .ip = ip_opt.?,
        };
    }
};

fn usage(prog: []const u8) void {
    std.debug.print(
        \\USAGE:
        \\  {s} --iface <interface> --ip <ipv4 address>
        \\
        \\DESCRIPTION:
        \\  If <interface> does not exist, a virtual Ethernet pair will be
        \\  created: <interface> <-> <interface>-peer
        \\  Otherwise, the existing interface is used.
        \\
        \\  The IP address must be in CIDR notation (xx.xx.xx.xx/yy). This
        \\  address will be assigned to <interfacce>.
        \\ 
        \\  The program will then listen on <interface>-peer for incoming Ethernet frames.
        \\  The MAC addresses are discovered automatically.
        \\
        \\EXAMPLES:
        \\  sudo {s} --iface veth0 --ip 192.168.38.2/24
        \\
        \\NOTES:
        \\  - Requires root privileges or CAP_NET_ADMIN and CAP_NET_RAW capabilites.
        \\  - The virtual pair is created using:
        \\        ip link add <iface> type veth peer name <iface>-peer
        \\  - Useful for testing or simulating Layer 2 protocols (e.g., ARP).
        \\
    ,
        .{ prog, prog },
    );
}
