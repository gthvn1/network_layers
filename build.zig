const std = @import("std");

pub fn build(b: *std.Build) !void {
    const exe = b.addExecutable((.{
        .name = "netl2",
        .root_module = b.createModule(.{
            .root_source_file = b.path("./src/main.zig"),
            .target = b.standardTargetOptions(.{}),
        }),
    }));

    exe.linkLibC();
    b.installArtifact(exe);
}
