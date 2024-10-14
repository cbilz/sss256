const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const clap = b.dependency("clap", .{
        .target = target,
        .optimize = optimize,
    });

    inline for (&.{ "split", "combine" }) |command| {
        const exe = b.addExecutable(.{
            .name = "sss256-" ++ command,
            .root_source_file = b.path("src/" ++ command ++ ".zig"),
            .target = target,
            .optimize = optimize,
        });
        exe.root_module.addImport("clap", clap.module("clap"));
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("run-" ++ command, "Run " ++ command);
        run_step.dependOn(&run_cmd.step);
    }

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(exe_unit_tests).step);
}
