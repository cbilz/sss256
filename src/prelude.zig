const std = @import("std");
const debug = std.debug;

const clap = @import("clap");

const exit = @import("exit.zig");

pub const Command = enum {
    split,
    combine,
};

const params_split_str =
    \\-h, --help                Show this help message and exit.
    \\-t, --threshold <2..255>  Number of shares required to reconstruct the secret.
    \\-n, --shares <2..255>     Total number of shares to generate.
    \\
;
const params_combine_str =
    \\-h, --help                Show this help message and exit.
    \\-t, --threshold <2..255>  Must match the threshold used during share generation.
    \\
;
const parsers = .{ .@"2..255" = clap.parsers.int(u8, 10) };

pub fn PreludeResult(command: Command) type {
    return switch (command) {
        .split => struct {
            threshold: u8,
            shares: u8,
        },
        .combine => struct {
            threshold: u8,
        },
    };
}

pub fn run(allocator: std.mem.Allocator, comptime command: Command) PreludeResult(command) {
    const params = comptime clap.parseParamsComptime(switch (command) {
        .split => params_split_str,
        .combine => params_combine_str,
    });

    var iter = try std.process.argsWithAllocator(allocator);
    defer iter.deinit();

    const exe_arg = iter.next() orelse "sss256-" ++ @tagName(command);

    // We catch help flags before calling into `clap` so that issues with any other parameters do
    // not prevent the output of help.

    if (isHelpRequired(allocator)) {
        printHelp(command, &params, exe_arg) catch exit.stderr_failed();
        exit.exit(.ok);
    }

    var diag = clap.Diagnostic{};
    const res = clap.parseEx(clap.Help, &params, parsers, &iter, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        switch (err) {
            error.InvalidCharacter, error.MissingValue, error.Overflow => {
                exitArgValueInvalid(command);
            },
            error.InvalidArgument => {
                const longest = diag.name.longest();
                debug.print("Invalid argument '{s}{s}'.\n", .{
                    longest.kind.prefix(),
                    switch (longest.kind) {
                        .short, .long => longest.name,
                        .positional => diag.arg,
                    },
                });
                exit.exit(.arg_unknown);
            },
            else => {
                debug.print(
                    "Unhandled {s} error while parsing command line arguments.\n",
                    .{@errorName(err)},
                );
                exit.exit(.unknown_clap_error);
            },
        }
        unreachable;
    };

    debug.assert(res.args.help == 0);

    const threshold = res.args.threshold orelse 0;
    if (threshold < 2) exitArgValueInvalid(command);

    return switch (command) {
        .split => blk: {
            const shares = res.args.shares orelse 0;
            if (shares < 2) exitArgValueInvalid(command);
            if (threshold > shares) {
                debug.print("The threshold must not exceed the number of shares.\n", .{});
                exit.exit(.threshold_exceeds_shares);
            }
            break :blk .{ .threshold = threshold, .shares = shares };
        },
        .combine => .{ .threshold = threshold },
    };
}

fn isHelpRequired(allocator: std.mem.Allocator) bool {
    // ArgIterator's public API does not support resetting, so we need an iterator separate from
    // the one used in the caller.
    var iter: std.process.ArgIterator = try std.process.argsWithAllocator(allocator);
    defer iter.deinit();

    // Skip the exe argument.
    _ = iter.next();

    var no_args = true;
    while (iter.next()) |arg| {
        if (std.mem.eql(u8, "--help", arg) or std.mem.eql(u8, "-h", arg)) {
            return true;
        }
        no_args = false;
    }
    return no_args;
}

fn printHelp(
    comptime command: Command,
    params: []const clap.Param(clap.Help),
    exe_arg: []const u8,
) !void {
    var bw = std.io.bufferedWriter(std.io.getStdErr().writer());
    const writer = bw.writer();

    try writer.writeAll("Usage: sss256-" ++ @tagName(command) ++ " ");
    try clap.usage(writer, clap.Help, params);
    try writer.writeAll("\n\n");

    try writer.writeAll(comptime switch (command) {
        .split =>
        \\Split a secret into multiple shares using Shamir's secret sharing
        \\scheme. Use the sss256-combine tool to reconstruct the secret.
        \\
        \\Bytes of the secret can only be reconstructed when corresponding
        \\bytes from a user-specified threshold number of shares, along with the
        \\indices of the shares, are known.
        \\
        \\The secret is read from standard input, and the shares are written to
        \\standard output. Each share consists of an index and a byte sequence
        \\of the same length as the secret, both written in hexadecimal format.
        \\
        \\A digest of the cryptographically secure random bytes used is printed
        \\to standard error for sanity checking.
        \\
        \\Options:
        \\
        \\
        ,
        .combine =>
        \\Reconstruct a secret from shares generated by the sss256-split tool
        \\using Shamir's secret sharing scheme.
        \\
        \\A threshold number of shares is required to reconstruct the secret.
        \\Even if only partial data is available from the required number of
        \\shares, corresponding bytes of the secret can still be recovered.
        \\
        \\Shares are read from standard input, one per line. Any input beyond
        \\the threshold number of lines is ignored. The reconstructed secret is
        \\written to standard output.
        \\
        \\Options:
        \\
        \\
        ,
    });

    try clap.help(writer, clap.Help, params, .{});

    try writer.print(comptime switch (command) {
        .split =>
        \\
        \\Example:
        \\
        \\    $ {s} --threshold=3 --shares=5
        \\
        ,
        .combine =>
        \\
        \\Example:
        \\
        \\    $ {s} --threshold=3
        \\
    }, .{exe_arg});

    try bw.flush();
}

fn exitArgValueInvalid(comptime command: Command) noreturn {
    debug.print(comptime switch (command) {
        .split => "Numbers between 2 and 255 must be passed to " ++
            "--threshold (or -t) and --shares (or -n).\n",
        .combine => "A number between 2 and 255 must be passed to " ++
            "--threshold (or -t).\n",
    }, .{});
    exit.exit(.arg_value_invalid);
}
