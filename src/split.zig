const std = @import("std");
const assert = std.debug.assert;

const exit = @import("exit.zig");
const prelude = @import("prelude.zig");
const GF256Rijndael = @import("GF256Rijndael.zig");

// We only use randomness directly from the operating system. This means any potential issues with
// Zig's CSPRNG implementations do not affect us.
pub const std_options = .{ .crypto_always_getrandom = true };

pub fn main() void {
    // TODO: Rework how we handle stderr in the whole codebase. We should not use std.debug.print
    // because it is unbuffered and fails silently. Instead we should manage a buffer and flush it
    // at appropriate points. Also, we should think about whether stderr problems are fatal or how
    // to report them. Stderr failure should perhaps still come with a stderr message.

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const prelude_result = prelude.run(allocator, .split);
    const threshold: u8 = prelude_result.threshold;
    const shares: u8 = prelude_result.shares;

    assert(threshold >= 2);
    assert(threshold <= shares);

    std.debug.print("Reading secret from stdin...\n", .{});
    const secret = readSecret(allocator) catch exit.stdin_failed();

    if (secret.len == 0) {
        std.debug.print("The secret must not be empty.\n", .{});
        exit.exit(.secret_empty);
    }

    // We generate all random coefficients in advance to reduce the potential for security bugs. The
    // downside is a larger memory footprint.
    const uv = @mulWithOverflow(secret.len, threshold - 1);
    if (uv[1] != 0) exit.oom();
    const coefficients = getRandomCoefficients(allocator, uv[0]);
    assert(coefficients.len == uv[0]);

    // We print a digest of the just obtained coefficients for sanity checking by the human user.
    printCoefficientDigest(coefficients) catch exit.stderr_failed();

    std.debug.print(
        "Generating shares for a ({d},{d}) threshold scheme...\n",
        .{ threshold, shares },
    );
    printShares(secret, coefficients, shares) catch exit.stdout_failed();
}

/// Only returns an error if reading from standard input failed.
fn readSecret(allocator: std.mem.Allocator) ![]const u8 {
    const stdin = std.io.getStdIn().reader();

    var secret_list = std.ArrayList(u8).init(allocator);
    secret_list.ensureUnusedCapacity(4096) catch |err| switch (err) {
        error.OutOfMemory => exit.oom(),
    };

    while (true) {
        const old_len = secret_list.items.len;
        secret_list.expandToCapacity();
        const bytes_read = try stdin.readAll(secret_list.items[old_len..]);

        if (old_len + bytes_read != secret_list.items.len) {
            return secret_list.items[0 .. old_len + bytes_read];
        }

        secret_list.ensureUnusedCapacity(1) catch |err| switch (err) {
            error.OutOfMemory => exit.oom(),
        };
    }
}

/// Aborts on failure
fn getRandomCoefficients(allocator: std.mem.Allocator, len: usize) []const u8 {
    assert(len >= 1);
    const coefficients = allocator.alloc(u8, len) catch |err| switch (err) {
        error.OutOfMemory => exit.oom(),
    };
    std.crypto.random.bytes(coefficients); // Panics on failure.
    return coefficients;
}

/// Only returns an error if writing to standard error failed.
fn printCoefficientDigest(coeffs: []const u8) !void {
    var bw = std.io.bufferedWriter(std.io.getStdErr().writer());
    const stderr = bw.writer();

    try stderr.writeAll("\nRandom coefficients are ");

    const printed_coeffs = @min(6, coeffs.len);
    for (0..printed_coeffs) |k| {
        if (k == printed_coeffs / 2 and coeffs.len > printed_coeffs) {
            try stderr.writeAll("..");
        }
        const offset = if (k < printed_coeffs / 2) 0 else coeffs.len - printed_coeffs;
        try printByteHex(stderr, coeffs[offset + k]);
    }

    const Int = std.math.IntFittingRange(0, 1024 * std.math.maxInt(usize));
    var pop_count: Int = 0;
    for (coeffs) |c| {
        pop_count += @popCount(c);
    }
    const denominator = 8 * @as(Int, coeffs.len);
    const numerator = 100 * pop_count + denominator / 2;
    const percent = numerator / denominator;

    try stderr.print(" with a bit average of {d}.{d:0>2}.\n", .{ percent / 100, percent % 100 });
    try bw.flush();
}

/// Only returns an error if writing to standard output failed.
fn printShares(secret: []const u8, coeffs: []const u8, shares: u8) !void {
    var bw = std.io.bufferedWriter(std.io.getStdOut().writer());
    const writer = bw.writer();

    assert(secret.len >= 1);
    assert(coeffs.len % secret.len == 0);

    const threshold = @divExact(coeffs.len, secret.len) + 1;

    assert(threshold >= 2);
    assert(threshold <= shares);

    var index: u8 = 0;
    while (index < shares) {
        index += 1;
        try printByteHex(writer, index);
        try writer.writeByte('-');
        var coeffs_pos: usize = 0;
        for (secret) |secret_byte| {
            var y = GF256Rijndael{ .int = 0 };
            for (0..threshold - 1) |_| {
                y = y.add(.{ .int = coeffs[coeffs_pos] });
                y = y.mul(.{ .int = index });
                coeffs_pos += 1;
            }
            y = y.add(.{ .int = secret_byte });
            try printByteHex(writer, y.int);
        }
        try writer.writeByte('\n');
    }
    try bw.flush();
}

fn printByteHex(writer: anytype, byte: u8) !void {
    for ([2]u8{ byte >> 4, byte & 0xf }) |digit| {
        try writer.writeByte(if (digit < 10) digit + '0' else digit - 10 + 'a');
    }
}
