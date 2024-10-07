const std = @import("std");
const assert = std.debug.assert;

const common = @import("common.zig");
const prelude = @import("prelude.zig");
const GF256Rijndael = @import("GF256Rijndael.zig");

// We only use randomness directly from the operating system. This means any potential issues with
// Zig's CSPRNG implementations do not affect us.
pub const std_options = .{ .crypto_always_getrandom = true };

pub fn main() void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const prelude_result = prelude.run(allocator, .split);
    const threshold: u8 = prelude_result.threshold;
    const shares: u8 = prelude_result.shares;

    assert(threshold >= 2);
    assert(threshold <= shares);

    var error_retaining_writer = common.error_retaining_writer(std.io.getStdErr().writer());
    const stderr = error_retaining_writer.writer();

    stderr.writeAll("Reading secret from stdin...\n") catch {};
    const secret = readSecret(allocator) catch common.stdin_failed();

    if (secret.len == 0) {
        stderr.writeAll("The secret must not be empty.\n") catch {};
        common.exit(.secret_empty);
    }

    // We generate all random coefficients in advance to reduce the potential for security bugs. The
    // downside is a larger memory footprint.
    stderr.writeAll("\nRequesting random coefficients from the operating system...\n") catch {};
    const uv = @mulWithOverflow(secret.len, threshold - 1);
    if (uv[1] != 0) common.oom();
    const coefficients = getRandomCoefficients(allocator, uv[0]);
    assert(coefficients.len == uv[0]);

    // We print a digest of the just obtained coefficients for sanity checking by the user.
    printCoefficientDigest(stderr, coefficients);
    stderr.print(
        "Generating shares for a ({d},{d}) threshold scheme...\n",
        .{ threshold, shares },
    ) catch {};

    printShares(secret, coefficients, shares) catch common.stdout_failed();

    error_retaining_writer.error_union catch common.stderr_failed();
}

/// Only returns an error if reading from standard input failed.
fn readSecret(allocator: std.mem.Allocator) ![]const u8 {
    const stdin = std.io.getStdIn().reader();

    var secret_list = std.ArrayList(u8).init(allocator);
    secret_list.ensureUnusedCapacity(4096) catch |err| switch (err) {
        error.OutOfMemory => common.oom(),
    };

    while (true) {
        const old_len = secret_list.items.len;
        secret_list.expandToCapacity();
        const bytes_read = try stdin.readAll(secret_list.items[old_len..]);

        if (old_len + bytes_read != secret_list.items.len) {
            return secret_list.items[0 .. old_len + bytes_read];
        }

        secret_list.ensureUnusedCapacity(1) catch |err| switch (err) {
            error.OutOfMemory => common.oom(),
        };
    }
}

/// Aborts on failure
fn getRandomCoefficients(allocator: std.mem.Allocator, len: usize) []const u8 {
    assert(len >= 1);
    const coefficients = allocator.alloc(u8, len) catch |err| switch (err) {
        error.OutOfMemory => common.oom(),
    };
    std.crypto.random.bytes(coefficients); // Panics on failure.
    return coefficients;
}

/// Silently ignores write errors. Use an error accumulating writer with this function.
fn printCoefficientDigest(writer: anytype, coeffs: []const u8) void {
    writer.writeAll("Random coefficients are ") catch {};

    const printed_coeffs = @min(6, coeffs.len);
    for (0..printed_coeffs) |k| {
        if (k == printed_coeffs / 2 and coeffs.len > printed_coeffs) {
            writer.writeAll("..") catch {};
        }
        const offset = if (k < printed_coeffs / 2) 0 else coeffs.len - printed_coeffs;
        printByteHex(writer, coeffs[offset + k]) catch {};
    }

    const Int = std.math.IntFittingRange(0, 1024 * std.math.maxInt(usize));
    var pop_count: Int = 0;
    for (coeffs) |c| {
        pop_count += @popCount(c);
    }
    const denominator = 8 * @as(Int, coeffs.len);
    const numerator = 100 * pop_count + denominator / 2;
    const percent = numerator / denominator;

    writer.print(
        " with a bit average of {d}.{d:0>2}.\n",
        .{ percent / 100, percent % 100 },
    ) catch {};
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
