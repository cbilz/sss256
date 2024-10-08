const builtin = @import("builtin");
const std = @import("std");
const assert = std.debug.assert;

const error_handling = @import("error_handling.zig");
const prelude = @import("prelude.zig");
const GF256Rijndael = @import("GF256Rijndael.zig");

/// We only use randomness directly from the operating system. This means any potential issues with
/// Zig's CSPRNG implementations should not affect us.
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

    var error_retaining_writer = error_handling.error_retaining_writer(std.io.getStdErr().writer());
    const stderr = error_retaining_writer.writer();

    stderr.writeAll("Reading secret from stdin...\n") catch {};
    const secret = readSecret(allocator, std.io.getStdIn().reader()) catch
        error_handling.stdin_failed();

    if (secret.len == 0) {
        stderr.writeAll("The secret must not be empty.\n") catch {};
        error_handling.exit(.secret_empty);
    }

    // We generate all random coefficients in advance to reduce the potential for security bugs. The
    // downside is a larger memory footprint.
    stderr.writeAll("\nRequesting random coefficients from the operating system...\n") catch {};
    const uv = @mulWithOverflow(secret.len, threshold - 1);
    if (uv[1] != 0) error_handling.oom();
    const coefficients = cryptoSecureRandomnessAlloc(allocator, uv[0]);
    assert(coefficients.len == uv[0]);

    // We print a digest of the just obtained coefficients for sanity checking by the user.
    printCoefficientDigest(stderr, coefficients);
    stderr.print(
        "Generating shares for a ({d},{d}) threshold scheme...\n",
        .{ threshold, shares },
    ) catch {};

    var bw = std.io.bufferedWriter(std.io.getStdOut().writer());
    printShares(bw.writer(), secret, coefficients, shares) catch error_handling.stdout_failed();
    bw.flush() catch error_handling.stdout_failed();

    error_retaining_writer.error_union catch error_handling.stderr_failed();
}

/// Only returns an error if reading from standard input failed.
fn readSecret(allocator: std.mem.Allocator, reader: anytype) ![]const u8 {
    var secret_list = std.ArrayList(u8).init(allocator);
    secret_list.ensureUnusedCapacity(4096) catch |err| switch (err) {
        error.OutOfMemory => error_handling.oom(),
    };

    while (true) {
        const old_len = secret_list.items.len;
        secret_list.expandToCapacity();
        const bytes_read = try reader.readAll(secret_list.items[old_len..]);

        if (old_len + bytes_read != secret_list.items.len) {
            return secret_list.items[0 .. old_len + bytes_read];
        }

        secret_list.ensureUnusedCapacity(1) catch |err| switch (err) {
            error.OutOfMemory => error_handling.oom(),
        };
    }
}

/// Allocates a slice of the specified length and fills it with random bytes obtained from the
/// operating system's cryptographically secure random number generator. Aborts on failure.
fn cryptoSecureRandomnessAlloc(allocator: std.mem.Allocator, len: usize) []const u8 {
    assert(len >= 1);

    const coefficients = allocator.alloc(u8, len) catch |err| switch (err) {
        error.OutOfMemory => error_handling.oom(),
    };

    // We fetch all random bytes directly from the operating system. It would be faster to obtain
    // just 16 or 32 random bytes from the operating system to seed a CSPRNG, but I haven't
    // thoroughly reviewed the CSPRNGs available in `std.Random` or in packages.

    switch (builtin.os.tag) {
        .linux => {
            var buf = coefficients;
            while (buf.len != 0) {
                // With a request size of at most 256 bytes, `getrandom` will only return EINTR if
                // the entropy pool has not been initialized yet.
                const request_size = @min(256, buf.len);
                const bytes_read = std.os.linux.getrandom(buf.ptr, request_size, 0);
                switch (std.os.linux.E.init(bytes_read)) {
                    .SUCCESS => {
                        if (bytes_read != request_size) break;
                        buf = buf[bytes_read..];
                    },
                    .INTR => {
                        std.debug.print(
                            "Please wait for the system to gather sufficient entropy.\n",
                            .{},
                        );
                        error_handling.exit(.no_entropy);
                    },
                    else => break,
                }
            } else return coefficients;
            std.debug.print("The system failed to provide entropy.\n", .{});
            error_handling.exit(.no_entropy);
        },
        else => @compileError("Entropy sourcing not yet implemented for this operating system.\n"),
    }
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
fn printShares(writer: anytype, secret: []const u8, coeffs: []const u8, shares: u8) !void {
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
}

fn printByteHex(writer: anytype, byte: u8) !void {
    for ([2]u8{ byte >> 4, byte & 0xf }) |digit| {
        try writer.writeByte(if (digit < 10) digit + '0' else digit - 10 + 'a');
    }
}
