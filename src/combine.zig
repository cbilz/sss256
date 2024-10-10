const std = @import("std");
const assert = std.debug.assert;

const error_handling = @import("error_handling.zig");
const prelude = @import("prelude.zig");
const GF256Rijndael = @import("GF256Rijndael.zig");

pub fn main() void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const prelude_result = prelude.run(allocator, .combine);
    const threshold: u8 = prelude_result.threshold;
    assert(threshold >= 2);

    var error_retaining_writer = error_handling.error_retaining_writer(std.io.getStdErr().writer());
    const stderr = error_retaining_writer.writer();

    stderr.print("Reading {d} shares from stdin...\n", .{threshold}) catch {};
    var br = std.io.bufferedReader(std.io.getStdIn().reader());
    const shares = readShares(allocator, br.reader(), stderr, threshold) catch
        error_handling.stdin_failed();

    stderr.writeAll("Reconstructing secret...\n") catch {};
    var bw = std.io.bufferedWriter(std.io.getStdOut().writer());
    printSecret(bw.writer(), shares, threshold) catch error_handling.stdout_failed();
    bw.flush() catch error_handling.stdout_failed();

    error_retaining_writer.error_union catch error_handling.stderr_failed();
}

/// Only returns an error if reading from standard input failed. Ignores errors returned by
/// `log_writer`.
fn readShares(
    allocator: std.mem.Allocator,
    reader: anytype,
    log_writer: anytype,
    threshold: u8,
) ![]const u8 {
    var coords = std.ArrayList(u8).init(allocator);
    var secret_len = @as(usize, std.math.maxInt(usize)) / threshold - 1;

    // This loop reads the shares, one per line.
    for (0..threshold) |line| {
        // This loop reads the tokens on each line:
        //
        //   - The first token should be a pair of hexadecimal digits indicating the share index.
        //   - The second token should to be a single hyphen separating index and data.
        //   - One or more pairs of hexadecimal digits should follow. This is the share data. Each
        //     share should have the same number of data digit pairs, equal to the length of the
        //     secret.
        //   - The last token should be a line feed.
        //
        // The length of the secret is not known until the first line was parsed. This means that we
        // will likely break out of `token_loop` early during the first iteration of `line_loop`.
        token_loop: for (0..secret_len + 3) |token_index| {
            var coefficient: u8 = 0;

            byte_loop: for (0..2) |byte_index| {
                const byte_optional: ?u8 = reader.readByte() catch |err| switch (err) {
                    error.EndOfStream => null,
                    else => return err,
                };

                // We break out from the following if-else chain if and only if `byte_optional` is
                // valid in the current context. Otherwise we print a message explaining what was
                // expected.

                if (token_index == 1) {
                    assert(byte_index == 0);

                    if (byte_optional == '-') {
                        continue :token_loop;
                    } else {
                        log_writer.writeAll("Expected hyphen") catch {};
                    }
                } else if (token_index == secret_len + 2) {
                    assert(byte_index == 0);

                    if (byte_optional == '\n') {
                        break :token_loop;
                    } else if (line == 0) {
                        log_writer.writeAll(
                            "Share too long. Please reconstruct shorter segments.\n",
                        ) catch {};
                        error_handling.exit(.share_too_long);
                    } else {
                        log_writer.writeAll("Expected line feed") catch {};
                    }
                } else if (asHexDigit(byte_optional)) |digit| {
                    coefficient = coefficient * 16 + digit;
                    continue :byte_loop;
                } else if (line == 0 and token_index >= 3 and byte_index == 0) {
                    if (byte_optional == '\n') {
                        secret_len = token_index - 2;
                        break :token_loop;
                    }
                    log_writer.writeAll("Expected hex digit or line feed") catch {};
                } else {
                    log_writer.writeAll("Expected hex digit") catch {};
                }

                // A parsing error has occured. We now also print a message explaining what the
                // invalid input was.

                if (byte_optional) |byte| {
                    if (controlCodeAbbreviation(byte)) |abbrev| {
                        log_writer.print(
                            ", but found control code {s} (hex 0x{x:0>2}) ",
                            .{ abbrev, byte },
                        ) catch {};
                    } else if (byte < 0x80) {
                        // The byte is a printable ASCII character.
                        log_writer.print(", but found '{c}' ", .{byte}) catch {};
                    } else {
                        log_writer.print(", but found non-ASCII byte 0x{x:0<2} ", .{byte}) catch {};
                    }
                } else {
                    log_writer.writeAll(", but reached the end of input ") catch {};
                }

                log_writer.print("on line {d}, column {d}.\n", .{
                    line + 1,
                    2 * token_index + @intFromBool(token_index <= 1) + byte_index,
                }) catch {};
                error_handling.exit(.parse_error);
            }

            assert(token_index != 1);
            assert(token_index <= secret_len + 1);

            if (token_index == 0) {
                if (coefficient == 0) {
                    log_writer.print(
                        "Share on line {d} has the invalid index 0x00.\n",
                        .{line + 1},
                    ) catch {};
                    error_handling.exit(.parse_error);
                }
                for (coords.items[0..line], 0..) |index, other_line| {
                    if (coefficient == index) {
                        log_writer.print(
                            "Shares on lines {d} and {d} have the same index 0x{x:0<2}.\n",
                            .{ other_line + 1, line + 1, coefficient },
                        ) catch {};
                        error_handling.exit(.parse_error);
                    }
                }
            }

            if (line == 0) {
                coords.resize(threshold * @max(1, token_index)) catch |err| switch (err) {
                    error.OutOfMemory => error_handling.oom(),
                };
            }

            coords.items[threshold * (token_index -| 1) + line] = coefficient;
        } else unreachable;
    }

    return coords.items;
}

/// Only returns an error if writing to standard output failed.
fn printSecret(writer: anytype, shares: []const u8, threshold: u8) !void {
    assert(shares.len >= 2 * @as(usize, threshold));
    assert(shares.len % threshold == 0);

    const indices = shares[0..threshold];
    const data = shares[threshold..];
    const secret_len = @divExact(data.len, threshold);

    for (0..secret_len) |pos| {
        var s = GF256Rijndael{ .int = 0 };

        for (indices, data[threshold * pos ..][0..threshold], 0..) |xi_int, yi_int, i| {
            const xi = GF256Rijndael{ .int = xi_int };
            const yi = GF256Rijndael{ .int = yi_int };

            var summand = yi;
            for (indices, 0..) |xj_int, j| {
                if (i == j) continue;
                const xj = GF256Rijndael{ .int = xj_int };
                summand = summand.mul(xj).mul(xj.add(xi).inv());
            }
            s = s.add(summand);
            assert(summand.int != 0 or yi.int == 0);
        }

        try writer.writeByte(s.int);
    }
}

fn asHexDigit(byte_optional: ?u8) ?u4 {
    if (byte_optional) |byte| {
        return switch (byte) {
            '0'...'9' => @intCast(byte - '0'),
            'A'...'F' => @intCast(byte - 'A' + 10),
            'a'...'f' => @intCast(byte - 'a' + 10),
            else => null,
        };
    } else return null;
}

fn controlCodeAbbreviation(byte: u8) ?[:0]const u8 {
    return switch (byte) {
        0x00 => "NUL",
        0x01 => "SOH",
        0x02 => "STX",
        0x03 => "ETX",
        0x04 => "EOT",
        0x05 => "ENQ",
        0x06 => "ACK",
        0x07 => "BEL",
        0x08 => "BS",
        0x09 => "HT",
        0x0a => "LF",
        0x0b => "VT",
        0x0c => "FF",
        0x0d => "CR",
        0x0e => "SO",
        0x0f => "SI",
        0x10 => "DLE",
        0x11 => "DC1",
        0x12 => "DC2",
        0x13 => "DC3",
        0x14 => "DC4",
        0x15 => "NAK",
        0x16 => "SYN",
        0x17 => "ETB",
        0x18 => "CAN",
        0x19 => "EM",
        0x1a => "SUB",
        0x1b => "ESC",
        0x1c => "FS",
        0x1d => "GS",
        0x1e => "RS",
        0x1f => "US",
        0x7f => "DEL",
        else => null,
    };
}
