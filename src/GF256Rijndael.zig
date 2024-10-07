//! The finite field GF(256) with the Rijndael polynomial x^8 + x^4 + x^3 + x + 1 as the reducing
//! polynomial.

const std = @import("std");
const assert = std.debug.assert;

const GF256Rijndael = @This();

/// The element of the field expressed as a binary number.
int: u8,

/// The polynomial x^4 + x^3 + x + 1, i.e. the Rijndael polynomial with the high term eliminated.
const p: u8 = 0x1b;

pub fn add(x: GF256Rijndael, y: GF256Rijndael) GF256Rijndael {
    return .{ .int = x.int ^ y.int };
}

pub fn mul(x: GF256Rijndael, y: GF256Rijndael) GF256Rijndael {
    if (x.int == 0 or y.int == 0) return .{ .int = 0 };
    return exp(@as(usize, log(x)) + log(y));
}

pub fn inv(x: GF256Rijndael) GF256Rijndael {
    assert(x.int != 0);
    return exp(255 - log(x));
}

/// Logarithm with base {3}. The return value is at least 0 and at most 254.
fn log(x: GF256Rijndael) u8 {
    assert(x.int != 0);
    return logexp_table[x.int];
}

/// Exponential with base {3}. Asserts that the exponent is at most 508.
fn exp(exponent: usize) GF256Rijndael {
    assert(exponent < 509);
    return .{ .int = logexp_table[exponent + 256] };
}

// log(0) invalid, then log(1) to log(255), then exp(0) to exp(508), all with base {3}.
const logexp_table: [256 + 509]u8 = blk: {
    var res = [1]u8{0} ** (256 + 509);
    res[0] = 0xaa; // do not try to read log(0)
    var x_int: u8 = 1;
    for (0..255) |exponent| {
        assert(res[x_int] == 0);

        res[x_int] = exponent; // log(.{ .int = x_int }) = exponent
        res[exponent + 256] = x_int; // exp(exponent) = .{ .int = x_int }

        if (exponent < 254) {
            res[exponent + 255 + 256] = x_int; // exp(exponent + 255) = .{ .int = x_int }
        }

        // Multiply with x + 1.
        x_int = x_int ^ (x_int << 1) ^ if (x_int & 0x80 != 0) p else 0;
    }
    assert(x_int == 1);
    break :blk res;
};

test "exhaustive check of field axioms" {
    for (0..256) |x_int| {
        const x = GF256Rijndael{ .int = @intCast(x_int) };

        // neutral elements
        try std.testing.expectEqual(x.int, x.add(.{ .int = 0 }).int);
        try std.testing.expectEqual(x.int, x.mul(.{ .int = 1 }).int);

        // inverses
        try std.testing.expectEqual(0, x.add(x).int);
        if (x.int != 0) {
            try std.testing.expectEqual(1, x.mul(x.inv()).int);
        }

        for (0..256) |y_int| {
            const y = GF256Rijndael{ .int = @intCast(y_int) };
            const xy = x.mul(y);

            // Commutativity. By symmetry it suffices to check this in the case `x.int < y.int`.
            if (x.int < y.int) {
                try std.testing.expectEqual(x.add(y).int, y.add(x).int);
                try std.testing.expectEqual(xy.int, y.mul(x).int);
            }

            for (0..256) |z_int| {
                const z = GF256Rijndael{ .int = @intCast(z_int) };

                // Associativity. It suffices to check this in the case `x.int < z.int` because we
                // independently verify commutativity.
                if (x.int < z.int) {
                    try std.testing.expectEqual(x.add(y.add(z)).int, (x.add(y)).add(z).int);
                    try std.testing.expectEqual(x.mul(y.mul(z)).int, xy.mul(z).int);
                }

                // Distributivity. It suffices to check this in the case `y.int <= z.int` because we
                // independently verify commutativity.
                if (y.int <= z.int) {
                    try std.testing.expectEqual(x.mul(y.add(z)).int, xy.add(x.mul(z)).int);
                }
            }
        }
    }
}
