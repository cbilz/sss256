const std = @import("std");

pub const Status = enum(u8) {
    ok = 0,
    arg_unknown = 1,
    arg_value_invalid = 2,
    threshold_exceeds_shares = 3,
    secret_empty = 4,
    share_too_long = 5,
    parse_error = 6,
    unknown_clap_error = 7,
    out_of_memory = 8,
    stdin_failed = 9,
    stdout_failed = 10,
    stderr_failed = 11,
};

pub fn exit(status: Status) noreturn {
    return std.process.exit(@intFromEnum(status));
}

pub fn oom() noreturn {
    std.debug.print("Out of memory.\n", .{});
    return std.process.exit(@intFromEnum(Status.out_of_memory));
}

pub fn stdin_failed() noreturn {
    std.debug.print("Failed to read from standard output.\n", .{});
    exit(.stdin_failed);
}

pub fn stdout_failed() noreturn {
    std.debug.print("Failed to write to standard output.\n", .{});
    exit(.stdout_failed);
}

pub fn stderr_failed() noreturn {
    std.debug.print("Failed to write to standard error.\n", .{});
    exit(.stderr_failed);
}
