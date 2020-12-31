const std = @import("std");
const RC4 = @import("./rc4.zig").RC4;

const fs = std.fs;
const io = std.io;

const Options = struct {
    key: ?[]const u8 = null,

    decrypt_flag: bool = false,
    file_flag: bool = false,
    text_flag: bool = false,
    file: ?[]const u8 = null,
    text: ?[]const u8 = null,
};

fn printHelp(stdout: fs.File) !void {
    try stdout.writer().writeAll("rc4 <keyword> [-d] [-t text] [-f file]\n");
}

pub fn main() !void {
    var allocator = std.testing.allocator; // TODO don't do this
    var args = std.process.argsAlloc(allocator) catch |err| {
        std.log.err("failed to allocate memory to parse args: {}", .{err});
        return;
    };
    defer std.process.argsFree(allocator, args);

    var stdout = io.getStdOut();
    if (args.len < 2) { // we require a key
        try printHelp(stdout);
        return;
    }

    var opts = Options{};
    for (args) |arg, idx| {
        if (idx == 0) continue; // skip the program itself
        if (opts.key == null) {
            opts.key = arg;
            continue;
        }
        if (arg.len < 2) { // arg is too small
            try printHelp(stdout);
            return;
        }
        if (arg[0] == '-') { // flags
            if (arg[1] == 'd') {
                opts.decrypt_flag = true;
                continue;
            }

            if (arg[1] == 't') {
                opts.text_flag = true;
            } else if (arg[1] == 'f') {
                opts.file_flag = true;
            } else {
                try printHelp(stdout);
                return;
            }
            if (opts.text_flag and opts.file_flag) {
                try printHelp(stdout);
                return;
            }
        } else {
            if (opts.text_flag and opts.text == null) {
                opts.text = arg;
            } else if (opts.file_flag and opts.file == null) {
                opts.file = arg;
            } else {
                try printHelp(stdout);
                return;
            }
        }
    }

    if (opts.key == null or (opts.file == null and opts.text == null)) {
        try printHelp(stdout);
        return;
    }

    var rc4 = RC4.init(opts.key.?);
    if (opts.text_flag) {
        if (opts.decrypt_flag) { // need to convert hex back to bytes
            var input_text = opts.text.?;
            var text = allocator.alloc(u8, input_text.len / 2) catch |err| {
                std.log.err("failed to allocate memory: {}", .{err});
                return;
            };
            std.fmt.hexToBytes(text[0..], input_text) catch |err| switch (err) {
                error.InvalidCharacter => {
                    std.log.err("invalid ciphertext -- should be hex", .{});
                    return;
                },
                error.InvalidLength => {
                    std.log.err("invalid hex provided -- length is odd", .{});
                    return;
                },
            };

            opts.text = text;
        }
        var input_text = opts.text.?;
        var out = allocator.alloc(u8, input_text.len) catch |err| {
            std.log.err("failed to allocate memory: {}", .{err});
            return;
        };
        rc4.encrypt(out, input_text);
        if (opts.decrypt_flag) {
            try stdout.writer().print("{}", .{out});
        } else {
            try stdout.writer().print("{x}", .{out});
        }
        return;
    }
}
