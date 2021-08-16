const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

fn nullTermPtrToSlice(comptime T: type, ptr: [*:0]T) []T {
    var len: usize = 0;
    while (ptr[len] != 0) : (len += 1) {}
    var ret: []u8 = undefined;
    ret.len = len;
    ret.ptr = ptr;
    return ret;
}

pub fn main() !u8 {
    if (std.os.argv.len < 2) {
        std.log.err(
            \\Usage:
                \\Generate key pair: {0s} -g <public key> <secret key>
                \\Sign stdin: {0s} -s <public key> <secret key>
                \\Verify stdin: {0s} -v <public key>
                , .{std.os.argv[0]});
        return 1;
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = &gpa.allocator;

    const cmd = nullTermPtrToSlice(u8, std.os.argv[1]);
    const dir = std.fs.cwd();

    if (std.mem.eql(u8, cmd, "-g")) {
        const kp = try Ed25519.KeyPair.create(null);

        // write public key
        const public_file = try dir.createFile(
            nullTermPtrToSlice(u8, std.os.argv[2]),
            .{ .truncate = true, .mode = 0o644 },
        );
        defer public_file.close();
        try public_file.writeAll(&kp.public_key);

        // write secret key
        const secret_file = try dir.createFile(
            nullTermPtrToSlice(u8, std.os.argv[3]),
            .{ .truncate = true, .mode = 0o600 },
        );
        defer secret_file.close();
        try secret_file.writeAll(&kp.secret_key);
    } else if (std.mem.eql(u8, cmd, "-s")) {
        var kp: Ed25519.KeyPair = undefined;

        // read public key
        const public_file = try dir.openFile(
            nullTermPtrToSlice(u8, std.os.argv[2]),
            .{ .read = true },
        );
        defer public_file.close();
        _ = try public_file.read(&kp.public_key);

        // read secret key
        const secret_file = try dir.openFile(
            nullTermPtrToSlice(u8, std.os.argv[3]),
            .{ .read = true },
        );
        defer secret_file.close();
        _ = try secret_file.read(&kp.secret_key);

        // read message
        const input = try std.io.getStdIn().readToEndAlloc(alloc, std.math.maxInt(usize));
        defer alloc.free(input);

        // output signature
        _ = try std.io.getStdOut().writeAll(
            &try Ed25519.sign(input, kp, blk: {
                var buf: [Ed25519.noise_length]u8 = undefined;
                try std.os.getrandom(&buf);
                break :blk buf;
            })
        );
    } else if (std.mem.eql(u8, cmd, "-v")) {
        // read public key
        var public_key: [Ed25519.public_length]u8 = undefined;
        const public_file = try dir.openFile(
            nullTermPtrToSlice(u8, std.os.argv[2]),
            .{ .read = true },
        );
        defer public_file.close();
        _ = try public_file.read(&public_key);

        // read signature
        var sig: [Ed25519.signature_length]u8 = undefined;
        _ = try std.io.getStdIn().readAll(&sig);

        // read message
        const msg = try std.io.getStdIn().readToEndAlloc(alloc, std.math.maxInt(usize));
        defer alloc.free(msg);

        if (Ed25519.verify(sig, msg, public_key)) {
            _ = try std.io.getStdErr().write("Good signature\n");
        } else |_| {
            _ = try std.io.getStdErr().write("Bad signature\n");
            return 1;
        }
    }

    return 0;
}
