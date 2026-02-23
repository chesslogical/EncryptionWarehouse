
const std = @import("std");
const ChaCha = std.crypto.stream.chacha.ChaCha20IETF;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 3) {
        try stdout.writeAll("Usage: keygen <size_bytes> <password>\n");
        return;
    }

    const size = try std.fmt.parseInt(usize, args[1], 10);
    if (size < 1 or size > 20 * 1024 * 1024 * 1024) {
        try stdout.writeAll("Error: size must be between 1 byte and 20GB\n");
        return;
    }

    const password = args[2];

    // Derive key and nonce deterministically from password
    var hasher = Sha256.init(.{});
    hasher.update(password);
    var hash1: [Sha256.digest_length]u8 = undefined;
    hasher.final(&hash1);

    hasher = Sha256.init(.{});
    hasher.update(password);
    hasher.update("keygen-nonce");
    var hash2: [Sha256.digest_length]u8 = undefined;
    hasher.final(&hash2);

    const key: [32]u8 = hash1;
    var nonce: [12]u8 = undefined;
    @memcpy(nonce[0..], hash2[0..12]);

    // Open (or create/truncate) key.key for writing
    const cwd = std.fs.cwd();
    const outFile = try cwd.createFile("key.key", .{ .truncate = true });
    defer outFile.close();
    const out = outFile.writer();

    const blockSize: usize = 64 * 1024;
    var buffer: [blockSize]u8 = undefined;
    var remaining: usize = size;
    var counter: u32 = 0;

    while (remaining > 0) {
        const chunk = if (remaining < blockSize) remaining else blockSize;
        ChaCha.stream(buffer[0..chunk], counter, key, nonce);
        const blocks: u32 = @intCast((chunk + 63) / 64);
        counter += blocks;
        try out.writeAll(buffer[0..chunk]);
        remaining -= chunk;
    }
}

