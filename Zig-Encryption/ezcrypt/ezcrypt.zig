const std = @import("std");

// Hardcoded variables - change these and recompile to alter encryption behavior
const encryption_key: [32]u8 = [_]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
const magic_header: []const u8 = "ZIGENC01"; // 8-byte magic for detection

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        std.debug.print("Usage: {s} <filename>\n", .{args[0]});
        std.process.exit(1);
    }

    const filename = args[1];
    var file = try std.fs.cwd().openFile(filename, .{ .mode = .read_write });
    defer file.close();

    const stat = try file.stat();
    if (stat.size == 0) {
        std.debug.print("Error: File is empty.\n", .{});
        std.process.exit(1);
    }

    const buf = try allocator.alloc(u8, stat.size);
    defer allocator.free(buf);

    const bytes_read = try file.readAll(buf);
    if (bytes_read != stat.size) {
        std.debug.print("Error: Failed to read entire file.\n", .{});
        std.process.exit(1);
    }

    const magic_len = magic_header.len;
    const nonce_len: usize = 12;
    const tag_len: usize = 16;
    const header_len = magic_len + nonce_len + tag_len;

    if (stat.size >= header_len and std.mem.eql(u8, buf[0..magic_len], magic_header)) {
        // File is encrypted: decrypt it
        const nonce_slice = buf[magic_len .. magic_len + nonce_len];
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, nonce_slice);

        const tag_slice = buf[magic_len + nonce_len .. header_len];
        var tag: [16]u8 = undefined;
        @memcpy(&tag, tag_slice);

        const ciphertext = buf[header_len..];

        const plaintext = try allocator.alloc(u8, ciphertext.len);
        defer allocator.free(plaintext);

        std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(plaintext, ciphertext, tag, &[_]u8{}, nonce, encryption_key) catch |err| {
            std.debug.print("Error: Decryption failed ({any}). File may be corrupted or key mismatch.\n", .{err});
            std.process.exit(1);
        };

        // Write decrypted content back in place
        try file.seekTo(0);
        try file.writeAll(plaintext);
        try file.setEndPos(plaintext.len);

        std.debug.print("File decrypted successfully.\n", .{});
    } else {
        // File is plaintext: encrypt it
        var nonce: [12]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        var tag: [16]u8 = undefined;

        const plaintext = buf[0..stat.size];
        const ciphertext = try allocator.alloc(u8, plaintext.len);
        defer allocator.free(ciphertext);

        std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, &tag, plaintext, &[_]u8{}, nonce, encryption_key);

        // Build new encrypted content: magic + nonce + tag + ciphertext
        const new_size = header_len + ciphertext.len;
        var new_buf = try allocator.alloc(u8, new_size);
        defer allocator.free(new_buf);

        @memcpy(new_buf[0..magic_len], magic_header);
        @memcpy(new_buf[magic_len .. magic_len + nonce_len], &nonce);
        @memcpy(new_buf[magic_len + nonce_len .. header_len], &tag);
        @memcpy(new_buf[header_len..], ciphertext);

        // Write encrypted content back in place
        try file.seekTo(0);
        try file.writeAll(new_buf);
        try file.setEndPos(new_size);

        std.debug.print("File encrypted successfully.\n", .{});
    }
}