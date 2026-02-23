
const std = @import("std");

pub fn main() !void {
    const fs = std.fs;
    const crypto = std.crypto;
    const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
    const pbkdf2 = crypto.pwhash.pbkdf2;
    const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
    const allocator = std.heap.page_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 5) {
        std.debug.print(
            "Usage: {s} <enc|dec> <input_file> <output_file> <password>\n",
            .{args[0]},
        );
        return error.InvalidArguments;
    }

    const mode = args[1];
    const input_path = args[2];
    const output_path = args[3];
    const password = args[4];

    const salt_len = 16;
    const nonce_len = Aes256Gcm.nonce_length;
    const tag_len = Aes256Gcm.tag_length;
    const key_len = Aes256Gcm.key_length;
    const iterations = 100_000;

    var key: [key_len]u8 = undefined;

    if (std.mem.eql(u8, mode, "enc")) {
        var salt: [salt_len]u8 = undefined;
        var nonce: [nonce_len]u8 = undefined;
        crypto.random.bytes(&salt);
        crypto.random.bytes(&nonce);

        try pbkdf2(&key, password, &salt, @as(u32, iterations), HmacSha256);

        const in_file = try fs.cwd().openFile(input_path, .{});
        defer in_file.close();
        const plaintext = try in_file.readToEndAlloc(allocator, std.math.maxInt(usize));
        defer allocator.free(plaintext);

        const ciphertext = try allocator.alloc(u8, plaintext.len);
        defer allocator.free(ciphertext);
        var tag: [tag_len]u8 = undefined;
        const ad: []const u8 = &[_]u8{};
        Aes256Gcm.encrypt(ciphertext, &tag, plaintext, ad, nonce, key);

        const out_file = try fs.cwd().createFile(output_path, .{});
        defer out_file.close();
        try out_file.writeAll(&salt);
        try out_file.writeAll(&nonce);
        try out_file.writeAll(&tag);
        try out_file.writeAll(ciphertext);

        std.debug.print("Encrypted '{s}' → '{s}' using password\n", .{input_path, output_path});

    } else if (std.mem.eql(u8, mode, "dec")) {
        const in_file = try fs.cwd().openFile(input_path, .{});
        defer in_file.close();
        const enc_data = try in_file.readToEndAlloc(allocator, std.math.maxInt(usize));
        defer allocator.free(enc_data);

        const header_len = salt_len + nonce_len + tag_len;
        if (enc_data.len < header_len)
            return error.InvalidEncryptedData;

        var salt: [salt_len]u8 = undefined;
        var nonce: [nonce_len]u8 = undefined;
        var tag: [tag_len]u8 = undefined;

        std.mem.copyForwards(u8, &salt, enc_data[0..salt_len]);
        std.mem.copyForwards(u8, &nonce, enc_data[salt_len .. salt_len + nonce_len]);
        std.mem.copyForwards(u8, &tag, enc_data[salt_len + nonce_len .. header_len]);

        const ciphertext = enc_data[header_len..];

        try pbkdf2(&key, password, &salt, @as(u32, iterations), HmacSha256);

        const decrypted = try allocator.alloc(u8, ciphertext.len);
        defer allocator.free(decrypted);
        const ad: []const u8 = &[_]u8{};
        try Aes256Gcm.decrypt(decrypted, ciphertext, tag, ad, nonce, key);

        const out_file = try fs.cwd().createFile(output_path, .{});
        defer out_file.close();
        try out_file.writeAll(decrypted);

        std.debug.print("Decrypted '{s}' → '{s}' using password\n", .{input_path, output_path});

    } else {
        std.debug.print("Invalid mode '{s}'. Use 'enc' or 'dec'\n", .{mode});
        return error.InvalidArguments;
    }
}
