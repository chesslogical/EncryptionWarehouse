
const std = @import("std");

pub fn main() !void {
    const fs = std.fs;
    const crypto = std.crypto;
    const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
    const allocator = std.heap.page_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 5) {
        std.debug.print(
            "Usage: {s} <enc|dec> <input_file> <output_file> <key_file>\n",
            .{args[0]},
        );
        return error.InvalidArguments;
    }

    const mode = args[1];
    const input_path = args[2];
    const output_path = args[3];
    const key_path = args[4];

    var key: [Aes256Gcm.key_length]u8 = undefined;

    // Load the key from file
    const key_file = try fs.cwd().openFile(key_path, .{});
    defer key_file.close();
    const read_bytes = try key_file.readAll(&key);
    if (read_bytes != key.len) return error.InvalidKeyFile;

    if (std.mem.eql(u8, mode, "enc")) {
        // Generate nonce
        var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
        crypto.random.bytes(&nonce);

        // Read plaintext
        const in_file = try fs.cwd().openFile(input_path, .{});
        defer in_file.close();
        const plaintext = try in_file.readToEndAlloc(allocator, std.math.maxInt(usize));
        defer allocator.free(plaintext);

        // Encrypt
        const ciphertext = try allocator.alloc(u8, plaintext.len);
        defer allocator.free(ciphertext);
        var tag: [Aes256Gcm.tag_length]u8 = undefined;
        const ad: []const u8 = &[_]u8{};
        Aes256Gcm.encrypt(ciphertext, &tag, plaintext, ad, nonce, key);

        // Write output (nonce || tag || ciphertext)
        const out_file = try fs.cwd().createFile(output_path, .{});
        defer out_file.close();
        try out_file.writeAll(&nonce);
        try out_file.writeAll(&tag);
        try out_file.writeAll(ciphertext);

        std.debug.print("Encrypted '{s}' → '{s}' using key from '{s}'\n", .{input_path, output_path, key_path});

    } else if (std.mem.eql(u8, mode, "dec")) {
        // Read encrypted file
        const in_file = try fs.cwd().openFile(input_path, .{});
        defer in_file.close();
        const enc_data = try in_file.readToEndAlloc(allocator, std.math.maxInt(usize));
        defer allocator.free(enc_data);

        const header_len = Aes256Gcm.nonce_length + Aes256Gcm.tag_length;
        if (enc_data.len < header_len) return error.InvalidEncryptedData;

        var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
        std.mem.copyForwards(u8, &nonce, enc_data[0..Aes256Gcm.nonce_length]);

        var tag: [Aes256Gcm.tag_length]u8 = undefined;
        std.mem.copyForwards(
            u8,
            &tag,
            enc_data[Aes256Gcm.nonce_length..header_len],
        );

        const ciphertext = enc_data[header_len..];
        const decrypted = try allocator.alloc(u8, ciphertext.len);
        defer allocator.free(decrypted);

        const ad: []const u8 = &[_]u8{};
        try Aes256Gcm.decrypt(decrypted, ciphertext, tag, ad, nonce, key);

        // Write decrypted output
        const out_file = try fs.cwd().createFile(output_path, .{});
        defer out_file.close();
        try out_file.writeAll(decrypted);

        std.debug.print("Decrypted '{s}' → '{s}' using key from '{s}'\n", .{input_path, output_path, key_path});

    } else {
        std.debug.print("Invalid mode '{s}'. Use 'enc' or 'dec'\n", .{mode});
        return error.InvalidArguments;
    }
}
