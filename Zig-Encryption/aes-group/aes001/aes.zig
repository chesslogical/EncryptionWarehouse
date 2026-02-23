const std = @import("std");

pub fn main() !void {
    const fs        = std.fs;
    const crypto    = std.crypto;
    const math      = std.math;
    const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
    const allocator = std.heap.page_allocator;

    // 1) Read plaintext from a.txt
    const in_file = try fs.cwd().openFile("a.txt", .{});
    defer in_file.close();

    const plaintext = try in_file.readToEndAlloc(allocator, math.maxInt(usize));
    defer allocator.free(plaintext);

    // 2) Generate AES-256 key and nonce
    var key:   [Aes256Gcm.key_length]u8   = undefined;
    var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
    crypto.random.bytes(&key);
    crypto.random.bytes(&nonce);

    // 3) Encrypt
    const ciphertext = try allocator.alloc(u8, plaintext.len);
    defer allocator.free(ciphertext);

    var tag: [Aes256Gcm.tag_length]u8 = undefined;
    const ad: []const u8 = &[_]u8{}; // Empty associated data
    Aes256Gcm.encrypt(ciphertext, &tag, plaintext, ad, nonce, key);

    // 4) Write b.enc = nonce || tag || ciphertext
    const enc_out = try fs.cwd().createFile("b.enc", .{});
    defer enc_out.close();

    try enc_out.writeAll(&nonce);
    try enc_out.writeAll(&tag);
    try enc_out.writeAll(ciphertext);

    // 5) Read encrypted data from b.enc
    const enc_in = try fs.cwd().openFile("b.enc", .{});
    defer enc_in.close();

    const bdata = try enc_in.readToEndAlloc(allocator, math.maxInt(usize));
    defer allocator.free(bdata);

    const header_size = Aes256Gcm.nonce_length + Aes256Gcm.tag_length;
    if (bdata.len < header_size)
        return error.InvalidEncryptedData;

    var nonce2: [Aes256Gcm.nonce_length]u8 = undefined;
    std.mem.copyForwards(u8, &nonce2, bdata[0..Aes256Gcm.nonce_length]);

    var tag2: [Aes256Gcm.tag_length]u8 = undefined;
    std.mem.copyForwards(
        u8,
        &tag2,
        bdata[Aes256Gcm.nonce_length .. header_size],
    );

    const ct2 = bdata[header_size..];
    const decrypted = try allocator.alloc(u8, ct2.len);
    defer allocator.free(decrypted);

    try Aes256Gcm.decrypt(decrypted, ct2, tag2, ad, nonce2, key);

    // 6) Write decrypted data to c.txt
    const out_file = try fs.cwd().createFile("c.txt", .{});
    defer out_file.close();

    try out_file.writeAll(decrypted);

    std.debug.print("Encryption → b.enc, decryption → c.txt done\n", .{});
}
