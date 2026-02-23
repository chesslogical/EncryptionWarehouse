const std = @import("std");
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const allocator = std.heap.page_allocator;

const magic = "ZIGC";
const version: u8 = 1;
const chunk_size = 1024 * 1024;

const Header = struct {
    magic: [4]u8,
    version: u8,
    chunk_size: u32,
    reserved: [7]u8,
};

pub fn main() !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        std.debug.print("Usage: {s} <file>\n", .{args[0]});
        return;
    }

    const file_path = args[1];
    const cwd = std.fs.cwd();

    const input_file = try cwd.openFile(file_path, .{});
    defer input_file.close();

    const key_file = try cwd.openFile("key.key", .{});
    defer key_file.close();

    var key: [Aes256Gcm.key_length]u8 = undefined;
    if (try key_file.readAll(&key) != key.len)
        return error.InvalidKeyFile;

    var header_buf: [4]u8 = undefined;
    try input_file.seekTo(0);
    const read_len = try input_file.read(&header_buf);
    const is_encrypted = read_len == 4 and std.mem.eql(u8, &header_buf, magic);

    try input_file.seekTo(0);

    const temp_name = try std.fmt.allocPrint(allocator, "{s}.securefile.tmp", .{file_path});
    defer allocator.free(temp_name);

    const temp_file = try cwd.createFile(temp_name, .{ .truncate = true });
    defer temp_file.close();

    if (is_encrypted) {
        try decryptFile(input_file, temp_file, &key);
        std.debug.print("✅ Decryption complete → {s}\n", .{file_path});
    } else {
        try encryptFile(input_file, temp_file, &key);
        std.debug.print("✅ Encryption complete → {s}\n", .{file_path});
    }

    try cwd.rename(temp_name, file_path);
}

fn encryptFile(in_file: std.fs.File, out_file: std.fs.File, key: *const [Aes256Gcm.key_length]u8) !void {
    try out_file.writeAll(magic);
    try out_file.writeAll(&[_]u8{version});
    try out_file.writeAll(std.mem.asBytes(&@as(u32, chunk_size)));
    try out_file.writeAll(&[_]u8{0} ** 7);

    var buffer = try allocator.alloc(u8, chunk_size);
    defer allocator.free(buffer);

    while (true) {
        const read_len = try in_file.read(buffer);
        if (read_len == 0) break;

        var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        var tag: [Aes256Gcm.tag_length]u8 = undefined;
        const ct = try allocator.alloc(u8, read_len);
        defer allocator.free(ct);

        Aes256Gcm.encrypt(ct, &tag, buffer[0..read_len], &.{}, nonce, key.*);

        const len_buf = std.mem.asBytes(&@as(u32, @intCast(read_len)));

        try out_file.writeAll(&nonce);
        try out_file.writeAll(&tag);
        try out_file.writeAll(len_buf);
        try out_file.writeAll(ct);
    }
}

fn decryptFile(in_file: std.fs.File, out_file: std.fs.File, key: *const [Aes256Gcm.key_length]u8) !void {
    var hdr: Header = .{
        .magic = undefined,
        .version = undefined,
        .chunk_size = undefined,
        .reserved = undefined,
    };

    try in_file.seekTo(0);
    _ = try in_file.read(&hdr.magic);

    var version_buf: [1]u8 = undefined;
    if (try in_file.read(&version_buf) != 1) return error.InvalidHeader;
    hdr.version = version_buf[0];

    _ = try in_file.read(std.mem.asBytes(&hdr.chunk_size));
    _ = try in_file.read(&hdr.reserved);

    if (!std.mem.eql(u8, hdr.magic[0..], magic))
        return error.InvalidHeader;

    const chunk_sz = hdr.chunk_size;
    var buffer = try allocator.alloc(u8, chunk_sz);
    defer allocator.free(buffer);

    while (true) {
        var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
        var tag: [Aes256Gcm.tag_length]u8 = undefined;
        var len_buf: [4]u8 = undefined;

        const nonce_read = try in_file.readAll(&nonce);
        if (nonce_read == 0) break;
        if (nonce_read != nonce.len) return error.InvalidEncryptedChunk;

        if (try in_file.readAll(&tag) != tag.len)
            return error.InvalidEncryptedChunk;

        if (try in_file.readAll(&len_buf) != len_buf.len)
            return error.InvalidEncryptedChunk;

        const ct_len = std.mem.bytesToValue(u32, &len_buf);
        if (ct_len > chunk_sz) return error.ChunkTooLarge;

        const read_ct = try in_file.readAll(buffer[0..ct_len]);
        if (read_ct != ct_len) return error.IncompleteChunk;

        const pt = try allocator.alloc(u8, ct_len);
        defer allocator.free(pt);

        try Aes256Gcm.decrypt(pt, buffer[0..ct_len], tag, &.{}, nonce, key.*);
        try out_file.writeAll(pt);
    }
}
