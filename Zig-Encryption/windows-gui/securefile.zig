//!zig win32_subsystem: windows
const std = @import("std");
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const allocator = std.heap.page_allocator;

extern "user32" fn MessageBoxW(hwnd: ?*anyopaque, lpText: [*:0]u16, lpCaption: [*:0]u16, uType: u32) c_int;
extern "comdlg32" fn GetOpenFileNameW(param: *OPENFILENAMEW) bool;

const MB_OK = 0x00000000;
const MB_ICONINFORMATION = 0x00000040;
const MAX_PATH = 260;

const OPENFILENAMEW = extern struct {
    lStructSize: u32,
    hwndOwner: ?*anyopaque,
    hInstance: ?*anyopaque,
    lpstrFilter: [*:0]u16,
    lpstrCustomFilter: ?[*:0]u16,
    nMaxCustFilter: u32,
    nFilterIndex: u32,
    lpstrFile: [*]u16,
    nMaxFile: u32,
    lpstrFileTitle: ?[*:0]u16,
    nMaxFileTitle: u32,
    lpstrInitialDir: ?[*:0]u16,
    lpstrTitle: ?[*:0]u16,
    flags: u32,
    nFileOffset: u16,
    nFileExtension: u16,
    lpstrDefExt: ?[*:0]u16,
    lCustData: usize,
    lpfnHook: ?*const anyopaque,
    lpTemplateName: ?[*:0]u16,
    pvReserved: ?*anyopaque,
    dwReserved: u32,
    flagsEx: u32,
};

const magic = "ZIGC";
const version: u8 = 1;
const chunk_size = 1024 * 1024;

pub fn main() !void {
    var file_buffer: [MAX_PATH]u16 = [_]u16{0} ** MAX_PATH;

    const filter = &[_:0]u16{
        'A','l','l',' ','F','i','l','e','s', 0,
        '*','.','*', 0,
        0
    };
    const title = &[_:0]u16{
        'S','e','l','e','c','t',' ','a',' ','f','i','l','e',' ','t','o',' ',
        'p','r','o','c','e','s','s', 0
    };

    var ofn = OPENFILENAMEW{
        .lStructSize = @sizeOf(OPENFILENAMEW),
        .hwndOwner = null,
        .hInstance = null,
        .lpstrFilter = @ptrCast(@constCast(filter)),
        .lpstrCustomFilter = null,
        .nMaxCustFilter = 0,
        .nFilterIndex = 1,
        .lpstrFile = &file_buffer,
        .nMaxFile = MAX_PATH,
        .lpstrFileTitle = null,
        .nMaxFileTitle = 0,
        .lpstrInitialDir = null,
        .lpstrTitle = @ptrCast(@constCast(title)),
        .flags = 0,
        .nFileOffset = 0,
        .nFileExtension = 0,
        .lpstrDefExt = null,
        .lCustData = 0,
        .lpfnHook = null,
        .lpTemplateName = null,
        .pvReserved = null,
        .dwReserved = 0,
        .flagsEx = 0,
    };

    if (!GetOpenFileNameW(&ofn)) return;

    const utf16_path_ptr: [*:0]const u16 = @ptrCast(ofn.lpstrFile);
    const file_path = try std.unicode.utf16LeToUtf8Alloc(allocator, std.mem.span(utf16_path_ptr));
    defer allocator.free(file_path);

    const result = try processFile(file_path);
    const title_box = &[_:0]u16{ 's','e','c','u','r','e','f','i','l','e', 0 };

    const msg = switch (result) {
        .Encrypted => &[_:0]u16{
            'E','n','c','r','y','p','t','i','o','n',' ',
            'c','o','m','p','l','e','t','e','!', 0
        },
        .Decrypted => &[_:0]u16{
            'D','e','c','r','y','p','t','i','o','n',' ',
            'c','o','m','p','l','e','t','e','!', 0
        },
    };

    _ = MessageBoxW(
        null,
        @ptrCast(@constCast(msg)),
        @ptrCast(@constCast(title_box)),
        MB_OK | MB_ICONINFORMATION
    );
}

const ResultType = enum { Encrypted, Decrypted };

fn processFile(file_path: []const u8) !ResultType {
    const cwd = std.fs.cwd();

    const input_file = try cwd.openFile(file_path, .{});
    defer input_file.close();

    const key_file = try cwd.openFile("key.key", .{});
    defer key_file.close();

    var key: [32]u8 = undefined;
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
        try cwd.rename(temp_name, file_path);
        return .Decrypted;
    } else {
        try encryptFile(input_file, temp_file, &key);
        try cwd.rename(temp_name, file_path);
        return .Encrypted;
    }
}

fn encryptFile(in_file: std.fs.File, out_file: std.fs.File, key: *const [32]u8) !void {
    try out_file.writeAll(magic);
    try out_file.writeAll(&[_]u8{version});
    try out_file.writeAll(std.mem.asBytes(&@as(u32, chunk_size)));
    try out_file.writeAll(&[_]u8{0} ** 7);

    var buffer = try allocator.alloc(u8, chunk_size);
    defer allocator.free(buffer);

    while (true) {
        const read_len = try in_file.read(buffer);
        if (read_len == 0) break;

        var nonce: [12]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        var tag: [16]u8 = undefined;
        const ct = try allocator.alloc(u8, read_len);
        defer allocator.free(ct);

        Aes256Gcm.encrypt(ct, &tag, buffer[0..read_len], &.{}, nonce, key.*);

        try out_file.writeAll(&nonce);
        try out_file.writeAll(&tag);
        try out_file.writeAll(std.mem.asBytes(&@as(u32, @intCast(read_len))));
        try out_file.writeAll(ct);
    }
}

fn decryptFile(in_file: std.fs.File, out_file: std.fs.File, key: *const [32]u8) !void {
    var magic_buf: [4]u8 = undefined;
    _ = try in_file.read(&magic_buf);

    var ver_buf: [1]u8 = undefined;
    _ = try in_file.read(&ver_buf);

    var chunk_size_buf: u32 = undefined;
    _ = try in_file.read(std.mem.asBytes(&chunk_size_buf));

    var reserved_buf: [7]u8 = undefined;
    _ = try in_file.read(&reserved_buf);

    const chunk_sz = chunk_size_buf;
    var buffer = try allocator.alloc(u8, chunk_sz);
    defer allocator.free(buffer);

    while (true) {
        var nonce: [12]u8 = undefined;
        var tag: [16]u8 = undefined;
        var len_buf: [4]u8 = undefined;

        const nonce_read = try in_file.readAll(&nonce);
        if (nonce_read == 0) break;
        if (nonce_read != nonce.len) return error.InvalidEncryptedChunk;

        if (try in_file.readAll(&tag) != tag.len) return error.InvalidEncryptedChunk;
        if (try in_file.readAll(&len_buf) != len_buf.len) return error.InvalidEncryptedChunk;

        const ct_len = std.mem.bytesToValue(u32, &len_buf);
        const read_ct = try in_file.readAll(buffer[0..ct_len]);
        if (read_ct != ct_len) return error.IncompleteChunk;

        const pt = try allocator.alloc(u8, ct_len);
        defer allocator.free(pt);

        try Aes256Gcm.decrypt(pt, buffer[0..ct_len], tag, &.{}, nonce, key.*);
        try out_file.writeAll(pt);
    }
}
