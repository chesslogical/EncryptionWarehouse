const std = @import("std");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    const gpa = std.heap.page_allocator;
    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len != 4) {
        try stdout.print("Usage: {s} <input_file> <output_file> <key_file>\n", .{args[0]});
        return error.InvalidArgs;
    }

    const input_path = args[1];
    const output_path = args[2];
    const key_path = args[3];

    var input_file = try std.fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    var key_file = try std.fs.cwd().openFile(key_path, .{});
    defer key_file.close();

    var output_file = try std.fs.cwd().createFile(output_path, .{ .truncate = true });
    defer output_file.close();

    // Buffers for reading and writing
    var input_buffer: [4096]u8 = undefined;
    var key_buffer: [4096]u8 = undefined;
    var encrypted_buffer: [4096]u8 = undefined;

    while (true) {
        const input_read = try input_file.read(&input_buffer);
        if (input_read == 0) break; // EOF

        const key_read = try key_file.read(&key_buffer);
        if (key_read < input_read) {
            try stdout.print("Error: Key file is smaller than input file.\n", .{});
            return error.KeyTooShort;
        }

        for (input_buffer[0..input_read], 0..) |byte, i| {
            encrypted_buffer[i] = byte ^ key_buffer[i];
        }

        try output_file.writeAll(encrypted_buffer[0..input_read]);
    }

    try stdout.print("Output saved to '{s}'\n", .{output_path});
}
