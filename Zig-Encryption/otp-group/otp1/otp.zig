
const std = @import("std");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var gpa = std.heap.page_allocator;
    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len != 4) {
        try stdout.print("Usage: {s} <input_file> <output_file> <key_file>\n", .{args[0]});
        return error.InvalidArgs;
    }

    const input_path = args[1];
    const output_path = args[2];
    const key_path = args[3];

    const input_data = readFileAlloc(gpa, input_path) catch |err| {
        try stdout.print("Failed to read input file '{s}': {any}\n", .{input_path, err});
        return err;
    };
    defer gpa.free(input_data);

    const key_data = readFileAlloc(gpa, key_path) catch |err| {
        try stdout.print("Failed to read key file '{s}': {any}\n", .{key_path, err});
        return err;
    };
    defer gpa.free(key_data);

    if (key_data.len < input_data.len) {
        try stdout.print("Error: Key file is smaller than input file. Exiting.\n", .{});
        return;
    }

    var encrypted = try gpa.alloc(u8, input_data.len);
    defer gpa.free(encrypted);

    for (input_data, 0..) |byte, i| {
        encrypted[i] = byte ^ key_data[i];
    }

    writeFile(output_path, encrypted) catch |err| {
        try stdout.print("Failed to write output file '{s}': {any}\n", .{output_path, err});
        return err;
    };

    try stdout.print("Output saved to '{s}'\n", .{output_path});
}

// --- Utility Functions ---

fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const file_size = try file.getEndPos();
    const buffer = try allocator.alloc(u8, file_size);
    _ = try file.readAll(buffer);
    return buffer;
}

fn writeFile(path: []const u8, data: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    _ = try file.writeAll(data);
}
