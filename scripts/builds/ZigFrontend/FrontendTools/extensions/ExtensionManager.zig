
const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;

/// ExtensionManager is responsible for managing browser extensions in Aluminum.
/// It handles loading, enabling, disabling, and updating extensions.
pub const ExtensionManager = struct {
    allocator: *Allocator,
    extensions: StringHashMap(Extension),
    enabled_extensions: ArrayList([]const u8),

    /// Initializes a new ExtensionManager with the given allocator.
    pub fn init(allocator: *Allocator) !ExtensionManager {
        return ExtensionManager{
            .allocator = allocator,
            .extensions = StringHashMap(Extension).init(allocator),
            .enabled_extensions = ArrayList([]const u8).init(allocator),
        };
    }

    /// Deinitializes the ExtensionManager and frees all associated resources.
    pub fn deinit(self: *ExtensionManager) void {
        var it = self.extensions.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
            self.allocator.free(entry.key_ptr.*);
        }
        self.extensions.deinit();
        self.enabled_extensions.deinit();
    }

    /// Loads an extension from the given path.
    pub fn loadExtension(self: *ExtensionManager, path: []const u8) !void {
        const extension = try Extension.loadFromPath(self.allocator, path);
        const id = try self.allocator.dupe(u8, extension.id);
        errdefer self.allocator.free(id);

        try self.extensions.put(id, extension);
    }

    /// Enables an extension with the given ID.
    pub fn enableExtension(self: *ExtensionManager, id: []const u8) !void {
        const extension = self.extensions.get(id) orelse return error.ExtensionNotFound;
        if (!extension.enabled) {
            extension.enabled = true;
            try self.enabled_extensions.append(id);
        }
    }

    /// Disables an extension with the given ID.
    pub fn disableExtension(self: *ExtensionManager, id: []const u8) !void {
        const extension = self.extensions.get(id) orelse return error.ExtensionNotFound;
        if (extension.enabled) {
            extension.enabled = false;
            for (self.enabled_extensions.items) |enabled_id, index| {
                if (std.mem.eql(u8, enabled_id, id)) {
                    _ = self.enabled_extensions.orderedRemove(index);
                    break;
                }
            }
        }
    }

    /// Updates an extension with the given ID.
    pub fn updateExtension(self: *ExtensionManager, id: []const u8) !void {
        const extension = self.extensions.get(id) orelse return error.ExtensionNotFound;
        try extension.update();
    }

    /// Returns a slice of all enabled extension IDs.
    pub fn getEnabledExtensions(self: *ExtensionManager) []const []const u8 {
        return self.enabled_extensions.items;
    }

    /// Returns the total number of installed extensions.
    pub fn getTotalExtensionsCount(self: *ExtensionManager) usize {
        return self.extensions.count();
    }

    /// Checks for updates for all installed extensions.
    pub fn checkForUpdates(self: *ExtensionManager) !void {
        var it = self.extensions.iterator();
        while (it.next()) |entry| {
            try entry.value_ptr.checkForUpdate();
        }
    }

    /// Removes an extension with the given ID.
    pub fn removeExtension(self: *ExtensionManager, id: []const u8) !void {
        const extension = self.extensions.get(id) orelse return error.ExtensionNotFound;
        try self.disableExtension(id);
        extension.deinit();
        _ = self.extensions.remove(id);
        self.allocator.free(id);
    }

    /// Exports the list of installed extensions to a JSON file.
    pub fn exportExtensionList(self: *ExtensionManager, path: []const u8) !void {
        var file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        var writer = file.writer();
        try writer.writeAll("{\n  \"extensions\": [\n");

        var it = self.extensions.iterator();
        var first = true;
        while (it.next()) |entry| {
            if (!first) {
                try writer.writeAll(",\n");
            }
            try writer.print("    {{\"id\": \"{s}\", \"enabled\": {}}}", .{ entry.key_ptr.*, entry.value_ptr.enabled });
            first = false;
        }

        try writer.writeAll("\n  ]\n}\n");
    }

    /// Imports the list of extensions from a JSON file and loads them.
    pub fn importExtensionList(self: *ExtensionManager, path: []const u8) !void {
        const file_contents = try std.fs.cwd().readFileAlloc(self.allocator, path, 1024 * 1024);
        defer self.allocator.free(file_contents);

        var parser = std.json.Parser.init(self.allocator, false);
        defer parser.deinit();

        var tree = try parser.parse(file_contents);
        defer tree.deinit();

        const root = tree.root;
        const extensions = root.Object.get("extensions").?.Array;

        for (extensions.items) |extension_json| {
            const id = extension_json.Object.get("id").?.String;
            const enabled = extension_json.Object.get("enabled").?.Bool;

            try self.loadExtension(id);
            if (enabled) {
                try self.enableExtension(id);
            }
        }
    }

    /// Performs a security audit on all installed extensions.
    pub fn performSecurityAudit(self: *ExtensionManager) !void {
        var it = self.extensions.iterator();
        while (it.next()) |entry| {
            try entry.value_ptr.performSecurityAudit();
        }
    }

    /// Generates a report of all installed extensions, including their status and resource usage.
    pub fn generateExtensionReport(self: *ExtensionManager) ![]u8 {
        var report = ArrayList(u8).init(self.allocator);
        errdefer report.deinit();

        try report.appendSlice("Extension Report\n=================\n\n");

        var it = self.extensions.iterator();
        while (it.next()) |entry| {
            const extension = entry.value_ptr;
            try report.writer().print("ID: {s}\nEnabled: {}\nVersion: {s}\nAuthor: {s}\nDescription: {s}\nResource Usage: {d} MB\n\n", .{
                extension.id,
                extension.enabled,
                extension.version,
                extension.author,
                extension.description,
                extension.getResourceUsage(),
            });
        }

        return report.toOwnedSlice();
    }
};

/// Represents a single browser extension.
const Extension = struct {
    id: []const u8,
    name: []const u8,
    version: []const u8,
    author: []const u8,
    description: []const u8,
    enabled: bool,
    path: []const u8,
    allocator: *Allocator,

    /// Loads an extension from the given path.
    pub fn loadFromPath(allocator: *Allocator, path: []const u8) !Extension {
        // TODO: Implement actual loading logic
        // This is a placeholder implementation
        return Extension{
            .id = try allocator.dupe(u8, "example-extension"),
            .name = try allocator.dupe(u8, "Example Extension"),
            .version = try allocator.dupe(u8, "1.0.0"),
            .author = try allocator.dupe(u8, "John Doe"),
            .description = try allocator.dupe(u8, "An example extension"),
            .enabled = false,
            .path = try allocator.dupe(u8, path),
            .allocator = allocator,
        };
    }

    /// Deinitializes the Extension and frees all associated resources.
    pub fn deinit(self: *Extension) void {
        self.allocator.free(self.id);
        self.allocator.free(self.name);
        self.allocator.free(self.version);
        self.allocator.free(self.author);
        self.allocator.free(self.description);
        self.allocator.free(self.path);
    }

    /// Updates the extension to the latest version.
    pub fn update(self: *Extension) !void {
        // TODO: Implement actual update logic
        std.debug.print("Updating extension: {s}\n", .{self.id});
    }

    /// Checks if there's an update available for the extension.
    pub fn checkForUpdate(self: *Extension) !void {
        // TODO: Implement actual update checking logic
        std.debug.print("Checking for updates: {s}\n", .{self.id});
    }

    /// Performs a security audit on the extension.
    pub fn performSecurityAudit(self: *Extension) !void {
        // TODO: Implement actual security audit logic
        std.debug.print("Performing security audit on: {s}\n", .{self.id});
    }

    /// Returns the resource usage of the extension in megabytes.
    pub fn getResourceUsage(self: *Extension) f64 {
        // TODO: Implement actual resource usage calculation
        return 10.5; // Placeholder value
    }
};

/// Main function to demonstrate the usage of ExtensionManager
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = &gpa.allocator;

    var extension_manager = try ExtensionManager.init(allocator);
    defer extension_manager.deinit();

    // Load some example extensions
    try extension_manager.loadExtension("path/to/extension1");
    try extension_manager.loadExtension("path/to/extension2");
    try extension_manager.loadExtension("path/to/extension3");

    // Enable some extensions
    try extension_manager.enableExtension("example-extension");
    try extension_manager.enableExtension("another-extension");

    // Print enabled extensions
    const enabled_extensions = extension_manager.getEnabledExtensions();
    std.debug.print("Enabled extensions: {any}\n", .{enabled_extensions});

    // Check for updates
    try extension_manager.checkForUpdates();

    // Generate and print extension report
    const report = try extension_manager.generateExtensionReport();
    defer allocator.free(report);
    std.debug.print("{s}\n", .{report});

    // Export extension list
    try extension_manager.exportExtensionList("extensions.json");

    // Perform security audit
    try extension_manager.performSecurityAudit();

    std.debug.print("Extension manager demo completed successfully.\n", .{});
}
