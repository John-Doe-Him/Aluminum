const std = @import("std");
const net = std.net;
const fs = std.fs;
const http = @import("http");
const ssl = @import("ssl");
const dns = @import("dns");
const log = std.log;
const mem = std.mem;
const json = std.json;

// Configuration constants
const PORT = 443;
const METAL_SUBDOMAIN = ".metal";
const CERT_PATH = "/path/to/ssl/cert.pem";
const KEY_PATH = "/path/to/ssl/key.pem";
const MAX_CONNECTIONS = 1000;
const TIMEOUT_MS = 30000;

// Custom error set for website hosting
const HostError = error{
    ServerInitFailed,
    SSLConfigFailed,
    DNSLookupFailed,
    FileReadError,
    JSONParseError,
};

// Website configuration structure
const WebsiteConfig = struct {
    domain: []const u8,
    root_dir: []const u8,
    index_file: []const u8,
    error_page: []const u8,
};

// Global server context
const ServerContext = struct {
    allocator: *std.mem.Allocator,
    websites: std.StringHashMap(WebsiteConfig),
    ssl_ctx: ssl.SSL_CTX,
};

// Function to initialize the server context
fn initServerContext(allocator: *std.mem.Allocator) !ServerContext {
    var websites = std.StringHashMap(WebsiteConfig).init(allocator);

    // Load website configurations from a JSON file
    const config_file = try fs.cwd().openFile("website_config.json", .{});
    defer config_file.close();

    const config_content = try config_file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(config_content);

    var json_parser = json.Parser.init(allocator, false);
    defer json_parser.deinit();

    var json_tree = try json_parser.parse(config_content);
    defer json_tree.deinit();

    const root = json_tree.root.Object;

    var it = root.iterator();
    while (it.next()) |entry| {
        const website = WebsiteConfig{
            .domain = try allocator.dupe(u8, entry.key_ptr.*),
            .root_dir = try allocator.dupe(u8, entry.value_ptr.Object.get("root_dir").?.String),
            .index_file = try allocator.dupe(u8, entry.value_ptr.Object.get("index_file").?.String),
            .error_page = try allocator.dupe(u8, entry.value_ptr.Object.get("error_page").?.String),
        };
        try websites.put(website.domain, website);
    }

    // Initialize SSL context
    const ssl_ctx = try ssl.SSL_CTX_new(ssl.TLS_server_method());
    errdefer ssl.SSL_CTX_free(ssl_ctx);

    try ssl.SSL_CTX_use_certificate_file(ssl_ctx, CERT_PATH, ssl.SSL_FILETYPE_PEM);
    try ssl.SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_PATH, ssl.SSL_FILETYPE_PEM);

    return ServerContext{
        .allocator = allocator,
        .websites = websites,
        .ssl_ctx = ssl_ctx,
    };
}

// Function to handle incoming connections
fn handleConnection(context: *ServerContext, socket: ssl.SSL) !void {
    if (ssl.SSL_accept(socket) <= 0) {
        log.err("SSL handshake failed", .{});
        return;
    }

    var buf: [4096]u8 = undefined;
    const request_bytes_read = try ssl.SSL_read(socket, &buf, buf.len);
    const request = buf[0..request_bytes_read];

    // Parse the HTTP request
    var request_iterator = mem.split(u8, request, "\r\n");
    const request_line = request_iterator.next() orelse return error.InvalidRequest;

    var request_parts = mem.split(u8, request_line, " ");
    _ = request_parts.next(); // Skip the HTTP method
    const requested_path = request_parts.next() orelse return error.InvalidRequest;

    // Extract the domain from the Host header
    var host: ?[]const u8 = null;
    while (request_iterator.next()) |header| {
        if (mem.startsWith(u8, header, "Host: ")) {
            host = header["Host: ".len..];
            break;
        }
    }

    if (host == null) return error.MissingHostHeader;

    // Check if the domain ends with .metal
    if (!mem.endsWith(u8, host.?, METAL_SUBDOMAIN)) {
        try sendErrorResponse(socket, "404 Not Found", "Invalid domain");
        return;
    }

    const domain = host.?[0 .. host.?.len - METAL_SUBDOMAIN.len];

    // Look up the website configuration
    const website_config = context.websites.get(domain) orelse {
        try sendErrorResponse(socket, "404 Not Found", "Website not found");
        return;
    };

    // Construct the full file path
    var file_path_buf: [fs.MAX_PATH_BYTES]u8 = undefined;
    const file_path = try std.fmt.bufPrint(&file_path_buf, "{s}{s}", .{
        website_config.root_dir,
        if (mem.eql(u8, requested_path, "/")) website_config.index_file else requested_path,
    });

    // Attempt to open and read the file
    const file = fs.openFileAbsolute(file_path, .{ .mode = .read_only }) catch |err| {
        switch (err) {
            error.FileNotFound => try sendErrorResponse(socket, "404 Not Found", "File not found"),
            error.AccessDenied => try sendErrorResponse(socket, "403 Forbidden", "Access denied"),
            else => try sendErrorResponse(socket, "500 Internal Server Error", "Unable to read file"),
        }
        return;
    };
    defer file.close();

    const file_size = try file.getEndPos();

    // Send HTTP response headers
    const headers = try std.fmt.allocPrint(context.allocator, "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: {d}\r\n" ++
        "Content-Type: {s}\r\n" ++
        "\r\n", .{ file_size, getMimeType(file_path) });
    defer context.allocator.free(headers);

    // Send file contents
    var send_buf: [8192]u8 = undefined;
    const total_sent: usize = 0;
    while (total_sent < file_size) {
        const to_send = @min(send_buf.len, file_size - total_sent);
        const file_bytes_read = try file.read(send_buf[0..to_send]);
        if (file_bytes_read == 0) break;
    }
}

fn sendErrorResponse(status: []const u8, message: []const u8) !void {
    const response = try std.fmt.allocPrint(std.heap.page_allocator, "HTTP/1.1 {s}\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Content-Length: {d}\r\n" ++
        "\r\n" ++
        "{s}", .{ status, message.len, message });
    defer std.heap.page_allocator.free(response);
}

// Function to determine MIME type based on file extension
fn getMimeType(file_path: []const u8) []const u8 {
    const extension = fs.path.extension(file_path);
    if (extension.len > 1) {
        const ext = extension[1..];
        if (std.mem.eql(u8, ext, "html") or std.mem.eql(u8, ext, "htm")) return "text/html";
        if (std.mem.eql(u8, ext, "css")) return "text/css";
        if (std.mem.eql(u8, ext, "js")) return "application/javascript";
        if (std.mem.eql(u8, ext, "json")) return "application/json";
        if (std.mem.eql(u8, ext, "png")) return "image/png";
        if (std.mem.eql(u8, ext, "jpg") or std.mem.eql(u8, ext, "jpeg")) return "image/jpeg";
        if (std.mem.eql(u8, ext, "gif")) return "image/gif";
        if (std.mem.eql(u8, ext, "svg")) return "image/svg+xml";
        if (std.mem.eql(u8, ext, "ico")) return "image/x-icon";
    }
    return "application/octet-stream";
}
// Main function to start the server
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = &gpa.allocator;

    var context = try initServerContext(allocator);
    defer {
        var it = context.websites.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.root_dir);
            allocator.free(entry.value_ptr.index_file);
            allocator.free(entry.value_ptr.error_page);
        }
        context.websites.deinit();
        ssl.SSL_CTX_free(context.ssl_ctx);
    }

    var server = net.StreamServer.init(.{
        .reuse_address = true,
        .kernel_backlog = 1024,
    });
    defer server.deinit();

    try server.listen(net.Address.parseIp("0.0.0.0", PORT) catch unreachable);

    log.info("Server listening on port {d}", .{PORT});

    while (true) {
        const client = server.accept() catch |err| {
            log.err("Error accepting connection: {}", .{err});
            continue;
        };

        const thread = try std.Thread.spawn(.{}, handleConnection, .{ &context, client });
        thread.detach();
    }
}
