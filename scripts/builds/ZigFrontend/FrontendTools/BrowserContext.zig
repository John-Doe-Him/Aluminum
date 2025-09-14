const std = @import("std");
const http = @import("http");
const ssl = @import("ssl");
const json = @import("json");
const url = @import("url");
const dom = @import("dom");
const css = @import("css");
const js = @import("javascript");
const storage = @import("storage");
const network = @import("network");
const rendering = @import("rendering");

/// BrowserContext represents the environment in which a web page is loaded and executed.
/// It encapsulates all the necessary components and settings for a browsing session.
pub const BrowserContext = struct {
    allocator: *std.mem.Allocator,
    settings: Settings,
    history: History,
    cookies: storage.CookieJar,
    cache: storage.Cache,
    network_manager: network.NetworkManager,
    dom_tree: *dom.Document,
    css_engine: *css.Engine,
    js_engine: *js.Engine,
    render_context: *rendering.Context,

    /// Initialize a new BrowserContext with default settings
    pub fn init(allocator: *std.mem.Allocator) !*BrowserContext {
        var self = try allocator.create(BrowserContext);
        errdefer allocator.destroy(self);

        self.* = BrowserContext{
            .allocator = allocator,
            .settings = try Settings.init(allocator),
            .history = try History.init(allocator),
            .cookies = try storage.CookieJar.init(allocator),
            .cache = try storage.Cache.init(allocator),
            .network_manager = try network.NetworkManager.init(allocator),
            .dom_tree = try dom.Document.init(allocator),
            .css_engine = try css.Engine.init(allocator),
            .js_engine = try js.Engine.init(allocator),
            .render_context = try rendering.Context.init(allocator),
        };

        try self.applyDefaultSettings();
        return self;
    }

    fn applyDefaultSettings(self: *BrowserContext) !void {
        try self.settings.setUserAgent("Aluminum/1.0");
        try self.settings.setDefaultEncoding("UTF-8");
        try self.settings.setJavaScriptEnabled(true);
        try self.settings.setCookiesEnabled(true);
    }
};

/// Load a web page from the given URL
pub fn loadUrl(self: *BrowserContext, url_str: []const u8) !void {
    const parsed_url = try url.parse(url_str);
    const request = try self.createHttpRequest(parsed_url);
    const response = try self.network_manager.sendRequest(request);

    try self.processResponse(response);
    try self.history.addEntry(url_str);
}

/// Create an HTTP request for the given URL
fn createHttpRequest(self: *BrowserContext, parsed_url: url.ParsedUrl) !http.Request {
    var headers = std.StringHashMap([]const u8).init(self.allocator);
    errdefer headers.deinit();

    try headers.put("User-Agent", self.settings.getUserAgent());
    try headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
    try headers.put("Accept-Language", "en-US,en;q=0.5");

    return http.Request{
        .method = .GET,
        .url = parsed_url,
        .headers = headers,
        .body = null,
    };
}

/// Process the HTTP response and render the page
fn processResponse(self: *BrowserContext, response: http.Response) !void {
    switch (response.status) {
        200 => try self.renderPage(response),
        301, 302, 303, 307, 308 => try self.handleRedirect(response),
        else => try self.handleError(response),
    }
}

/// Render the page content
fn renderPage(self: *BrowserContext, response: http.Response) !void {
    const content_type = response.headers.get("Content-Type") orelse "text/html";

    if (std.mem.startsWith(u8, content_type, "text/html")) {
        try self.renderHtml(response.body);
    } else if (std.mem.startsWith(u8, content_type, "application/json")) {
        try self.renderJson(response.body);
    } else {
        // Handle other content types or show raw content
        try self.renderRawContent(response.body);
    }
}

/// Render HTML content
fn renderHtml(self: *BrowserContext, html: []const u8) !void {
    // Parse HTML and build DOM tree
    try self.dom_tree.parseHtml(html);

    // Apply CSS styles
    try self.css_engine.applyStyles(self.dom_tree);

    // Execute JavaScript
    if (self.settings.isJavaScriptEnabled()) {
        try self.js_engine.executeScripts(self.dom_tree);
    }

    // Perform layout calculations
    try self.render_context.calculateLayout(self.dom_tree);

    // Render the page
    try self.render_context.paint();
}

/// Render JSON content
fn renderJson(self: *BrowserContext, json_str: []const u8) !void {
    const parsed_json = try json.parse(self.allocator, json_str);
    defer json.parseFree(self.allocator, parsed_json);

    // Create a simple DOM representation of the JSON data
    try self.dom_tree.createJsonView(parsed_json);

    // Apply minimal styling
    try self.css_engine.applyJsonStyles(self.dom_tree);

    // Perform layout calculations
    try self.render_context.calculateLayout(self.dom_tree);

    // Render the JSON view
    try self.render_context.paint();
}

/// Render raw content
fn renderRawContent(self: *BrowserContext, content: []const u8) !void {
    // Create a simple DOM representation of the raw content
    try self.dom_tree.createRawContentView(content);

    // Apply minimal styling
    try self.css_engine.applyRawContentStyles(self.dom_tree);

    // Perform layout calculations
    try self.render_context.calculateLayout(self.dom_tree);

    // Render the raw content view
    try self.render_context.paint();
}

/// Handle HTTP redirects
fn handleRedirect(self: *BrowserContext, response: http.Response) !void {
    const location = response.headers.get("Location") orelse return error.MissingRedirectLocation;
    const new_url = try url.resolveRelative(response.request.url, location);
    try self.loadUrl(new_url);
}

/// Handle HTTP errors
fn handleError(self: *BrowserContext, response: http.Response) !void {
    // Create an error page
    const error_html = try std.fmt.allocPrint(self.allocator, "<html><body><h1>Error {d}</h1><p>{s}</p></body></html>", .{ response.status, response.statusText() });
    defer self.allocator.free(error_html);

    try self.renderHtml(error_html);
}

/// Navigate back in the browsing history
pub fn goBack(self: *BrowserContext) !void {
    const previous_url = try self.history.getPrevious();
    try self.loadUrl(previous_url);
}

/// Navigate forward in the browsing history
pub fn goForward(self: *BrowserContext) !void {
    const next_url = try self.history.getNext();
    try self.loadUrl(next_url);
}

/// Reload the current page
pub fn reload(self: *BrowserContext) !void {
    const current_url = try self.history.getCurrent();
    try self.loadUrl(current_url);
}

/// Set a cookie for the current domain
pub fn setCookie(self: *BrowserContext, name: []const u8, value: []const u8) !void {
    const current_url = try self.history.getCurrent();
    const parsed_url = try url.parse(current_url);
    try self.cookies.set(parsed_url.host, name, value);
}

/// Get a cookie value for the current domain
pub fn getCookie(self: *BrowserContext, name: []const u8) ?[]const u8 {
    const current_url = self.history.getCurrent() catch return null;
    const parsed_url = url.parse(current_url) catch return null;
    return self.cookies.get(parsed_url.host, name);
}

/// Clear all cookies
pub fn clearCookies(self: *BrowserContext) void {
    self.cookies.clear();
}

/// Clear browsing data (cookies, cache, and history)
pub fn clearBrowsingData(self: *BrowserContext) void {
    self.cookies.clear();
    self.cache.clear();
    self.history.clear();
}

/// Set the proxy server for the browser context
pub fn setProxy(self: *BrowserContext, proxy_url: ?[]const u8) !void {
    try self.settings.setProxy(proxy_url);
    try self.network_manager.updateProxy(proxy_url);
}

/// Enable or disable JavaScript execution
pub fn setJavaScriptEnabled(self: *BrowserContext, enabled: bool) !void {
    try self.settings.setJavaScriptEnabled(enabled);
    if (enabled) {
        try self.js_engine.enable();
    } else {
        self.js_engine.disable();
    }
}

/// Set the user agent string
pub fn setUserAgent(self: *BrowserContext, user_agent: []const u8) !void {
    try self.settings.setUserAgent(user_agent);
}

/// Get the current page title
pub fn getPageTitle(self: *BrowserContext) ?[]const u8 {
    return self.dom_tree.getTitle();
}

/// Get the current page URL
pub fn getCurrentUrl(self: *BrowserContext) ?[]const u8 {
    return self.history.getCurrent() catch null;
}

/// Execute JavaScript in the context of the current page
pub fn executeScript(self: *BrowserContext, script: []const u8) !js.Value {
    if (!self.settings.isJavaScriptEnabled()) {
        return error.JavaScriptDisabled;
    }
    return self.js_engine.evaluate(script);
}

/// Add a new stylesheet to the current page
pub fn addStylesheet(self: *BrowserContext, stylesheet: []const u8) !void {
    try self.css_engine.addStylesheet(stylesheet);
    try self.css_engine.applyStyles(self.dom_tree);
    try self.render_context.calculateLayout(self.dom_tree);
    try self.render_context.paint();
}

/// Take a screenshot of the current page
pub fn takeScreenshot(self: *BrowserContext, file_path: []const u8) !void {
    const screenshot = try self.render_context.captureScreenshot();
    defer self.allocator.free(screenshot);

    var file = try std.fs.cwd().createFile(file_path, .{});
    defer file.close();

    try file.writeAll(screenshot);
}

/// Print the current page to a PDF file
pub fn printToPdf(self: *BrowserContext, file_path: []const u8) !void {
    const pdf_data = try self.render_context.generatePdf();
    defer self.allocator.free(pdf_data);

    var file = try std.fs.cwd().createFile(file_path, .{});
    defer file.close();

    try file.writeAll(pdf_data);
}

/// Clean up resources used by the BrowserContext
pub fn deinit(self: *BrowserContext) void {
    self.settings.deinit();
    self.history.deinit();
    self.cookies.deinit();
    self.cache.deinit();
    self.network_manager.deinit();
    self.dom_tree.deinit();
    self.css_engine.deinit();
    self.js_engine.deinit();
    self.render_context.deinit();
    self.allocator.destroy(self);
}

/// Settings stores configuration options for the browser context
const Settings = struct {
    allocator: *std.mem.Allocator,
    user_agent: []u8,
    default_encoding: []u8,
    javascript_enabled: bool,
    cookies_enabled: bool,
    max_connections: u32,
    proxy: ?[]u8,

    fn init(allocator: *std.mem.Allocator) !Settings {
        return Settings{
            .allocator = allocator,
            .user_agent = try allocator.dupe(u8, ""),
            .default_encoding = try allocator.dupe(u8, ""),
            .javascript_enabled = false,
            .cookies_enabled = false,
            .max_connections = 0,
            .proxy = null,
        };
    }

    fn setUserAgent(self: *Settings, user_agent: []const u8) !void {
        self.allocator.free(self.user_agent);
        self.user_agent = try self.allocator.dupe(u8, user_agent);
    }

    fn getUserAgent(self: *Settings) []const u8 {
        return self.user_agent;
    }

    fn setDefaultEncoding(self: *Settings, encoding: []const u8) !void {
        self.allocator.free(self.default_encoding);
        self.default_encoding = try self.allocator.dupe(u8, encoding);
    }

    fn setJavaScriptEnabled(self: *Settings, enabled: bool) !void {
        self.javascript_enabled = enabled;
    }

    fn isJavaScriptEnabled(self: *Settings) bool {
        return self.javascript_enabled;
    }

    fn setCookiesEnabled(self: *Settings, enabled: bool) !void {
        self.cookies_enabled = enabled;
    }

    fn setMaxConnections(self: *Settings, max_connections: u32) !void {
        self.max_connections = max_connections;
    }

    fn setProxy(self: *Settings, proxy_url: ?[]const u8) !void {
        if (self.proxy) |old_proxy| {
            self.allocator.free(old_proxy);
        }
        self.proxy = if (proxy_url) |proxy_url_value| try self.allocator.dupe(u8, proxy_url_value) else null;
    }

    fn deinit(self: *Settings) void {
        self.allocator.free(self.user_agent);
        self.allocator.free(self.default_encoding);
        if (self.proxy) |proxy| {
            self.allocator.free(proxy);
        }
    }
};
/// History manages the browsing history for the browser context
const History = struct {
    allocator: *std.mem.Allocator,
    entries: std.ArrayList([]u8),
    current_index: usize,

    fn init(allocator: *std.mem.Allocator) !History {
        return History{
            .allocator = allocator,
            .entries = std.ArrayList([]u8).init(allocator),
            .current_index = 0,
        };
    }

    fn addEntry() !void {}
};
