const std = @import("std");
const ArrayList = std.ArrayList;
const AutoHashMap = std.AutoHashMap;
const StringHashMap = std.StringHashMap;
const Allocator = std.mem.Allocator;
const json = std.json;

/// Represents a suggested query with its associated weight
const SuggestedQuery = struct {
    query: []const u8,
    weight: f64,
};

/// Manages suggested queries for the Aluminum web browser
pub const SuggestedQueries = struct {
    allocator: *Allocator,
    queries: ArrayList(SuggestedQuery),
    query_index: StringHashMap(usize),

    /// Initialize a new SuggestedQueries instance
    pub fn init(allocator: *Allocator) !SuggestedQueries {
        return SuggestedQueries{
            .allocator = allocator,
            .queries = ArrayList(SuggestedQuery).init(allocator),
            .query_index = StringHashMap(usize).init(allocator),
        };
    }

    /// Deinitialize and free resources
    pub fn deinit(self: *SuggestedQueries) void {
        for (self.queries.items) |query| {
            self.allocator.free(query.query);
        }
        self.queries.deinit();
        self.query_index.deinit();
    }

    /// Add a new suggested query or update its weight if it already exists
    pub fn addQuery(self: *SuggestedQueries, query: []const u8, weight: f64) !void {
        const owned_query = try self.allocator.dupe(u8, query);
        errdefer self.allocator.free(owned_query);

        if (self.query_index.get(query)) |index| {
            self.queries.items[index].weight += weight;
        } else {
            const new_index = self.queries.items.len;
            try self.queries.append(.{ .query = owned_query, .weight = weight });
            try self.query_index.put(owned_query, new_index);
        }
    }

    /// Remove a suggested query
    pub fn removeQuery(self: *SuggestedQueries, query: []const u8) void {
        if (self.query_index.remove(query)) |index| {
            const last_index = self.queries.items.len - 1;
            if (index != last_index) {
                self.queries.items[index] = self.queries.items[last_index];
                self.query_index.put(self.queries.items[index].query, index) catch {};
            }
            _ = self.queries.pop();
            self.allocator.free(query);
        }
    }

    /// Get the top N suggested queries
    pub fn getTopQueries(self: *SuggestedQueries, n: usize) ![]SuggestedQuery {
        var sorted_queries = try self.allocator.dupe(SuggestedQuery, self.queries.items);
        defer self.allocator.free(sorted_queries);

        std.sort.sort(SuggestedQuery, sorted_queries, {}, struct {
            fn compare(_: void, a: SuggestedQuery, b: SuggestedQuery) bool {
                return a.weight > b.weight;
            }
        }.compare);

        const result_len = @min(n, sorted_queries.len);
        const result = try self.allocator.alloc(SuggestedQuery, result_len);
        std.mem.copy(SuggestedQuery, result, sorted_queries[0..result_len]);

        return result;
    }

    /// Load suggested queries from a JSON file
    pub fn loadFromFile(self: *SuggestedQueries, file_path: []const u8) !void {
        const file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();

        const file_size = try file.getEndPos();
        const file_contents = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(file_contents);

        _ = try file.readAll(file_contents);

        var parser = json.Parser.init(self.allocator, false);
        defer parser.deinit();

        var tree = try parser.parse(file_contents);
        defer tree.deinit();

        const root = tree.root;

        if (root.Object.get("suggested_queries")) |queries_array| {
            for (queries_array.Array.items) |query_obj| {
                const query = query_obj.Object.get("query").?.String;
                const weight = query_obj.Object.get("weight").?.Float;
                try self.addQuery(query, weight);
            }
        }
    }

    /// Save suggested queries to a JSON file
    pub fn saveToFile(self: *SuggestedQueries, file_path: []const u8) !void {
        var file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        var writer = file.writer();

        try writer.writeAll("{\n  \"suggested_queries\": [\n");

        for (self.queries.items, 0..) |query, i| {
            try writer.print("    {{\"query\": \"{s}\", \"weight\": {d}}}", .{ query.query, query.weight });
            if (i < self.queries.items.len - 1) {
                try writer.writeAll(",");
            }
            try writer.writeAll("\n");
        }

        try writer.writeAll("  ]\n}\n");
    }
    /// Update query weights based on user interaction
    pub fn updateQueryWeight(self: *SuggestedQueries, query: []const u8, interaction_type: enum { Click, Ignore }) !void {
        if (self.query_index.get(query)) |index| {
            switch (interaction_type) {
                .Click => self.queries.items[index].weight *= 1.1,
                .Ignore => self.queries.items[index].weight *= 0.9,
            }
        } else {
            if (interaction_type == .Click) {
                try self.addQuery(query, 1.0);
            }
        }
    }

    /// Periodically clean up and normalize weights
    pub fn normalizeWeights(self: *SuggestedQueries) void {
        var max_weight: f64 = 0;
        for (self.queries.items) |query| {
            if (query.weight > max_weight) {
                max_weight = query.weight;
            }
        }

        if (max_weight > 0) {
            for (self.queries.items) |*query| {
                query.weight /= max_weight;
            }
        }
    }

    /// Generate context-aware suggestions based on user's current input
    pub fn getContextAwareSuggestions(self: *SuggestedQueries, input: []const u8, max_suggestions: usize) ![]SuggestedQuery {
        var matching_queries = ArrayList(SuggestedQuery).init(self.allocator);
        defer matching_queries.deinit();

        for (self.queries.items) |query| {
            if (std.mem.indexOf(u8, query.query, input) != null) {
                try matching_queries.append(query);
            }
        }

        var sorted_matches = try self.allocator.dupe(SuggestedQuery, matching_queries.items);
        defer self.allocator.free(sorted_matches);

        std.sort.sort(SuggestedQuery, sorted_matches, {}, struct {
            fn compare(_: void, a: SuggestedQuery, b: SuggestedQuery) bool {
                return a.weight > b.weight;
            }
        }.compare);

        const result_len = @min(max_suggestions, sorted_matches.len);
        const result = try self.allocator.alloc(SuggestedQuery, result_len);
        std.mem.copy(SuggestedQuery, result, sorted_matches[0..result_len]);

        return result;
    }

    /// Merge suggestions from multiple sources (e.g., local history, global trends)
    pub fn mergeSuggestions(self: *SuggestedQueries, other_sources: []const SuggestedQueries, weights: []const f64) !void {
        std.debug.assert(other_sources.len == weights.len);

        for (other_sources, 0..) |source, i| {
            for (source.queries.items) |query| {
                try self.addQuery(query.query, query.weight * weights[i]);
            }
        }

        self.normalizeWeights();
    }
    /// Export suggestions to a CSV file for analysis
    pub fn exportToCSV(self: *SuggestedQueries, file_path: []const u8) !void {
        var file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        var writer = file.writer();

        try writer.writeAll("Query,Weight\n");

        for (self.queries.items) |query| {
            try writer.print("\"{s}\",{d}\n", .{ query.query, query.weight });
        }
    }

    /// Import suggestions from a CSV file
    pub fn importFromCSV(self: *SuggestedQueries, file_path: []const u8) !void {
        const file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();

        var buf_reader = std.io.bufferedReader(file.reader());
        var in_stream = buf_reader.reader();

        var buf: [1024]u8 = undefined;
        _ = try in_stream.readUntilDelimiterOrEof(&buf, '\n'); // Skip header

        while (try in_stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
            var iter = std.mem.split(u8, line, ",");
            const query = iter.next() orelse continue;
            const weight_str = iter.next() orelse continue;

            const weight = try std.fmt.parseFloat(f64, weight_str);
            try self.addQuery(query, weight);
        }
    }

    /// Remove outdated or low-weight suggestions
    pub fn pruneQueries(self: *SuggestedQueries, weight_threshold: f64, max_queries: usize) !void {
        var pruned_queries = ArrayList(SuggestedQuery).init(self.allocator);
        defer pruned_queries.deinit();

        for (self.queries.items) |query| {
            if (query.weight >= weight_threshold) {
                try pruned_queries.append(query);
            } else {
                self.allocator.free(query.query);
            }
        }

        std.sort.sort(SuggestedQuery, pruned_queries.items, {}, struct {
            fn compare(_: void, a: SuggestedQuery, b: SuggestedQuery) bool {
                return a.weight > b.weight;
            }
        }.compare);

        const new_len = @min(pruned_queries.items.len, max_queries);
        if (new_len < pruned_queries.items.len) {
            for (pruned_queries.items[new_len..]) |query| {
                self.allocator.free(query.query);
            }
            pruned_queries.shrinkRetainingCapacity(new_len);
        }

        self.queries.clearAndFree();
        self.query_index.clearAndFree();

        try self.queries.appendSlice(pruned_queries.items);
        for (self.queries.items, 0..) |query, i| {
            try self.query_index.put(query.query, i);
        }
    }
    /// Generate a report of query statistics
    pub fn generateStatisticsReport(self: *SuggestedQueries) ![]u8 {
        var report = ArrayList(u8).init(self.allocator);
        errdefer report.deinit();

        var writer = report.writer();

        try writer.writeAll("Suggested Queries Statistics Report\n");
        try writer.writeAll("===================================\n\n");

        try writer.print("Total number of queries: {d}\n", .{self.queries.items.len});

        if (self.queries.items.len > 0) {
            var total_weight: f64 = 0;
            var min_weight: f64 = std.math.inf(f64);
            var max_weight: f64 = -std.math.inf(f64);

            for (self.queries.items) |query| {
                total_weight += query.weight;
                min_weight = @min(min_weight, query.weight);
                max_weight = @max(max_weight, query.weight);
            }

            const avg_weight = total_weight / @as(f64, @floatFromInt(self.queries.items.len));

            try writer.print("\nWeight statistics:\n", .{});
            try writer.print("  Minimum weight: {d:.4}\n", .{min_weight});
            try writer.print("  Maximum weight: {d:.4}\n", .{max_weight});
            try writer.print("  Average weight: {d:.4}\n", .{avg_weight});

            try writer.writeAll("\nTop 10 queries by weight:\n");
            var sorted_queries = try self.allocator.dupe(SuggestedQuery, self.queries.items);
            defer self.allocator.free(sorted_queries);

            std.sort.sort(SuggestedQuery, sorted_queries, {}, struct {
                fn compare(_: void, a: SuggestedQuery, b: SuggestedQuery) bool {
                    return a.weight > b.weight;
                }
            }.compare);

            for (sorted_queries[0..@min(10, sorted_queries.len)], 0..) |query, i| {
                try writer.print("  {d}. \"{s}\" (weight: {d:.4})\n", .{ i + 1, query.query, query.weight });
            }
        }

        return report.toOwnedSlice();
    }
};
/// Main function to demonstrate the usage of SuggestedQueries
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = &gpa.allocator;

    var suggested_queries = try SuggestedQueries.init(allocator);
    defer suggested_queries.deinit();

    // Add some initial queries
    try suggested_queries.addQuery("Aluminum browser features", 1.0);
    try suggested_queries.addQuery("How to customize Aluminum", 0.8);
    try suggested_queries.addQuery("Aluminum vs Chrome", 1.2);
    try suggested_queries.addQuery("Aluminum privacy settings", 0.9);
    try suggested_queries.addQuery("Aluminum extensions", 1.1);

    // Simulate user interactions
    try suggested_queries.updateQueryWeight("Aluminum browser features", .Click);
    try suggested_queries.updateQueryWeight("How to customize Aluminum", .Click);
    try suggested_queries.updateQueryWeight("Aluminum vs Chrome", .Ignore);

    // Get top queries
    const top_queries = try suggested_queries.getTopQueries(3);
    defer allocator.free(top_queries);

    std.debug.print("Top 3 suggested queries:\n", .{});
    for (top_queries, 0..) |query, i| {
        std.debug.print("{d}. {s} (weight: {d:.2})\n", .{ i + 1, query.query, query.weight });
    }

    // Generate and print statistics report
    const report = try suggested_queries.generateStatisticsReport();
    defer allocator.free(report);
}
