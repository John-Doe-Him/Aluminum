const std = @import("std");
const gl = @import("gl");
const math = @import("math");
const mem = std.mem;
const Allocator = mem.Allocator;

/// RenderEngine is responsible for managing the rendering pipeline of the Aluminum web browser.
pub const RenderEngine = struct {
    allocator: *Allocator,
    window_width: u32,
    window_height: u32,
    render_queue: std.ArrayList(RenderCommand),
    texture_cache: TextureCache,
    shader_program: gl.GLuint,

    /// Initialize a new RenderEngine instance
    pub fn init(allocator: *Allocator, window_width: u32, window_height: u32) !RenderEngine {
        var engine = RenderEngine{
            .allocator = allocator,
            .window_width = window_width,
            .window_height = window_height,
            .render_queue = std.ArrayList(RenderCommand).init(allocator),
            .texture_cache = try TextureCache.init(allocator),
            .shader_program = 0,
        };

        try engine.initializeOpenGL();
        try engine.compileShaders();

        return engine;
    }

    /// Clean up resources used by the RenderEngine
    pub fn deinit(self: *RenderEngine) void {
        self.render_queue.deinit();
        self.texture_cache.deinit();
        gl.deleteProgram(self.shader_program);
    }

    /// Initialize OpenGL context and set up necessary configurations
    fn initializeOpenGL() !void {
        gl.enable(gl.BLEND);
        gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
        gl.clearColor(1.0, 1.0, 1.0, 1.0);
    }

    /// Compile and link shader programs
    fn compileShaders(self: *RenderEngine) !void {
        const vertex_shader_source =
            \\#version 330 core
            \\layout (location = 0) in vec3 aPos;
            \\layout (location = 1) in vec2 aTexCoord;
            \\
            \\out vec2 TexCoord;
            \\
            \\uniform mat4 projection;
            \\
            \\void main()
            \\{
            \\    gl_Position = projection * vec4(aPos.x, aPos.y, aPos.z, 1.0);
            \\    TexCoord = aTexCoord;
            \\}
        ;

        const fragment_shader_source =
            \\#version 330 core
            \\out vec4 FragColor;
            \\
            \\in vec2 TexCoord;
            \\
            \\uniform sampler2D texture1;
            \\
            \\void main()
            \\{
            \\    FragColor = texture(texture1, TexCoord);
            \\}
        ;

        const vertex_shader = try self.compileShader(vertex_shader_source, gl.VERTEX_SHADER);
        const fragment_shader = try self.compileShader(fragment_shader_source, gl.FRAGMENT_SHADER);

        self.shader_program = gl.createProgram();
        gl.attachShader(self.shader_program, vertex_shader);
        gl.attachShader(self.shader_program, fragment_shader);
        gl.linkProgram(self.shader_program);

        // Check for linking errors
        var success: gl.GLint = undefined;
        gl.getProgramiv(self.shader_program, gl.LINK_STATUS, &success);
        if (success == 0) {
            var info_log: [512]u8 = undefined;
            var log_length: gl.GLsizei = undefined;
            gl.getProgramInfoLog(self.shader_program, 512, &log_length, &info_log);
            return error.ShaderLinkingFailed;
        }

        gl.deleteShader(vertex_shader);
        gl.deleteShader(fragment_shader);
    }

    /// Compile a shader from source
    fn compileShader(source: []const u8, shader_type: c_uint) !gl.GLuint {
        const shader = gl.createShader(shader_type);
        const source_ptr: ?[*]const u8 = source.ptr;
        gl.shaderSource(shader, 1, &source_ptr);
        gl.compileShader(shader);

        // Check for compilation errors
        var success: gl.GLint = undefined;
        gl.getShaderiv(shader, gl.COMPILE_STATUS, &success);
        if (success == 0) {
            var info_log: [512]u8 = undefined;
            var log_length: gl.GLsizei = undefined;
            gl.getShaderInfoLog(shader, 512, &log_length, &info_log);
            return error.ShaderCompilationFailed;
        }

        return shader;
    }
    pub fn queueRenderCommand(self: *RenderEngine, command: RenderCommand) !void {
        try self.render_queue.append(command);
    }

    /// Execute all queued render commands
    pub fn render(self: *RenderEngine) !void {
        gl.clear(gl.COLOR_BUFFER_BIT);
        gl.useProgram(self.shader_program);

        // Set up projection matrix
        const projection = math.Mat4.orthographic(0, @as(f32, @floatFromInt(self.window_width)), @as(f32, @floatFromInt(self.window_height)), 0, -1, 1);
        const projection_location = gl.getUniformLocation(self.shader_program, "projection");
        gl.uniformMatrix4fv(projection_location, 1, gl.FALSE, &projection.data);

        for (self.render_queue.items) |command| {
            switch (command) {
                .DrawRect => |rect| try self.drawRect(rect),
                .DrawText => |text| try self.drawText(text),
                .DrawImage => |image| try self.drawImage(image),
            }
        }

        // Clear the render queue after execution
        self.render_queue.clearRetainingCapacity();
    }
    /// Draw a rectangle on the screen
    fn drawRect(rect: Rect) !void {
        const vertices = [_]f32{
            rect.x,              rect.y,               0.0, 0.0, 0.0,
            rect.x + rect.width, rect.y,               0.0, 1.0, 0.0,
            rect.x + rect.width, rect.y + rect.height, 0.0, 1.0, 1.0,
            rect.x,              rect.y + rect.height, 0.0, 0.0, 1.0,
        };

        const indices = [_]u32{ 0, 1, 2, 2, 3, 0 };

        var vbo: gl.GLuint = undefined;
        var vao: gl.GLuint = undefined;
        var ebo: gl.GLuint = undefined;

        gl.genVertexArrays(1, &vao);
        gl.genBuffers(1, &vbo);
        gl.genBuffers(1, &ebo);

        gl.bindVertexArray(vao);

        gl.bindBuffer(gl.ARRAY_BUFFER, vbo);
        gl.bufferData(gl.ARRAY_BUFFER, @sizeOf(f32) * vertices.len, &vertices, gl.STATIC_DRAW);

        gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, ebo);
        gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, @sizeOf(u32) * indices.len, &indices, gl.STATIC_DRAW);

        gl.vertexAttribPointer(0, 3, gl.FLOAT, gl.FALSE, 5 * @sizeOf(f32), null);
        gl.enableVertexAttribArray(0);

        gl.vertexAttribPointer(1, 2, gl.FLOAT, gl.FALSE, 5 * @sizeOf(f32), @ptrFromInt(3 * @sizeOf(f32)));
        gl.enableVertexAttribArray(1);

        // Create a 1x1 white texture for solid color rendering
        var texture: gl.GLuint = undefined;
        gl.genTextures(1, &texture);
        gl.bindTexture(gl.TEXTURE_2D, texture);
        const color_data = [_]u8{ rect.color.r, rect.color.g, rect.color.b, rect.color.a };
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 1, 1, 0, gl.RGBA, gl.UNSIGNED_BYTE, &color_data);

        gl.drawElements(gl.TRIANGLES, 6, gl.UNSIGNED_INT, null);

        gl.deleteVertexArrays(1, &vao);
        gl.deleteBuffers(1, &vbo);
        gl.deleteBuffers(1, &ebo);
        gl.deleteTextures(1, &texture);
    }
    /// Draw text on the screen
    fn drawText(self: *RenderEngine, text: Text) !void {
        // TODO: Implement text rendering using a font atlas
        // This is a placeholder implementation
        const rect = Rect{
            .x = text.x,
            .y = text.y,
            .width = @as(f32, @floatFromInt(text.content.len)) * 8, // Assume 8 pixels per character
            .height = 16, // Assume 16 pixels tall
            .color = text.color,
        };
        try self.drawRect(rect);
    }
    /// Draw an image on the screen
    fn drawImage(self: *RenderEngine, image: Image) !void {
        const texture = try self.texture_cache.getOrLoadTexture(image.path);

        const vertices = [_]f32{
            image.x,               image.y,                0.0, 0.0, 0.0,
            image.x + image.width, image.y,                0.0, 1.0, 0.0,
            image.x + image.width, image.y + image.height, 0.0, 1.0, 1.0,
            image.x,               image.y + image.height, 0.0, 0.0, 1.0,
        };

        const indices = [_]u32{ 0, 1, 2, 2, 3, 0 };

        var vbo: gl.GLuint = undefined;
        var vao: gl.GLuint = undefined;
        var ebo: gl.GLuint = undefined;

        gl.genVertexArrays(1, &vao);
        gl.genBuffers(1, &vbo);
        gl.genBuffers(1, &ebo);

        gl.bindVertexArray(vao);

        gl.bindBuffer(gl.ARRAY_BUFFER, vbo);
        gl.bufferData(gl.ARRAY_BUFFER, @sizeOf(f32) * vertices.len, &vertices, gl.STATIC_DRAW);

        gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, ebo);
        gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, @sizeOf(u32) * indices.len, &indices, gl.STATIC_DRAW);

        gl.vertexAttribPointer(0, 3, gl.FLOAT, gl.FALSE, 5 * @sizeOf(f32), null);
        gl.enableVertexAttribArray(0);

        gl.vertexAttribPointer(1, 2, gl.FLOAT, gl.FALSE, 5 * @sizeOf(f32), @ptrFromInt(3 * @sizeOf(f32)));
        gl.enableVertexAttribArray(1);

        gl.bindTexture(gl.TEXTURE_2D, texture);
        gl.drawElements(gl.TRIANGLES, 6, gl.UNSIGNED_INT, null);

        gl.deleteVertexArrays(1, &vao);
        gl.deleteBuffers(1, &vbo);
        gl.deleteBuffers(1, &ebo);
    }
};

/// Represents a color in RGBA format
pub const Color = struct {
    r: u8,
    g: u8,
    b: u8,
    a: u8,
};

/// Represents a rectangle to be drawn
pub const Rect = struct {
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    color: Color,
};

/// Represents text to be drawn
pub const Text = struct {
    x: f32,
    y: f32,
    content: []const u8,
    color: Color,
};

/// Represents an image to be drawn
pub const Image = struct {
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    path: []const u8,
};

/// Represents a render command
pub const RenderCommand = union(enum) {
    DrawRect: Rect,
    DrawText: Text,
    DrawImage: Image,
};

/// Manages texture caching to improve performance
const TextureCache = struct {
    allocator: *Allocator,
    textures: std.StringHashMap(gl.GLuint),

    fn init(allocator: *Allocator) !TextureCache {
        return TextureCache{
            .allocator = allocator,
            .textures = std.StringHashMap(gl.GLuint).init(allocator),
        };
    }

    fn deinit(self: *TextureCache) void {
        var it = self.textures.iterator();
        while (it.next()) |entry| {
            gl.deleteTextures(1, &entry.value_ptr.*);
        }
        self.textures.deinit();
    }

    fn getOrLoadTexture(self: *TextureCache, path: []const u8) !gl.GLuint {
        if (self.textures.get(path)) |texture| {
            return texture;
        }

        const texture = try self.loadTexture(path);
        try self.textures.put(path, texture);
        return texture;
    }

    fn loadTexture() !gl.GLuint {
        // TODO: Implement actual texture loading from file
        // This is a placeholder implementation that creates a checkerboard pattern
        var texture: gl.GLuint = undefined;
        gl.genTextures(1, &texture);
        gl.bindTexture(gl.TEXTURE_2D, texture);

        const width: c_int = 64;
        const height: c_int = 64;
        var data: [64 * 64 * 4]u8 = undefined;

        var y: usize = 0;
        while (y < height) : (y += 1) {
            var x: usize = 0;
            while (x < width) : (x += 1) {
                const index = (y * width + x) * 4;
                const color: u8 = if ((x / 8 + y / 8) % 2 == 0) 255 else 0;
                data[index] = color;
                data[index + 1] = color;
                data[index + 2] = color;
                data[index + 3] = 255;
            }
        }
    }
};
