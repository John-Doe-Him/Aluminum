const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const process = std.process;
const Builder = std.build.Builder;
const Step = std.build.Step;
const CrossTarget = std.zig.CrossTarget;
const Mode = std.builtin.Mode;

// Configuration constants
const ZIG_FRONTEND_DIR = "ZigFrontend";
const ZIG_COMPILER_RT_DIR = "compiler-rt";
const ZIG_LIBC_DIR = "libc";
const ZIG_LIBCXX_DIR = "libcxx";
const ZIG_LIBUNWIND_DIR = "libunwind";

pub fn build(b: *Builder) !void {
    // Parse command-line arguments
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    // Create the main executable
    const exe = b.addExecutable("zig-frontend", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    // Add dependencies
    try addDependencies(b, exe);

    // Set up the run step
    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Create a "run" step
    const run_step = b.step("run", "Run the Zig frontend");
    run_step.dependOn(&run_cmd.step);

    // Set up testing
    const test_step = b.step("test", "Run unit tests");
    const tests = b.addTest("src/tests.zig");
    tests.setTarget(target);
    tests.setBuildMode(mode);
    test_step.dependOn(&tests.step);

    // Set up documentation generation
    const docs_step = b.step("docs", "Generate documentation");
    const docs = b.addTest("src/main.zig");
    docs.emit_docs = .emit;
    docs_step.dependOn(&docs.step);

    // Set up linting
    const lint_step = b.step("lint", "Run linter");
    const lint = b.addSystemCommand(&[_][]const u8{
        "zig", "fmt", "src",
    });
    lint_step.dependOn(&lint.step);

    // Set up benchmarking
    const bench_step = b.step("bench", "Run benchmarks");
    const bench = b.addExecutable("bench", "src/bench.zig");
    bench.setTarget(target);
    bench.setBuildMode(mode);
    bench_step.dependOn(&bench.run().step);

    // Additional build steps for the Zig frontend
    try setupZigFrontend(b, target, mode);
}

fn addDependencies(b: *Builder, exe: *std.build.LibExeObjStep) !void {
    // Add standard library
    exe.linkLibC();
    exe.linkLibCpp();

    // Add third-party dependencies
    const deps = b.addFetchDepsTarball(
        "https://rawgithubcontent.com/zig_modded/FrontendModule/Repo/deps/frontend-deps.tar.gz",
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    );
    exe.step.dependOn(&deps.step);

    // Link against LLVM
    exe.linkSystemLibrary("LLVM");

    // Add any other necessary dependencies
    // ...
}

fn setupZigFrontend(b: *Builder, target: CrossTarget, mode: Mode) !void {
    // Create the Zig frontend directory if it doesn't exist
    try fs.cwd().makePath(ZIG_FRONTEND_DIR);

    // Generate the Zig frontend source files
    try generateZigFrontendSources(b);

    // Build the Zig frontend library
    const lib = b.addStaticLibrary("zigfrontend", ZIG_FRONTEND_DIR ++ "/src/lib.zig");
    lib.setTarget(target);
    lib.setBuildMode(mode);
    lib.install();

    // Build additional components
    try buildCompilerRT(b, target, mode);
    try buildLibC(b, target, mode);
    try buildLibCXX(b, target, mode);
    try buildLibUnwind(b, target, mode);

    // Set up integration tests
    const integration_tests = b.addTest(ZIG_FRONTEND_DIR ++ "/tests/integration_tests.zig");
    integration_tests.setTarget(target);
    integration_tests.setBuildMode(mode);
    const test_step = b.step("test-frontend", "Run Zig frontend integration tests");
    test_step.dependOn(&integration_tests.step);

    // Set up benchmarks specific to the Zig frontend
    const frontend_bench = b.addExecutable("frontend-bench", ZIG_FRONTEND_DIR ++ "/bench/frontend_bench.zig");
    frontend_bench.setTarget(target);
    frontend_bench.setBuildMode(mode);
    const bench_step = b.step("bench-frontend", "Run Zig frontend benchmarks");
    bench_step.dependOn(&frontend_bench.run().step);
}

fn generateZigFrontendSources(b: *Builder) !void {
    // Generate lexer
    try generateLexer(b);

    // Generate parser
    try generateParser(b);

    // Generate AST
    try generateAST(b);

    // Generate semantic analyzer
    try generateSemanticAnalyzer(b);

    // Generate code generator
    try generateCodeGenerator(b);

    // Generate other necessary components
    // ...
}

fn generateLexer(b: *Builder) !void {
    const lexer_gen = b.addSystemCommand(&[_][]const u8{
        "flex", "-o", ZIG_FRONTEND_DIR ++ "/src/lexer.c", ZIG_FRONTEND_DIR ++ "/src/lexer.l",
    });
    try lexer_gen.step.make();
}

fn generateParser(b: *Builder) !void {
    const parser_gen = b.addSystemCommand(&[_][]const u8{
        "bison", "-d", "-o", ZIG_FRONTEND_DIR ++ "/src/parser.c", ZIG_FRONTEND_DIR ++ "/src/parser.y",
    });
    try parser_gen.step.make();
}

fn generateAST(b: *Builder) !void {
    // Implementation for generating Abstract Syntax Tree
    // This could involve creating Zig structs and enums to represent different AST nodes
    const ast_gen = b.addSystemCommand(&[_][]const u8{
        "zig", "run",                              ZIG_FRONTEND_DIR ++ "/tools/ast_generator.zig",
        "--",  ZIG_FRONTEND_DIR ++ "/src/ast.zig",
    });
    try ast_gen.step.make();
}

fn generateSemanticAnalyzer(b: *Builder) !void {
    // Implementation for generating the semantic analyzer
    const semantic_gen = b.addSystemCommand(&[_][]const u8{
        "zig", "run",                                            ZIG_FRONTEND_DIR ++ "/tools/semantic_analyzer_generator.zig",
        "--",  ZIG_FRONTEND_DIR ++ "/src/semantic_analyzer.zig",
    });
    try semantic_gen.step.make();
}

fn generateCodeGenerator(b: *Builder) !void {
    // Implementation for generating the code generator
    const codegen = b.addSystemCommand(&[_][]const u8{
        "zig", "run",                                  ZIG_FRONTEND_DIR ++ "/tools/codegen_generator.zig",
        "--",  ZIG_FRONTEND_DIR ++ "/src/codegen.zig",
    });
    try codegen.step.make();
}

fn buildCompilerRT(b: *Builder, target: CrossTarget, mode: Mode) !void {
    const compiler_rt = b.addStaticLibrary("compiler_rt", null);
    compiler_rt.setTarget(target);
    compiler_rt.setBuildMode(mode);
    compiler_rt.addCSourceFiles(&.{
        ZIG_COMPILER_RT_DIR ++ "/builtins/absvdi2.c",
        ZIG_COMPILER_RT_DIR ++ "/builtins/absvsi2.c",
        // Add more compiler-rt source files as needed
    }, &.{ "-std=c11", "-fno-builtin" });
    compiler_rt.setOutputDir(ZIG_FRONTEND_DIR ++ "/lib");
    compiler_rt.install();
}

fn buildLibC(b: *Builder, target: CrossTarget, mode: Mode) !void {
    const libc = b.addStaticLibrary("c", null);
    libc.setTarget(target);
    libc.setBuildMode(mode);
    libc.addCSourceFiles(&.{
        ZIG_LIBC_DIR ++ "/src/string/memcpy.c",
        ZIG_LIBC_DIR ++ "/src/string/memset.c",
        // Add more libc source files as needed
    }, &.{ "-std=c11", "-fno-builtin" });
    libc.setOutputDir(ZIG_FRONTEND_DIR ++ "/lib");
    libc.install();
}

fn buildLibCXX(b: *Builder, target: CrossTarget, mode: Mode) !void {
    const libcxx = b.addStaticLibrary("c++", null);
    libcxx.setTarget(target);
    libcxx.setBuildMode(mode);
    libcxx.addCSourceFiles(&.{
        ZIG_LIBCXX_DIR ++ "/src/string.cpp",
        ZIG_LIBCXX_DIR ++ "/src/vector.cpp",
        // Add more libcxx source files as needed
    }, &.{ "-std=c++14", "-fno-exceptions", "-fno-rtti" });
    libcxx.setOutputDir(ZIG_FRONTEND_DIR ++ "/lib");
    libcxx.install();
}

fn buildLibUnwind(b: *Builder, target: CrossTarget, mode: Mode) !void {
    const libunwind = b.addStaticLibrary("unwind", null);
    libunwind.setTarget(target);
    libunwind.setBuildMode(mode);
    libunwind.addCSourceFiles(&.{
        ZIG_LIBUNWIND_DIR ++ "/src/Unwind-EHABI.cpp",
        ZIG_LIBUNWIND_DIR ++ "/src/Unwind-seh.cpp",
        // Add more libunwind source files as needed
    }, &.{ "-std=c++14", "-fno-exceptions", "-funwind-tables" });
    libunwind.setOutputDir(ZIG_FRONTEND_DIR ++ "/lib");
    libunwind.install();
}

// Helper function to create a custom build step
fn customBuildStep(b: *Builder, name: []const u8, description: []const u8, run: fn (*Step) anyerror!void) *Step {
    const step = b.allocator.create(Step) catch @panic("OOM");
    step.* = Step.init(.Custom, name, b.allocator, run);
    step.description = description;
    return step;
}

// Add any additional helper functions or utilities as needed
// ...
