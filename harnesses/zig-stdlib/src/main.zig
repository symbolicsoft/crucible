const std = @import("std");
const json = std.json;
const fmt = std.fmt;
const ml_kem = std.crypto.kem.ml_kem;
const mldsa = std.crypto.sign.mldsa;
const Shake256 = std.crypto.hash.sha3.Shake256;
const Io = std.Io;

const Handshake = struct {
    implementation: []const u8,
    functions: []const []const u8,
};

const Request = struct {
    function: []const u8,
    inputs: json.ObjectMap,
    params: json.ObjectMap,
};

const Response = struct {
    outputs: ?json.ObjectMap = null,
    error_msg: ?[]const u8 = null,
    unsupported: ?bool = null,

    pub fn jsonStringify(self: *const Response, jw: *json.Stringify) !void {
        try jw.beginObject();
        if (self.outputs) |outputs| {
            try jw.objectField("outputs");
            try jw.beginObject();
            var it = outputs.iterator();
            while (it.next()) |entry| {
                try jw.objectField(entry.key_ptr.*);
                try jw.write(entry.value_ptr.*.string);
            }
            try jw.endObject();
        }
        if (self.error_msg) |msg| {
            try jw.objectField("error");
            try jw.write(msg);
        }
        if (self.unsupported) |u| {
            if (u) {
                try jw.objectField("unsupported");
                try jw.write(true);
            }
        }
        try jw.endObject();
    }
};

fn getInputHex(inputs: json.ObjectMap, key: []const u8) ![]const u8 {
    const val = inputs.get(key) orelse return error.MissingInput;
    return switch (val) {
        .string => |s| if (s.len % 2 == 0) s else error.InvalidInput,
        else => error.InvalidInput,
    };
}

fn getInputBytes(inputs: json.ObjectMap, key: []const u8, buf: []u8) ![]u8 {
    const hex_str = try getInputHex(inputs, key);
    if (hex_str.len / 2 > buf.len) return error.InvalidInput;
    return fmt.hexToBytes(buf[0 .. hex_str.len / 2], hex_str) catch return error.InvalidInput;
}

fn getInputBytesAlloc(allocator: std.mem.Allocator, inputs: json.ObjectMap, key: []const u8) ![]u8 {
    const hex_str = try getInputHex(inputs, key);
    const out = try allocator.alloc(u8, hex_str.len / 2);
    return fmt.hexToBytes(out, hex_str) catch return error.InvalidInput;
}

fn getParamInt(params: json.ObjectMap, key: []const u8) ?i64 {
    const val = params.get(key) orelse return null;
    return switch (val) {
        .integer => |i| i,
        else => null,
    };
}

fn hexEncodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{x}", .{bytes});
}

fn makeOutputs(allocator: std.mem.Allocator, kvs: anytype) !json.ObjectMap {
    var map = json.ObjectMap.init(allocator);
    inline for (kvs) |kv| {
        try map.put(kv[0], .{ .string = kv[1] });
    }
    return map;
}

fn errResponse(msg: []const u8) Response {
    return .{ .error_msg = msg };
}

fn handleKemKeyGen(allocator: std.mem.Allocator, req: Request) !Response {
    var seed_buf: [64]u8 = undefined;
    const randomness = getInputBytes(req.inputs, "randomness", &seed_buf) catch
        return errResponse("missing or invalid 'randomness'");
    if (randomness.len != 64)
        return errResponse("randomness must be 64 bytes");

    const param_set = getParamInt(req.params, "param_set") orelse
        return errResponse("missing param_set");

    switch (param_set) {
        inline 512, 768, 1024 => |ps| {
            const Kem = switch (ps) {
                512 => ml_kem.MLKem512,
                768 => ml_kem.MLKem768,
                1024 => ml_kem.MLKem1024,
                else => unreachable,
            };
            const kp = Kem.KeyPair.generateDeterministic(seed_buf) catch
                return errResponse("key generation failed");
            const ek_bytes = kp.public_key.toBytes();
            const dk_bytes = kp.secret_key.toBytes();
            return .{ .outputs = try makeOutputs(allocator, .{
                .{ "ek", try hexEncodeAlloc(allocator, &ek_bytes) },
                .{ "dk", try hexEncodeAlloc(allocator, &dk_bytes) },
            }) };
        },
        else => return errResponse("unsupported param_set"),
    }
}

fn handleKemEncaps(allocator: std.mem.Allocator, req: Request) !Response {
    var ek_buf: [ml_kem.MLKem1024.PublicKey.encoded_length]u8 = undefined;
    const ek_bytes = getInputBytes(req.inputs, "ek", &ek_buf) catch
        return errResponse("missing or invalid 'ek'");
    var rand_buf: [32]u8 = undefined;
    const randomness = getInputBytes(req.inputs, "randomness", &rand_buf) catch
        return errResponse("missing or invalid 'randomness'");
    if (randomness.len != 32)
        return errResponse("randomness must be 32 bytes");

    switch (ek_bytes.len) {
        inline ml_kem.MLKem512.PublicKey.encoded_length,
        ml_kem.MLKem768.PublicKey.encoded_length,
        ml_kem.MLKem1024.PublicKey.encoded_length,
        => |ek_len| {
            const Kem = switch (ek_len) {
                ml_kem.MLKem512.PublicKey.encoded_length => ml_kem.MLKem512,
                ml_kem.MLKem768.PublicKey.encoded_length => ml_kem.MLKem768,
                ml_kem.MLKem1024.PublicKey.encoded_length => ml_kem.MLKem1024,
                else => unreachable,
            };
            const pk = Kem.PublicKey.fromBytes(ek_buf[0..ek_len]) catch
                return errResponse("invalid encapsulation key");
            const result = pk.encapsDeterministic(&rand_buf);
            return .{ .outputs = try makeOutputs(allocator, .{
                .{ "c", try hexEncodeAlloc(allocator, &result.ciphertext) },
                .{ "K", try hexEncodeAlloc(allocator, &result.shared_secret) },
            }) };
        },
        else => return errResponse("invalid ek length"),
    }
}

fn handleKemDecaps(allocator: std.mem.Allocator, req: Request) !Response {
    var dk_buf: [ml_kem.MLKem1024.SecretKey.encoded_length]u8 = undefined;
    const dk_bytes = getInputBytes(req.inputs, "dk", &dk_buf) catch
        return errResponse("missing or invalid 'dk'");
    var ct_buf: [ml_kem.MLKem1024.ciphertext_length]u8 = undefined;
    const ct_bytes = getInputBytes(req.inputs, "c", &ct_buf) catch
        return errResponse("missing or invalid 'c'");

    switch (dk_bytes.len) {
        inline ml_kem.MLKem512.SecretKey.encoded_length,
        ml_kem.MLKem768.SecretKey.encoded_length,
        ml_kem.MLKem1024.SecretKey.encoded_length,
        => |dk_len| {
            const Kem = switch (dk_len) {
                ml_kem.MLKem512.SecretKey.encoded_length => ml_kem.MLKem512,
                ml_kem.MLKem768.SecretKey.encoded_length => ml_kem.MLKem768,
                ml_kem.MLKem1024.SecretKey.encoded_length => ml_kem.MLKem1024,
                else => unreachable,
            };
            if (ct_bytes.len != Kem.ciphertext_length)
                return errResponse("invalid ciphertext length");
            const sk = Kem.SecretKey.fromBytes(dk_buf[0..dk_len]) catch
                return errResponse("invalid decapsulation key");
            const ss = sk.decaps(ct_buf[0..Kem.ciphertext_length]) catch
                return errResponse("decapsulation failed");
            return .{ .outputs = try makeOutputs(allocator, .{
                .{ "K", try hexEncodeAlloc(allocator, &ss) },
            }) };
        },
        else => return errResponse("invalid dk length"),
    }
}

fn handleDsaKeyGen(allocator: std.mem.Allocator, req: Request) !Response {
    var seed_buf: [32]u8 = undefined;
    const seed = getInputBytes(req.inputs, "seed", &seed_buf) catch
        return errResponse("missing or invalid 'seed'");
    if (seed.len != 32)
        return errResponse("seed must be 32 bytes");

    const param_set = getParamInt(req.params, "param_set") orelse
        return errResponse("missing param_set");

    switch (param_set) {
        inline 44, 65, 87 => |ps| {
            const Dsa = switch (ps) {
                44 => mldsa.MLDSA44,
                65 => mldsa.MLDSA65,
                87 => mldsa.MLDSA87,
                else => unreachable,
            };
            const kp = Dsa.KeyPair.generateDeterministic(seed_buf) catch
                return errResponse("key generation failed");
            const pk_bytes = kp.public_key.toBytes();
            const sk_bytes = kp.secret_key.toBytes();
            return .{ .outputs = try makeOutputs(allocator, .{
                .{ "pk", try hexEncodeAlloc(allocator, &pk_bytes) },
                .{ "sk", try hexEncodeAlloc(allocator, &sk_bytes) },
            }) };
        },
        else => return errResponse("unsupported param_set"),
    }
}

fn signInternal(comptime Dsa: type, sk: *const Dsa.SecretKey, rnd: [Dsa.noise_length]u8) Dsa.Signer {
    var h = Shake256.init(.{});
    h.update(&sk.tr);
    return .{ .h = h, .secret_key = sk, .rnd = rnd };
}

fn verifyInternal(comptime Dsa: type, sig: Dsa.Signature, pk: Dsa.PublicKey) Dsa.Verifier {
    var h = Shake256.init(.{});
    h.update(&pk.tr);
    return .{ .h = h, .signature = sig, .public_key = pk };
}

fn handleDsaSign(allocator: std.mem.Allocator, req: Request) !Response {
    const sk_bytes = getInputBytesAlloc(allocator, req.inputs, "sk") catch
        return errResponse("missing or invalid 'sk'");
    const message = getInputBytesAlloc(allocator, req.inputs, "message") catch
        return errResponse("missing or invalid 'message'");
    var rnd_buf: [32]u8 = undefined;
    const rnd = getInputBytes(req.inputs, "rnd", &rnd_buf) catch
        return errResponse("missing or invalid 'rnd'");
    if (rnd.len != 32)
        return errResponse("rnd must be 32 bytes");

    const param_set = getParamInt(req.params, "param_set");
    const ps = param_set orelse blk: {
        break :blk switch (sk_bytes.len) {
            mldsa.MLDSA44.private_key_bytes => @as(i64, 44),
            mldsa.MLDSA65.private_key_bytes => 65,
            mldsa.MLDSA87.private_key_bytes => 87,
            else => return errResponse("cannot infer param_set from sk length"),
        };
    };

    switch (ps) {
        inline 44, 65, 87 => |p| {
            const Dsa = switch (p) {
                44 => mldsa.MLDSA44,
                65 => mldsa.MLDSA65,
                87 => mldsa.MLDSA87,
                else => unreachable,
            };
            if (sk_bytes.len != Dsa.SecretKey.encoded_length)
                return errResponse("invalid sk length");
            const sk = Dsa.SecretKey.fromBytes(sk_bytes[0..Dsa.SecretKey.encoded_length].*) catch
                return errResponse("invalid secret key");
            var signer = signInternal(Dsa, &sk, rnd_buf);
            signer.update(message);
            const sig = signer.finalize();
            const sig_bytes = sig.toBytes();
            return .{ .outputs = try makeOutputs(allocator, .{
                .{ "signature", try hexEncodeAlloc(allocator, &sig_bytes) },
            }) };
        },
        else => return errResponse("unsupported param_set"),
    }
}

fn handleDsaVerify(allocator: std.mem.Allocator, req: Request) !Response {
    const pk_bytes = getInputBytesAlloc(allocator, req.inputs, "pk") catch
        return errResponse("missing or invalid 'pk'");
    const message = getInputBytesAlloc(allocator, req.inputs, "message") catch
        return errResponse("missing or invalid 'message'");
    const sig_bytes = getInputBytesAlloc(allocator, req.inputs, "sigma") catch
        return errResponse("missing or invalid 'sigma'");

    const param_set = getParamInt(req.params, "param_set");
    const ps = param_set orelse blk: {
        break :blk switch (pk_bytes.len) {
            mldsa.MLDSA44.public_key_bytes => @as(i64, 44),
            mldsa.MLDSA65.public_key_bytes => 65,
            mldsa.MLDSA87.public_key_bytes => 87,
            else => return errResponse("cannot infer param_set from pk length"),
        };
    };

    switch (ps) {
        inline 44, 65, 87 => |p| {
            const Dsa = switch (p) {
                44 => mldsa.MLDSA44,
                65 => mldsa.MLDSA65,
                87 => mldsa.MLDSA87,
                else => unreachable,
            };
            if (pk_bytes.len != Dsa.PublicKey.encoded_length)
                return errResponse("invalid pk length");
            if (sig_bytes.len != Dsa.Signature.encoded_length)
                return errResponse("invalid signature length");
            const pk = Dsa.PublicKey.fromBytes(pk_bytes[0..Dsa.PublicKey.encoded_length].*) catch
                return errResponse("invalid public key");
            const sig = Dsa.Signature.fromBytes(sig_bytes[0..Dsa.Signature.encoded_length].*) catch {
                return .{ .outputs = try makeOutputs(allocator, .{
                    .{ "valid", "00" },
                }) };
            };
            var verifier = verifyInternal(Dsa, sig, pk);
            verifier.update(message);
            verifier.verify() catch {
                return .{ .outputs = try makeOutputs(allocator, .{
                    .{ "valid", "00" },
                }) };
            };
            return .{ .outputs = try makeOutputs(allocator, .{
                .{ "valid", "01" },
            }) };
        },
        else => return errResponse("unsupported param_set"),
    }
}

fn handleRequest(allocator: std.mem.Allocator, req: Request) !Response {
    const function = req.function;
    if (std.mem.eql(u8, function, "ML_KEM_KeyGen")) return handleKemKeyGen(allocator, req);
    if (std.mem.eql(u8, function, "ML_KEM_Encaps")) return handleKemEncaps(allocator, req);
    if (std.mem.eql(u8, function, "ML_KEM_Decaps")) return handleKemDecaps(allocator, req);
    if (std.mem.eql(u8, function, "ML_DSA_KeyGen")) return handleDsaKeyGen(allocator, req);
    if (std.mem.eql(u8, function, "ML_DSA_Sign")) return handleDsaSign(allocator, req);
    if (std.mem.eql(u8, function, "ML_DSA_Verify")) return handleDsaVerify(allocator, req);
    return .{ .unsupported = true };
}

fn writeResponse(stdout: *Io.Writer, resp: Response) !void {
    try json.Stringify.value(resp, .{
        .emit_null_optional_fields = false,
    }, stdout);
    try stdout.writeAll("\n");
    try stdout.flush();
}

fn getObjectField(obj: json.ObjectMap, key: []const u8, allocator: std.mem.Allocator) json.ObjectMap {
    const val = obj.get(key) orelse return json.ObjectMap.init(allocator);
    return switch (val) {
        .object => |o| o,
        else => json.ObjectMap.init(allocator),
    };
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var per_request_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);

    var stdout_buffer: [1024 * 64]u8 = undefined;
    var stdout_file: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file.interface;

    var stdin_buffer: [1024 * 1024]u8 = undefined;
    var stdin_file: Io.File.Reader = .initStreaming(.stdin(), io, &stdin_buffer);
    const stdin = &stdin_file.interface;

    const handshake = Handshake{
        .implementation = "zig-stdlib",
        .functions = &.{
            "ML_KEM_KeyGen",
            "ML_KEM_Encaps",
            "ML_KEM_Decaps",
            "ML_DSA_KeyGen",
            "ML_DSA_Sign",
            "ML_DSA_Verify",
        },
    };
    try json.Stringify.value(handshake, .{}, stdout);
    try stdout.writeAll("\n");
    try stdout.flush();

    while (true) {
        _ = per_request_arena.reset(.retain_capacity);
        const arena = per_request_arena.allocator();

        const line = stdin.takeDelimiter('\n') catch |err| switch (err) {
            error.ReadFailed => break,
            else => return err,
        };
        const line_str = line orelse break;
        if (line_str.len == 0) break;

        var parsed = json.parseFromSlice(json.Value, arena, line_str, .{
            .ignore_unknown_fields = true,
        }) catch {
            try writeResponse(stdout, errResponse("invalid JSON"));
            continue;
        };
        defer parsed.deinit();

        const obj = parsed.value.object;
        const function = if (obj.get("function")) |v| switch (v) {
            .string => |s| s,
            else => {
                try writeResponse(stdout, errResponse("invalid function field"));
                continue;
            },
        } else {
            try writeResponse(stdout, errResponse("missing function field"));
            continue;
        };

        const req = Request{
            .function = function,
            .inputs = getObjectField(obj, "inputs", arena),
            .params = getObjectField(obj, "params", arena),
        };

        const resp = handleRequest(arena, req) catch {
            try writeResponse(stdout, errResponse("internal error"));
            continue;
        };
        try writeResponse(stdout, resp);
    }
}
