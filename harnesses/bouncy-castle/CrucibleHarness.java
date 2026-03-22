import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.*;
import org.bouncycastle.pqc.crypto.mldsa.*;

/**
 * Crucible test harness for Bouncy Castle ML-KEM and ML-DSA implementations.
 *
 * Protocol:
 *   - Startup: print JSON handshake line to stdout
 *   - Read JSON request lines from stdin, write JSON response lines to stdout
 *   - All byte data is hex-encoded
 */
public class CrucibleHarness {

    private static final SecureRandom RNG = new SecureRandom();

    public static void main(String[] args) {
        // Force stdout to be unbuffered line-by-line.
        PrintStream out = new PrintStream(System.out, true);

        // Send handshake.
        out.println("{\"implementation\":\"bouncy-castle-1.80\"," +
            "\"functions\":[" +
            "\"ML_KEM_KeyGen\"," +
            "\"ML_KEM_Encaps\"," +
            "\"ML_KEM_Decaps\"," +
            "\"ML_DSA_KeyGen\"," +
            "\"ML_DSA_Sign\"," +
            "\"ML_DSA_Verify\"" +
            "]}");

        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) break;

                try {
                    Map<String, Object> req = parseJson(line);
                    String function = (String) req.get("function");
                    @SuppressWarnings("unchecked")
                    Map<String, String> inputs = (Map<String, String>) req.getOrDefault("inputs", new LinkedHashMap<>());
                    @SuppressWarnings("unchecked")
                    Map<String, Object> params = (Map<String, Object>) req.getOrDefault("params", new LinkedHashMap<>());

                    String response = handleRequest(function, inputs, params);
                    out.println(response);
                } catch (Exception e) {
                    out.println(errorJson("request processing error: " + e.getMessage()));
                }
            }
        } catch (Exception e) {
            // Fatal error reading stdin.
            System.err.println("Fatal: " + e.getMessage());
            System.exit(1);
        }
    }

    private static String handleRequest(String function, Map<String, String> inputs, Map<String, Object> params) {
        try {
            switch (function) {
                case "ML_KEM_KeyGen":
                    return handleMLKEMKeyGen(inputs, params);
                case "ML_KEM_Encaps":
                    return handleMLKEMEncaps(inputs, params);
                case "ML_KEM_Decaps":
                    return handleMLKEMDecaps(inputs, params);
                case "ML_DSA_KeyGen":
                    return handleMLDSAKeyGen(inputs, params);
                case "ML_DSA_Sign":
                    return handleMLDSASign(inputs, params);
                case "ML_DSA_Verify":
                    return handleMLDSAVerify(inputs, params);
                default:
                    return "{\"unsupported\":true}";
            }
        } catch (Exception e) {
            return errorJson(function + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    // ---- ML-KEM ----

    private static MLKEMParameters getMLKEMParams(Map<String, Object> params) {
        int paramSet = getParamInt(params, "param_set", 768);
        switch (paramSet) {
            case 512: return MLKEMParameters.ml_kem_512;
            case 768: return MLKEMParameters.ml_kem_768;
            case 1024: return MLKEMParameters.ml_kem_1024;
            default: throw new IllegalArgumentException("unsupported ML-KEM param_set: " + paramSet);
        }
    }

    private static MLKEMParameters guessMLKEMParamsFromEkLength(int ekLen) {
        // ML-KEM encapsulation key sizes: 512->800, 768->1184, 1024->1568
        switch (ekLen) {
            case 800: return MLKEMParameters.ml_kem_512;
            case 1184: return MLKEMParameters.ml_kem_768;
            case 1568: return MLKEMParameters.ml_kem_1024;
            default: return null;
        }
    }

    private static MLKEMParameters guessMLKEMParamsFromDkLength(int dkLen) {
        // ML-KEM decapsulation key sizes: 512->1632, 768->2400, 1024->3168
        switch (dkLen) {
            case 1632: return MLKEMParameters.ml_kem_512;
            case 2400: return MLKEMParameters.ml_kem_768;
            case 3168: return MLKEMParameters.ml_kem_1024;
            default: return null;
        }
    }

    private static String handleMLKEMKeyGen(Map<String, String> inputs, Map<String, Object> params) {
        MLKEMParameters mlkemParams = getMLKEMParams(params);

        MLKEMKeyPairGenerator gen = new MLKEMKeyPairGenerator();
        gen.init(new MLKEMKeyGenerationParameters(RNG, mlkemParams));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        MLKEMPublicKeyParameters pub = (MLKEMPublicKeyParameters) kp.getPublic();
        MLKEMPrivateKeyParameters priv = (MLKEMPrivateKeyParameters) kp.getPrivate();

        byte[] ek = pub.getEncoded();
        byte[] dk = priv.getEncoded();

        Map<String, String> outputs = new LinkedHashMap<>();
        outputs.put("ek", bytesToHex(ek));
        outputs.put("dk", bytesToHex(dk));
        return outputsJson(outputs);
    }

    private static String handleMLKEMEncaps(Map<String, String> inputs, Map<String, Object> params) {
        byte[] ekBytes = hexToBytes(requireInput(inputs, "ek"));

        // Determine parameter set from key length or params.
        MLKEMParameters mlkemParams = guessMLKEMParamsFromEkLength(ekBytes.length);
        if (mlkemParams == null) {
            mlkemParams = getMLKEMParams(params);
        }

        MLKEMPublicKeyParameters pubKey = new MLKEMPublicKeyParameters(mlkemParams, ekBytes);

        MLKEMGenerator generator = new MLKEMGenerator(RNG);
        SecretWithEncapsulation enc = generator.generateEncapsulated(pubKey);

        byte[] ct = enc.getEncapsulation();
        byte[] ss = enc.getSecret();

        Map<String, String> outputs = new LinkedHashMap<>();
        outputs.put("c", bytesToHex(ct));
        outputs.put("K", bytesToHex(ss));
        return outputsJson(outputs);
    }

    private static String handleMLKEMDecaps(Map<String, String> inputs, Map<String, Object> params) {
        byte[] cBytes = hexToBytes(requireInput(inputs, "c"));
        byte[] dkBytes = hexToBytes(requireInput(inputs, "dk"));

        // Determine parameter set from dk length or params.
        MLKEMParameters mlkemParams = guessMLKEMParamsFromDkLength(dkBytes.length);
        if (mlkemParams == null) {
            mlkemParams = getMLKEMParams(params);
        }

        MLKEMPrivateKeyParameters privKey = new MLKEMPrivateKeyParameters(mlkemParams, dkBytes);

        MLKEMExtractor extractor = new MLKEMExtractor(privKey);
        byte[] ss = extractor.extractSecret(cBytes);

        Map<String, String> outputs = new LinkedHashMap<>();
        outputs.put("K", bytesToHex(ss));
        return outputsJson(outputs);
    }

    // ---- ML-DSA ----

    private static MLDSAParameters getMLDSAParams(Map<String, Object> params) {
        int paramSet = getParamInt(params, "param_set", 65);
        switch (paramSet) {
            case 44: return MLDSAParameters.ml_dsa_44;
            case 65: return MLDSAParameters.ml_dsa_65;
            case 87: return MLDSAParameters.ml_dsa_87;
            default: throw new IllegalArgumentException("unsupported ML-DSA param_set: " + paramSet);
        }
    }

    private static MLDSAParameters guessMLDSAParamsFromPkLength(int pkLen) {
        // ML-DSA public key sizes: 44->1312, 65->1952, 87->2592
        switch (pkLen) {
            case 1312: return MLDSAParameters.ml_dsa_44;
            case 1952: return MLDSAParameters.ml_dsa_65;
            case 2592: return MLDSAParameters.ml_dsa_87;
            default: return null;
        }
    }

    private static MLDSAParameters guessMLDSAParamsFromSkLength(int skLen) {
        // ML-DSA secret key sizes: 44->2560, 65->4032, 87->4896
        switch (skLen) {
            case 2560: return MLDSAParameters.ml_dsa_44;
            case 4032: return MLDSAParameters.ml_dsa_65;
            case 4896: return MLDSAParameters.ml_dsa_87;
            default: return null;
        }
    }

    private static String handleMLDSAKeyGen(Map<String, String> inputs, Map<String, Object> params) {
        MLDSAParameters mldsaParams = getMLDSAParams(params);

        MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
        gen.init(new MLDSAKeyGenerationParameters(RNG, mldsaParams));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        MLDSAPublicKeyParameters pub = (MLDSAPublicKeyParameters) kp.getPublic();
        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters) kp.getPrivate();

        byte[] pk = pub.getEncoded();
        byte[] sk = priv.getEncoded();

        Map<String, String> outputs = new LinkedHashMap<>();
        outputs.put("pk", bytesToHex(pk));
        outputs.put("sk", bytesToHex(sk));
        return outputsJson(outputs);
    }

    private static String handleMLDSASign(Map<String, String> inputs, Map<String, Object> params) {
        byte[] skBytes = hexToBytes(requireInput(inputs, "sk"));
        byte[] message = hexToBytes(requireInput(inputs, "message"));

        // Determine parameter set from sk length or params.
        MLDSAParameters mldsaParams = guessMLDSAParamsFromSkLength(skBytes.length);
        if (mldsaParams == null) {
            mldsaParams = getMLDSAParams(params);
        }

        MLDSAPrivateKeyParameters privKey = new MLDSAPrivateKeyParameters(mldsaParams, skBytes);

        MLDSASigner signer = new MLDSASigner();
        signer.init(true, privKey);
        signer.update(message, 0, message.length);
        byte[] sig;
        try {
            sig = signer.generateSignature();
        } catch (Exception e) {
            throw new RuntimeException("signing failed: " + e.getMessage(), e);
        }

        Map<String, String> outputs = new LinkedHashMap<>();
        outputs.put("signature", bytesToHex(sig));
        return outputsJson(outputs);
    }

    private static String handleMLDSAVerify(Map<String, String> inputs, Map<String, Object> params) {
        byte[] pkBytes = hexToBytes(requireInput(inputs, "pk"));
        byte[] message = hexToBytes(requireInput(inputs, "message"));
        byte[] sigBytes = hexToBytes(requireInput(inputs, "signature"));

        // Determine parameter set from pk length or params.
        MLDSAParameters mldsaParams = guessMLDSAParamsFromPkLength(pkBytes.length);
        if (mldsaParams == null) {
            mldsaParams = getMLDSAParams(params);
        }

        MLDSAPublicKeyParameters pubKey = new MLDSAPublicKeyParameters(mldsaParams, pkBytes);

        MLDSASigner signer = new MLDSASigner();
        signer.init(false, pubKey);
        signer.update(message, 0, message.length);
        boolean valid = signer.verifySignature(sigBytes);

        Map<String, String> outputs = new LinkedHashMap<>();
        outputs.put("valid", valid ? "true" : "false");
        return outputsJson(outputs);
    }

    // ---- Minimal JSON helpers (no external deps) ----

    private static String requireInput(Map<String, String> inputs, String key) {
        String val = inputs.get(key);
        if (val == null) throw new IllegalArgumentException("missing input: " + key);
        return val;
    }

    private static int getParamInt(Map<String, Object> params, String key, int defaultVal) {
        Object val = params.get(key);
        if (val == null) return defaultVal;
        if (val instanceof Number) return ((Number) val).intValue();
        return Integer.parseInt(val.toString());
    }

    private static String errorJson(String msg) {
        return "{\"error\":" + jsonString(msg) + "}";
    }

    private static String outputsJson(Map<String, String> outputs) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"outputs\":{");
        boolean first = true;
        for (Map.Entry<String, String> entry : outputs.entrySet()) {
            if (!first) sb.append(",");
            sb.append(jsonString(entry.getKey()));
            sb.append(":");
            sb.append(jsonString(entry.getValue()));
            first = false;
        }
        sb.append("}}");
        return sb.toString();
    }

    private static String jsonString(String s) {
        StringBuilder sb = new StringBuilder();
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default: sb.append(c);
            }
        }
        sb.append('"');
        return sb.toString();
    }

    // ---- Minimal JSON parser ----

    /**
     * Parse a JSON object string into a Map. Supports nested objects, strings, numbers, booleans, null.
     * This is intentionally minimal — just enough for the harness protocol.
     */
    private static Map<String, Object> parseJson(String json) {
        int[] pos = {0};
        skipWhitespace(json, pos);
        Object result = parseValue(json, pos);
        if (result instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) result;
            return map;
        }
        throw new RuntimeException("expected JSON object at top level");
    }

    private static Object parseValue(String json, int[] pos) {
        skipWhitespace(json, pos);
        if (pos[0] >= json.length()) throw new RuntimeException("unexpected end of JSON");
        char c = json.charAt(pos[0]);
        switch (c) {
            case '{': return parseObject(json, pos);
            case '[': return parseArray(json, pos);
            case '"': return parseString(json, pos);
            case 't': case 'f': return parseBoolean(json, pos);
            case 'n': return parseNull(json, pos);
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return parseNumber(json, pos);
                throw new RuntimeException("unexpected character at pos " + pos[0] + ": " + c);
        }
    }

    private static Map<String, Object> parseObject(String json, int[] pos) {
        Map<String, Object> map = new LinkedHashMap<>();
        pos[0]++; // skip '{'
        skipWhitespace(json, pos);
        if (pos[0] < json.length() && json.charAt(pos[0]) == '}') {
            pos[0]++;
            return map;
        }
        while (pos[0] < json.length()) {
            skipWhitespace(json, pos);
            String key = parseString(json, pos);
            skipWhitespace(json, pos);
            expect(json, pos, ':');
            Object value = parseValue(json, pos);
            map.put(key, value);
            skipWhitespace(json, pos);
            if (pos[0] < json.length() && json.charAt(pos[0]) == ',') {
                pos[0]++;
            } else {
                break;
            }
        }
        skipWhitespace(json, pos);
        expect(json, pos, '}');
        return map;
    }

    private static java.util.List<Object> parseArray(String json, int[] pos) {
        java.util.List<Object> list = new java.util.ArrayList<>();
        pos[0]++; // skip '['
        skipWhitespace(json, pos);
        if (pos[0] < json.length() && json.charAt(pos[0]) == ']') {
            pos[0]++;
            return list;
        }
        while (pos[0] < json.length()) {
            list.add(parseValue(json, pos));
            skipWhitespace(json, pos);
            if (pos[0] < json.length() && json.charAt(pos[0]) == ',') {
                pos[0]++;
            } else {
                break;
            }
        }
        skipWhitespace(json, pos);
        expect(json, pos, ']');
        return list;
    }

    private static String parseString(String json, int[] pos) {
        expect(json, pos, '"');
        StringBuilder sb = new StringBuilder();
        while (pos[0] < json.length()) {
            char c = json.charAt(pos[0]);
            if (c == '"') {
                pos[0]++;
                return sb.toString();
            }
            if (c == '\\') {
                pos[0]++;
                if (pos[0] >= json.length()) throw new RuntimeException("unexpected end of string escape");
                char esc = json.charAt(pos[0]);
                switch (esc) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        String hex = json.substring(pos[0] + 1, pos[0] + 5);
                        sb.append((char) Integer.parseInt(hex, 16));
                        pos[0] += 4;
                        break;
                    default: sb.append(esc);
                }
            } else {
                sb.append(c);
            }
            pos[0]++;
        }
        throw new RuntimeException("unterminated string");
    }

    private static Number parseNumber(String json, int[] pos) {
        int start = pos[0];
        boolean isFloat = false;
        if (json.charAt(pos[0]) == '-') pos[0]++;
        while (pos[0] < json.length() && json.charAt(pos[0]) >= '0' && json.charAt(pos[0]) <= '9') pos[0]++;
        if (pos[0] < json.length() && json.charAt(pos[0]) == '.') { isFloat = true; pos[0]++; }
        while (pos[0] < json.length() && json.charAt(pos[0]) >= '0' && json.charAt(pos[0]) <= '9') pos[0]++;
        if (pos[0] < json.length() && (json.charAt(pos[0]) == 'e' || json.charAt(pos[0]) == 'E')) {
            isFloat = true;
            pos[0]++;
            if (pos[0] < json.length() && (json.charAt(pos[0]) == '+' || json.charAt(pos[0]) == '-')) pos[0]++;
            while (pos[0] < json.length() && json.charAt(pos[0]) >= '0' && json.charAt(pos[0]) <= '9') pos[0]++;
        }
        String numStr = json.substring(start, pos[0]);
        if (isFloat) return Double.parseDouble(numStr);
        long val = Long.parseLong(numStr);
        if (val >= Integer.MIN_VALUE && val <= Integer.MAX_VALUE) return (int) val;
        return val;
    }

    private static Boolean parseBoolean(String json, int[] pos) {
        if (json.startsWith("true", pos[0])) { pos[0] += 4; return true; }
        if (json.startsWith("false", pos[0])) { pos[0] += 5; return false; }
        throw new RuntimeException("expected boolean at pos " + pos[0]);
    }

    private static Object parseNull(String json, int[] pos) {
        if (json.startsWith("null", pos[0])) { pos[0] += 4; return null; }
        throw new RuntimeException("expected null at pos " + pos[0]);
    }

    private static void skipWhitespace(String json, int[] pos) {
        while (pos[0] < json.length() && Character.isWhitespace(json.charAt(pos[0]))) pos[0]++;
    }

    private static void expect(String json, int[] pos, char expected) {
        if (pos[0] >= json.length() || json.charAt(pos[0]) != expected) {
            throw new RuntimeException("expected '" + expected + "' at pos " + pos[0] +
                (pos[0] < json.length() ? " but got '" + json.charAt(pos[0]) + "'" : " but got EOF"));
        }
        pos[0]++;
    }

    // ---- Hex utilities ----

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    private static String bytesToHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hex[i * 2] = HEX_CHARS[v >>> 4];
            hex[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(hex);
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
