package io.paymos.wallet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.zip.GZIPInputStream;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.jna.Function;
import com.sun.jna.Memory;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Pointer;

/**
 * The SDK's half of the 2-of-2 co-sign, over the same Rust core the Python SDK embeds and the
 * .NET server calls. Nobody reimplements FROST: this is a JSON op in, a JSON op out, and the
 * bytes signed here are the bytes those two would sign.
 *
 * <p>Only two operations run client-side in production: commit (round one, per movement source)
 * and sign (round two, one share per signing package). build_signing_package and aggregate are
 * server-side operations and are deliberately absent from the public surface.
 *
 * <p>The binary comes from three places, in this order:
 *   1. {@code PAYMOS_NATIVE_LIB} — a full path to a local binary. The offline escape hatch.
 *   2. The per-user cache, where a previous run already left a verified binary.
 *   3. The paymos-wallet-core GitHub release — downloaded, SHA-256-checked against the release's
 *      checksum file, then cached. A mismatch refuses: a substituted binary never crosses the
 *      FFI boundary.
 * Whatever the source, the loaded binary must self-report the version this SDK is pinned to
 * (fail-closed), and only then do its exports serve calls.
 */
public final class NativeCore {
    /** The paymos-wallet-core release this SDK build is pinned to. Bump when the core releases. */
    public static final String CORE_VERSION = "0.1.0";

    private static final String RELEASE_BASE =
        "https://github.com/paymos-labs/paymos-wallet-core/releases/download";

    private static Function mpcCall;
    private static Function mpcFree;

    private NativeCore() {}

    /** Round one for one signing session. Returns [commitments, nonces]; keep nonces private. */
    public static JsonObject[] commit(JsonObject keyPackage) {
        JsonObject req = new JsonObject();
        req.addProperty("op", "commit");
        req.add("key_package", keyPackage);
        JsonObject r = callOp(req);
        return new JsonObject[] { r.getAsJsonObject("commitments"), r.getAsJsonObject("nonces") };
    }

    /** Round two: this side's signature share, which the server aggregates with its own. */
    public static JsonObject sign(JsonObject signingPackage, JsonObject nonces, JsonObject keyPackage) {
        JsonObject req = new JsonObject();
        req.addProperty("op", "sign");
        req.add("signing_package", signingPackage);
        req.add("nonces", nonces);
        req.add("key_package", keyPackage);
        return callOp(req).getAsJsonObject("signature_share");
    }

    /** The loaded core's self-reported version. */
    public static String version() {
        JsonObject req = new JsonObject();
        req.addProperty("op", "version");
        return callOp(req).get("version").getAsString();
    }

    /** Run one JSON op against the core; unwraps the {ok, …} envelope. Package-private on purpose. */
    static synchronized JsonObject callOp(JsonObject request) {
        ensureCore();
        byte[] reqBytes = request.toString().getBytes(StandardCharsets.UTF_8);
        Memory req = new Memory(reqBytes.length);
        req.write(0, reqBytes, 0, reqBytes.length);
        Memory outLen = new Memory(8);
        Pointer outPtr = (Pointer) mpcCall.invoke(Pointer.class, new Object[] { req, (long) reqBytes.length, outLen });
        try {
            if (outPtr == null) throw new PaymosException("mpc call returned nothing");
            long len = outLen.getLong(0);
            String raw = new String(outPtr.getByteArray(0, (int) len), StandardCharsets.UTF_8);
            JsonObject resp = JsonParser.parseString(raw).getAsJsonObject();
            if (!resp.has("ok") || !resp.get("ok").getAsBoolean()) {
                String msg = resp.has("error") && resp.get("error").isJsonPrimitive()
                    ? resp.get("error").getAsString() : "mpc call failed";
                throw new PaymosException(msg);
            }
            return resp;
        } finally {
            if (outPtr != null) mpcFree.invoke(new Object[] { outPtr, outLen.getLong(0) });
        }
    }

    private static void ensureCore() {
        if (mpcCall != null) return;
        Path path = resolvePath();
        NativeLibrary lib = NativeLibrary.getInstance(path.toString());
        Function call = lib.getFunction("mpc_call");
        Function free = lib.getFunction("mpc_free");

        // The version check goes through the freshly resolved exports — the core answers for
        // itself before those exports serve anyone.
        byte[] reqBytes = "{\"op\":\"version\"}".getBytes(StandardCharsets.UTF_8);
        Memory req = new Memory(reqBytes.length);
        req.write(0, reqBytes, 0, reqBytes.length);
        Memory outLen = new Memory(8);
        Pointer outPtr = (Pointer) call.invoke(Pointer.class, new Object[] { req, (long) reqBytes.length, outLen });
        String reported = "";
        try {
            if (outPtr != null) {
                String raw = new String(outPtr.getByteArray(0, (int) outLen.getLong(0)), StandardCharsets.UTF_8);
                JsonObject resp = JsonParser.parseString(raw).getAsJsonObject();
                if (resp.has("version")) reported = resp.get("version").getAsString();
            }
        } finally {
            if (outPtr != null) free.invoke(new Object[] { outPtr, outLen.getLong(0) });
        }
        if (reported.isEmpty())
            throw new PaymosException("the loaded co-signing core does not report a version — too old for this SDK");
        if (!reported.equals(CORE_VERSION))
            throw new PaymosException(
                "co-signing core version mismatch: " + path + " reports v" + reported
                    + ", this SDK is pinned to v" + CORE_VERSION + ". "
                    + "Set PAYMOS_NATIVE_LIB to a matching build or clear the paymos native cache.");

        mpcCall = call;
        mpcFree = free;
    }

    // ── where the binary comes from ──────────────────────────────────────────

    private static Path resolvePath() {
        String rid = currentRid();
        // The env var is the documented override; the system property is the JVM-native spelling
        // of the same thing (and the only one a test can set inside the process).
        String override = System.getenv("PAYMOS_NATIVE_LIB");
        if (override == null || override.isEmpty()) override = System.getProperty("paymos.native.lib");
        if (override != null && !override.isEmpty()) {
            Path p = Paths.get(override);
            if (!Files.exists(p))
                throw new PaymosException("PAYMOS_NATIVE_LIB points at a missing file: " + override);
            return p;
        }

        Path cacheDir = cacheRoot().resolve("v" + CORE_VERSION).resolve(rid);
        Path cached = cacheDir.resolve(libName(rid));
        if (Files.exists(cached)) return cached;

        String archiveName = "paymos-wallet-native-v" + CORE_VERSION + "-" + rid + ".tar.gz";
        byte[] archive = download(RELEASE_BASE + "/v" + CORE_VERSION + "/" + archiveName);
        String checksum = new String(
            download(RELEASE_BASE + "/v" + CORE_VERSION + "/" + archiveName + ".sha256"), StandardCharsets.UTF_8);
        verifySha256(archive, checksum, archiveName);
        extractSingleFileTarGz(archive, cached);
        return cached;
    }

    private static String currentRid() {
        String osName = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        String os;
        if (osName.contains("win")) os = "win";
        else if (osName.contains("mac")) os = "osx";
        else if (osName.contains("linux")) os = "linux";
        else
            throw new PaymosException(
                "unsupported OS: " + osName + ". Supported: linux/macos/windows on x64 and arm64");

        String archName = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
        String arch;
        if (archName.equals("amd64") || archName.equals("x86_64")) arch = "x64";
        else if (archName.equals("aarch64")) arch = "arm64";
        else
            throw new PaymosException(
                "unsupported CPU architecture: " + archName + ". Supported: x64, arm64");
        return os + "-" + arch;
    }

    private static String libName(String rid) {
        if (rid.startsWith("win")) return "wallet_mpc.dll";
        if (rid.startsWith("osx")) return "libwallet_mpc.dylib";
        return "libwallet_mpc.so";
    }

    private static Path cacheRoot() {
        String base;
        String osName = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        if (osName.contains("win")) base = System.getenv("LOCALAPPDATA");
        else if (osName.contains("mac"))
            base = Paths.get(System.getProperty("user.home"), "Library", "Caches").toString();
        else {
            base = System.getenv("XDG_CACHE_HOME");
            if (base == null) base = Paths.get(System.getProperty("user.home"), ".cache").toString();
        }
        if (base == null || base.isEmpty())
            throw new PaymosException("cannot locate a user cache directory");
        return Paths.get(base, "paymos", "native");
    }

    private static byte[] download(String url) {
        try {
            HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL) // GitHub releases redirect to a CDN
                .build();
            HttpResponse<byte[]> resp = client.send(
                HttpRequest.newBuilder(URI.create(url)).build(), HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() != 200)
                throw new PaymosException(
                    "failed to download the co-signing core: " + url + " answered " + resp.statusCode() + ". "
                        + "Set PAYMOS_NATIVE_LIB to a local libwallet_mpc build to run offline");
            return resp.body();
        } catch (PaymosException e) {
            throw e;
        } catch (IOException e) {
            throw new PaymosException(
                "failed to download the co-signing core: " + e.getMessage() + ". "
                    + "Set PAYMOS_NATIVE_LIB to a local libwallet_mpc build to run offline");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PaymosException("failed to download the co-signing core: interrupted");
        }
    }

    private static void verifySha256(byte[] payload, String checksumText, String archiveName) {
        // Format produced by `sha256sum`: "<hex>  <name>".
        String[] fields = checksumText.trim().split("\\s+");
        if (fields.length == 0 || fields[0].isEmpty())
            throw new PaymosException("empty checksum file for the co-signing core download");
        String expected = fields[0].toLowerCase(Locale.ROOT);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest)
                sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            if (!sb.toString().equals(expected))
                throw new PaymosException(
                    "SHA-256 mismatch for " + archiveName + ": expected " + expected + ", got " + sb + ". "
                        + "The download was refused and nothing was loaded.");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 missing from this JVM", e);
        }
    }

    // Minimal tar reader for our own single-file archives (ustar, type '0'), over GZIP.
    private static void extractSingleFileTarGz(byte[] archive, Path destination) {
        byte[] tar;
        try (InputStream gz = new GZIPInputStream(new java.io.ByteArrayInputStream(archive));
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            gz.transferTo(out);
            tar = out.toByteArray();
        } catch (IOException e) {
            throw new PaymosException("the downloaded core archive is not gzip: " + e.getMessage());
        }

        int offset = 0;
        while (offset + 512 <= tar.length) {
            if (isZeroBlock(tar, offset)) break;
            int size = (int) readOctal(tar, offset + 124, 12);
            char type = (char) tar[offset + 156];
            if (type == '0' || type == '\0') {
                try {
                    Files.createDirectories(destination.getParent());
                    Path tmp = destination.resolveSibling(destination.getFileName() + ".tmp");
                    Files.write(tmp, java.util.Arrays.copyOfRange(tar, offset + 512, offset + 512 + size));
                    Files.move(tmp, destination, StandardCopyOption.REPLACE_EXISTING);
                    destination.toFile().setExecutable(true);
                    return;
                } catch (IOException e) {
                    throw new PaymosException("cannot install the co-signing core: " + e.getMessage());
                }
            }
            offset += 512 + ((size + 511) / 512) * 512;
        }
        throw new PaymosException("the downloaded core archive carried no file — refusing to install it");
    }

    private static boolean isZeroBlock(byte[] b, int offset) {
        for (int i = 0; i < 512; i++)
            if (b[offset + i] != 0) return false;
        return true;
    }

    private static long readOctal(byte[] b, int offset, int len) {
        long value = 0;
        for (int i = 0; i < len; i++) {
            int c = b[offset + i];
            if (c < '0' || c > '7') break;
            value = value * 8 + (c - '0');
        }
        return value;
    }
}
