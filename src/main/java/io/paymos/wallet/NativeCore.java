package io.paymos.wallet;

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
import java.util.Map;
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
 *   1. {@code PAYMOS_NATIVE_LIB} — a full path to a local binary. The offline escape hatch, and
 *      the operator's own choice: no hash below applies to it.
 *   2. The per-user cache, where a previous run already left a verified binary.
 *   3. The paymos-wallet-core GitHub release — downloaded, verified, then cached.
 *
 * <p>How a download and a cached file are verified depends on {@link #PINNED_CORE_SHA256}. With an
 * entry for this version and platform, that compiled-in hash is the ONLY one accepted: the
 * release's own .sha256 is not even fetched, the library extracted from the archive must hash to
 * the pin before it is written, and the cached file is re-hashed against it on every load — a
 * mismatch anywhere refuses, and nothing crosses the FFI boundary. Without an entry, the archive is
 * checked against the .sha256 published beside it in the same release, which catches a corrupted
 * download but not a replaced release, and a cached file is trusted as written.
 *
 * <p>Whatever the source, the loaded binary must self-report the version this SDK is pinned to
 * (fail-closed), and only then do its exports serve calls.
 */
public final class NativeCore {
    /** The paymos-wallet-core release this SDK build is pinned to. Bump when the core releases. */
    public static final String CORE_VERSION = "0.1.0";

    /**
     * Core version → platform ("linux-x64", "linux-arm64", "win-x64", "win-arm64", "osx-x64",
     * "osx-arm64") → the lowercase hex SHA-256 of the LIBRARY FILE inside
     * paymos-wallet-native-v&lt;version&gt;-&lt;platform&gt;.tar.gz — libwallet_mpc.so,
     * wallet_mpc.dll or libwallet_mpc.dylib as extracted, not the archive. Empty in this build: until
     * it is filled, a download is checked only against the release's own .sha256. Fill it from a
     * build you trust; the Go, C#, PHP and Ruby SDKs carry the same table.
     */
    static final Map<String, Map<String, String>> PINNED_CORE_SHA256 = Map.of(
        // "0.1.0", Map.of(
        //     "linux-x64", "<sha256 of libwallet_mpc.so>",
        //     "linux-arm64", "<sha256 of libwallet_mpc.so>",
        //     "win-x64", "<sha256 of wallet_mpc.dll>")
    );

    private static final String RELEASE_BASE =
        "https://github.com/paymos-labs/paymos-wallet-core/releases/download";

    /**
     * The archive holds one library of about a megabyte. These bounds stop a replaced release from
     * spending the integrator's memory on a huge download or a decompression bomb.
     */
    static final long MAX_ARCHIVE_BYTES = 64L << 20;
    static final long MAX_LIBRARY_BYTES = 64L << 20;

    /** Fetches a URL, refusing a body over the limit. The tests hand in a stand-in release. */
    interface Downloader {
        byte[] get(String url, long limit);
    }

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

        return resolveCachedOrDownloaded(cacheRoot(), rid, CORE_VERSION, RELEASE_BASE, NativeCore::download,
            PINNED_CORE_SHA256);
    }

    /** The compiled-in hash for {@code version} on {@code rid}, lowercased, or null. */
    static String pinnedHash(Map<String, Map<String, String>> pins, String version, String rid) {
        Map<String, String> byRid = pins.get(version);
        String hash = byRid == null ? null : byRid.get(rid);
        if (hash == null || hash.isBlank()) return null;
        return hash.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * The cached core for {@code rid}, downloading and installing it first when there is none —
     * verified against {@code pins} when they cover the platform (and then re-hashed on every
     * call), otherwise against the release's own checksum. Package-private and parameterised so
     * the tests can drive it without a network.
     */
    static Path resolveCachedOrDownloaded(Path cacheRoot, String rid, String version, String releaseBase,
                                          Downloader download, Map<String, Map<String, String>> pins) {
        Path cached = cacheRoot.resolve("v" + version).resolve(rid).resolve(libName(rid));
        String pinned = pinnedHash(pins, version, rid);

        if (!Files.exists(cached)) {
            String archiveName = "paymos-wallet-native-v" + version + "-" + rid + ".tar.gz";
            byte[] archive = download.get(releaseBase + "/v" + version + "/" + archiveName, MAX_ARCHIVE_BYTES);
            if (pinned == null) {
                // No compiled-in hash: the release's own checksum, which proves the download intact
                // and nothing more.
                String checksum = new String(
                    download.get(releaseBase + "/v" + version + "/" + archiveName + ".sha256", 4096), StandardCharsets.UTF_8);
                verifySha256(archive, checksum, archiveName);
            }
            byte[] library = readSingleFileTarGz(archive, MAX_LIBRARY_BYTES);
            if (pinned != null) checkPinned(library, pinned, archiveName); // refused before a byte is written
            install(library, cached);
        }

        // A pinned core is re-hashed on every load, cached or just installed: the cache is only a
        // file on disk, and the pin is the only thing that says what may run.
        if (pinned != null) {
            byte[] onDisk;
            try {
                onDisk = Files.readAllBytes(cached);
            } catch (IOException e) {
                throw new PaymosException("cannot read the cached co-signing core " + cached + ": " + e.getMessage());
            }
            try {
                checkPinned(onDisk, pinned, cached.toString());
            } catch (PaymosException e) {
                throw new PaymosException(e.getMessage() + ". Nothing was loaded; delete " + cached
                    + " to fetch the core again — the download is held to the same hash.");
            }
        }
        return cached;
    }

    private static void checkPinned(byte[] payload, String want, String what) {
        String got = sha256Hex(payload);
        if (!got.equals(want))
            throw new PaymosException("SHA-256 mismatch for " + what + ": this SDK pins " + want + ", got " + got);
    }

    private static String sha256Hex(byte[] payload) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest)
                sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 missing from this JVM", e);
        }
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

    private static byte[] download(String url, long limit) {
        try {
            HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL) // GitHub releases redirect to a CDN
                .build();
            HttpResponse<InputStream> resp = client.send(
                HttpRequest.newBuilder(URI.create(url)).build(), HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream body = resp.body()) {
                if (resp.statusCode() != 200)
                    throw new PaymosException(
                        "failed to download the co-signing core: " + url + " answered " + resp.statusCode() + ". "
                            + "Set PAYMOS_NATIVE_LIB to a local libwallet_mpc build to run offline");
                byte[] bytes = body.readNBytes((int) Math.min(Integer.MAX_VALUE - 8, limit + 1));
                if (bytes.length > limit)
                    throw new PaymosException(
                        "failed to download the co-signing core: " + url + " is over " + limit + " bytes — refusing it");
                return bytes;
            }
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

    /**
     * The first regular file of one of our own single-file archives (ustar, type '0', over GZIP),
     * refused once it — or the tar around it — decompresses past {@code limit}.
     */
    static byte[] readSingleFileTarGz(byte[] archive, long limit) {
        // A tar header per file and two zero blocks at the end: 64 KiB is room to spare.
        long tarLimit = limit + 65536;
        byte[] tar;
        try (InputStream gz = new GZIPInputStream(new java.io.ByteArrayInputStream(archive))) {
            tar = gz.readNBytes((int) Math.min(Integer.MAX_VALUE - 8, tarLimit + 1));
        } catch (IOException e) {
            throw new PaymosException("the downloaded core archive is not gzip: " + e.getMessage());
        }
        if (tar.length > tarLimit)
            throw new PaymosException("the downloaded core archive holds a file over " + limit + " bytes — refusing to install it");

        int offset = 0;
        while (offset + 512 <= tar.length) {
            if (isZeroBlock(tar, offset)) break;
            long size = readOctal(tar, offset + 124, 12);
            char type = (char) tar[offset + 156];
            if (size > limit || offset + 512 + size > tar.length)
                throw new PaymosException("the downloaded core archive holds a file over " + limit
                    + " bytes, or a truncated one — refusing to install it");
            if (type == '0' || type == '\0')
                return java.util.Arrays.copyOfRange(tar, offset + 512, offset + 512 + (int) size);
            offset += 512 + (int) ((size + 511) / 512) * 512;
        }
        throw new PaymosException("the downloaded core archive carried no file — refusing to install it");
    }

    /** Writes the library through a temporary file, so a reader never meets half of it. */
    private static void install(byte[] library, Path destination) {
        try {
            Files.createDirectories(destination.getParent());
            Path tmp = destination.resolveSibling(destination.getFileName() + ".tmp");
            Files.write(tmp, library);
            Files.move(tmp, destination, StandardCopyOption.REPLACE_EXISTING);
            destination.toFile().setExecutable(true);
        } catch (IOException e) {
            throw new PaymosException("cannot install the co-signing core: " + e.getMessage());
        }
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
