package io.paymos.wallet;

// Where the co-signing core comes from, and what it must hash to. The release is an in-memory
// stand-in; nothing here downloads anything or loads a library.

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;

class NativeCoreTest {
    private static final String RID = "linux-x64"; // the resolver is told the platform; any one will do
    private static final String VERSION = "0.1.0";
    private static final String BASE = "https://release.test";
    private static final String ARCHIVE = "paymos-wallet-native-v" + VERSION + "-" + RID + ".tar.gz";

    @TempDir
    Path cache;

    /** A release archive in the shape native-artifacts.sh packs: one ustar file, no directory. */
    static byte[] archive(byte[] library) throws IOException {
        ByteArrayOutputStream tar = new ByteArrayOutputStream();
        byte[] header = new byte[512];
        byte[] name = "libwallet_mpc.so".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(name, 0, header, 0, name.length);
        byte[] size = String.format("%011o", library.length).getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(size, 0, header, 124, size.length);
        header[156] = '0';
        tar.write(header);
        tar.write(library);
        tar.write(new byte[(512 - library.length % 512) % 512]);
        tar.write(new byte[1024]);
        ByteArrayOutputStream gz = new ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(gz)) {
            out.write(tar.toByteArray());
        }
        return gz.toByteArray();
    }

    static String sha(byte[] b) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (byte x : MessageDigest.getInstance("SHA-256").digest(b)) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    static final class Release implements NativeCore.Downloader {
        final Map<String, byte[]> files = new HashMap<>();
        final List<String> asked = new ArrayList<>();

        @Override
        public byte[] get(String url, long limit) {
            asked.add(url);
            byte[] body = files.get(url);
            if (body == null) throw new PaymosException("404 " + url);
            return body;
        }
    }

    /** A release serving {@code library}; its .sha256 the archive's true one unless given. */
    static Release serving(byte[] library, String checksum) throws Exception {
        byte[] archive = archive(library);
        Release r = new Release();
        r.files.put(BASE + "/v" + VERSION + "/" + ARCHIVE, archive);
        r.files.put(BASE + "/v" + VERSION + "/" + ARCHIVE + ".sha256",
            ((checksum == null ? sha(archive) : checksum) + "  " + ARCHIVE + "\n").getBytes(StandardCharsets.UTF_8));
        return r;
    }

    static Map<String, Map<String, String>> pins(String hash) {
        return hash == null ? Map.of() : Map.of(VERSION, Map.of(RID, hash));
    }

    Path resolve(Release r, Map<String, Map<String, String>> pins) {
        return NativeCore.resolveCachedOrDownloaded(cache, RID, VERSION, BASE, r, pins);
    }

    @Test
    void everyShippedPinNamesAKnownPlatformAndIsASha256() {
        // Empty until the owner fills it; a pasted entry with a typo fails here, not at a user's first payout.
        List<String> platforms = List.of("linux-x64", "linux-arm64", "win-x64", "win-arm64", "osx-x64", "osx-arm64");
        NativeCore.PINNED_CORE_SHA256.forEach((version, byRid) -> byRid.forEach((rid, hash) -> {
            assertTrue(platforms.contains(rid), version + ": unknown platform " + rid);
            assertTrue(hash.matches("[0-9a-fA-F]{64}"), version + "/" + rid + ": not a sha256: " + hash);
        }));
    }

    @Test
    void aPinnedHashIsTheOnlyOneAcceptedAndTheCacheIsRehashed() throws Exception {
        byte[] library = "the trusted co-signing core".getBytes(StandardCharsets.UTF_8);
        Release release = serving(library, "0".repeat(64)); // wrong, and never read
        Map<String, Map<String, String>> pins = pins(sha(library).toUpperCase(Locale.ROOT));

        Path path = resolve(release, pins);
        assertArrayEquals(library, Files.readAllBytes(path));
        assertTrue(release.asked.stream().noneMatch(u -> u.endsWith(".sha256")), release.asked.toString());

        int asked = release.asked.size();
        assertEquals(path, resolve(release, pins));
        assertEquals(asked, release.asked.size(), "a cached core loads without a download");

        Files.write(path, "a substituted library".getBytes(StandardCharsets.UTF_8));
        PaymosException ex = assertThrows(PaymosException.class, () -> resolve(release, pins));
        assertTrue(ex.getMessage().contains("SHA-256 mismatch"), ex.getMessage());
        assertTrue(ex.getMessage().contains(path.toString()), ex.getMessage());
        assertTrue(Files.exists(path), "the refused file is left where it is");
    }

    @Test
    void aDownloadThatMissesThePinIsRefusedBeforeAnythingIsWritten() throws Exception {
        Release release = serving("a replaced release".getBytes(StandardCharsets.UTF_8), null); // its .sha256 is right
        PaymosException ex = assertThrows(PaymosException.class,
            () -> resolve(release, pins(sha("the trusted co-signing core".getBytes(StandardCharsets.UTF_8)))));
        assertTrue(ex.getMessage().contains("SHA-256 mismatch"), ex.getMessage());
        try (Stream<Path> files = Files.walk(cache)) {
            assertEquals(0, files.filter(Files::isRegularFile).count());
        }
    }

    @Test
    void withoutAPinTheReleaseChecksumDecidesAsItAlwaysDid() throws Exception {
        byte[] library = "a core this SDK build carries no hash for".getBytes(StandardCharsets.UTF_8);
        Release release = serving(library, null);
        Path path = resolve(release, pins(null));
        assertTrue(release.asked.stream().anyMatch(u -> u.endsWith(".sha256")));

        Files.write(path, "changed on disk".getBytes(StandardCharsets.UTF_8));
        assertEquals(path, resolve(release, pins(null)), "an unpinned cache is trusted as written");

        Files.delete(path);
        PaymosException ex = assertThrows(PaymosException.class,
            () -> resolve(serving(library, "0".repeat(64)), pins(null)));
        assertTrue(ex.getMessage().contains("SHA-256 mismatch"), ex.getMessage());
    }

    @Test
    void aReleaseCannotMakeTheSdkDecompressABomb() throws Exception {
        PaymosException ex = assertThrows(PaymosException.class,
            () -> NativeCore.readSingleFileTarGz(archive(new byte[200_000]), 1024));
        assertTrue(ex.getMessage().contains("over 1024 bytes"), ex.getMessage());
        ex = assertThrows(PaymosException.class, () -> NativeCore.readSingleFileTarGz(archive(new byte[4096]), 1024));
        assertTrue(ex.getMessage().contains("over 1024 bytes"), ex.getMessage());
        assertEquals(4096, NativeCore.readSingleFileTarGz(archive(new byte[4096]), 4096).length);
    }
}
