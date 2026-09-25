package io.paymos.wallet;

// Test-only access to the co-signing core: find the locally built binary, and run the 2-of-2 DKG
// the server and the client would run between them, so a test holds real key material.

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

final class TestNative {
    private TestNative() {}

    static final class Keys {
        final JsonObject client;
        final JsonObject server;
        final JsonObject publicKeyPackage;

        Keys(JsonObject client, JsonObject server, JsonObject publicKeyPackage) {
            this.client = client;
            this.server = server;
            this.publicKeyPackage = publicKeyPackage;
        }
    }

    /** PAYMOS_NATIVE_LIB when set; otherwise the core's own release build in a source checkout. */
    static void ensureNativeLib() {
        if (System.getenv("PAYMOS_NATIVE_LIB") != null) return;
        Path dir = Paths.get("").toAbsolutePath();
        while (dir != null && !Files.isDirectory(dir.resolve("mpc/wallet-mpc")))
            dir = dir.getParent();
        if (dir == null) return;
        String os = System.getProperty("os.name").toLowerCase();
        String lib = os.contains("win") ? "wallet_mpc.dll"
            : os.contains("mac") ? "libwallet_mpc.dylib" : "libwallet_mpc.so";
        Path candidate = dir.resolve(Paths.get("mpc", "wallet-mpc", "target", "release", lib));
        if (Files.exists(candidate))
            System.setProperty("paymos.native.lib", candidate.toString());
    }

    static JsonObject call(String json) {
        return NativeCore.callOp(JsonParser.parseString(json).getAsJsonObject());
    }

    static Keys dkg2of2() {
        JsonObject a1 = call("{\"op\":\"dkg_part1\",\"id\":1,\"max\":2,\"min\":2}");
        JsonObject b1 = call("{\"op\":\"dkg_part1\",\"id\":2,\"max\":2,\"min\":2}");
        JsonObject a2 = call("{\"op\":\"dkg_part2\",\"secret\":" + a1.get("secret")
            + ",\"round1_packages\":[[2," + b1.get("package") + "]]}");
        JsonObject b2 = call("{\"op\":\"dkg_part2\",\"secret\":" + b1.get("secret")
            + ",\"round1_packages\":[[1," + a1.get("package") + "]]}");
        JsonObject a3 = call("{\"op\":\"dkg_part3\",\"secret\":" + a2.get("secret")
            + ",\"round1_packages\":[[2," + b1.get("package") + "]]"
            + ",\"round2_packages\":[[2," + packageFor(b2.getAsJsonArray("packages"), 1) + "]]}");
        JsonObject b3 = call("{\"op\":\"dkg_part3\",\"secret\":" + b2.get("secret")
            + ",\"round1_packages\":[[1," + a1.get("package") + "]]"
            + ",\"round2_packages\":[[1," + packageFor(a2.getAsJsonArray("packages"), 2) + "]]}");
        return new Keys(a3.getAsJsonObject("key_package"), b3.getAsJsonObject("key_package"),
            a3.getAsJsonObject("public_key_package"));
    }

    private static String packageFor(JsonArray packages, int id) {
        for (var el : packages) {
            JsonArray pair = el.getAsJsonArray();
            if (pair.get(0).getAsInt() == id) return pair.get(1).toString();
        }
        throw new AssertionError("no round2 package for " + id);
    }
}
