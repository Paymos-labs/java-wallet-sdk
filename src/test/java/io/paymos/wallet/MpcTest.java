package io.paymos.wallet;

// Proves the Java SDK drives the same co-signing core the Python SDK and the server drive: a
// full 2-of-2 round — two parties, distributed key generation, commit, sign, aggregate — and
// the resulting ed25519 signature verifies. If this passes, the halves agree on what a
// signature is.
//
// The server-side operations are driven directly here rather than through the SDK, because the
// SDK deliberately cannot perform them: it holds one half and no more.
//
// The core binary comes from PAYMOS_NATIVE_LIB (set by the release preflight) or, in a source
// checkout, from the core's own release build under mpc/wallet-mpc/target.

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MpcTest {
    private static final int CLIENT = 1;
    private static final int SERVER = 2;

    @BeforeAll
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

    @Test
    void coSignsAReal2of2SignatureWithTheServerHalf() {
        JsonObject a1 = call("{\"op\":\"dkg_part1\",\"id\":1,\"max\":2,\"min\":2}");
        JsonObject b1 = call("{\"op\":\"dkg_part1\",\"id\":2,\"max\":2,\"min\":2}");
        JsonObject a2 = call("{\"op\":\"dkg_part2\",\"secret\":" + a1.get("secret")
            + ",\"round1_packages\":[[2," + b1.get("package") + "]]}");
        JsonObject b2 = call("{\"op\":\"dkg_part2\",\"secret\":" + b1.get("secret")
            + ",\"round1_packages\":[[1," + a1.get("package") + "]]}");
        JsonObject a3 = call("{\"op\":\"dkg_part3\",\"secret\":" + a2.get("secret")
            + ",\"round1_packages\":[[2," + b1.get("package") + "]]"
            + ",\"round2_packages\":[[2," + packageFor(b2.getAsJsonArray("packages"), CLIENT) + "]]}");
        JsonObject b3 = call("{\"op\":\"dkg_part3\",\"secret\":" + b2.get("secret")
            + ",\"round1_packages\":[[1," + a1.get("package") + "]]"
            + ",\"round2_packages\":[[1," + packageFor(a2.getAsJsonArray("packages"), SERVER) + "]]}");
        assertEquals(a3.get("group_pubkey_hex").getAsString(), b3.get("group_pubkey_hex").getAsString(),
            "both halves derive one group key");

        JsonObject kpA = a3.getAsJsonObject("key_package");
        JsonObject kpB = b3.getAsJsonObject("key_package");

        // The client half goes through the SDK; the server half is driven directly, because the
        // SDK has no way to perform it and that is the point.
        JsonObject[] clientPair = NativeCore.commit(kpA);
        JsonObject server = call("{\"op\":\"commit\",\"key_package\":" + kpB + "}");

        JsonArray commitmentsArr = new JsonArray();
        JsonArray c1 = new JsonArray();
        c1.add(CLIENT);
        c1.add(clientPair[0]);
        JsonArray c2 = new JsonArray();
        c2.add(SERVER);
        c2.add(server.getAsJsonObject("commitments"));
        commitmentsArr.add(c1);
        commitmentsArr.add(c2);
        JsonObject pkg = call("{\"op\":\"build_signing_package\",\"commitments\":" + commitmentsArr
            + ",\"message_hex\":\"deadbeef\"}");

        JsonObject clientShare = NativeCore.sign(pkg.getAsJsonObject("signing_package"), clientPair[1], kpA);
        JsonObject serverShare = call("{\"op\":\"sign\",\"signing_package\":" + pkg.get("signing_package")
            + ",\"nonces\":" + server.get("nonces") + ",\"key_package\":" + kpB + "}");

        JsonArray sharesArr = new JsonArray();
        JsonArray s1 = new JsonArray();
        s1.add(CLIENT);
        s1.add(clientShare);
        JsonArray s2 = new JsonArray();
        s2.add(SERVER);
        s2.add(serverShare.get("signature_share"));
        sharesArr.add(s1);
        sharesArr.add(s2);
        JsonObject agg = call("{\"op\":\"aggregate\",\"signing_package\":" + pkg.get("signing_package")
            + ",\"signature_shares\":" + sharesArr
            + ",\"public_key_package\":" + a3.get("public_key_package") + "}");
        assertTrue(agg.get("verified").getAsBoolean(), "aggregate verifies: " + agg);
    }

    @Test
    void reportsAFailedOpInsteadOfReturningNonsense() {
        assertThrows(PaymosException.class,
            () -> NativeCore.sign(new JsonObject(), new JsonObject(), new JsonObject()));
    }

    @Test
    void reportsThePinnedCoreVersion() {
        assertEquals(NativeCore.CORE_VERSION, NativeCore.version());
    }

    private static JsonObject call(String json) {
        return NativeCore.callOp(com.google.gson.JsonParser.parseString(json).getAsJsonObject());
    }

    private static String packageFor(JsonArray packages, int id) {
        for (var el : packages) {
            JsonArray pair = el.getAsJsonArray();
            if (pair.get(0).getAsInt() == id) return pair.get(1).toString();
        }
        throw new AssertionError("no round2 package for " + id);
    }
}
