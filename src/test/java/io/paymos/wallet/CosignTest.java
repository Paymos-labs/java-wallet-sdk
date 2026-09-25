package io.paymos.wallet;

// The co-sign, driven for real: a stand-in server holds the other half of a genuine 2-of-2 key,
// countersigns every commitment the SDK sends, and verifies the aggregate of both shares. Ported
// from the Python SDK's tests/test_frost.py, so the guard is held to the same cases in both.
//
// The honest run must produce a signature that verifies. Each tampered run breaks exactly one
// thing the blind-sign guard checks, and must end with nothing signed.

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CosignTest {
    private static final String RECIPIENT = "vault.example";
    private static TestNative.Keys keys;
    private static String vk;

    @BeforeAll
    static void dkg() {
        TestNative.ensureNativeLib();
        keys = TestNative.dkg2of2();
        vk = keys.client.get("verifying_key").getAsString();
    }

    static String transfer(String amountRaw, String signer) {
        return "{\"deadline\":\"2026-07-07T00:00:00.000Z\",\"intents\":[{\"intent\":\"transfer\","
            + "\"receiver_id\":\"acct.example\",\"tokens\":{\"usdc-base\":\"" + amountRaw + "\"}}],"
            + "\"signer_id\":\"" + signer + "\"}";
    }

    /** A transfer with the tokens object written out raw, so a test can put anything in it. */
    static String transferTokens(String tokensJson) {
        return "{\"intents\":[{\"intent\":\"transfer\",\"receiver_id\":\"acct.example\",\"tokens\":"
            + tokensJson + "}],\"signer_id\":\"" + vk + "\"}";
    }

    static byte[] nonce(int i) {
        byte[] b = new byte[32];
        for (int k = 0; k < 32; k++) b[k] = (byte) ((i + k) % 256);
        return b;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /** The server's half of the protocol, answering from the contract's wire shapes. */
    static class Server implements Http.Transport {
        final JsonObject quote;
        int beginCalls;
        int aggregateCalls;
        JsonArray lastCommitments;
        final List<JsonObject> packages = new ArrayList<>();
        final List<JsonObject> serverShares = new ArrayList<>();
        /** (source index, per-source amount) → the disclosed message. Tamper runs replace it. */
        BiFunction<Integer, String, String> message = (i, amount) -> transfer(amount, vk);
        /** Digest the package REALLY binds to, given the disclosed message. Tamper runs replace it. */
        BiFunction<String, byte[], String> digest = (m, n) -> Digest.payloadDigestHex(m, n, RECIPIENT, null);
        boolean discloseMessages = true;
        /** The catalog the server publishes; the recorded one, fingerprints included. */
        JsonElement assets = ContractTest.fixture("assets").getAsJsonObject("response").get("body");
        /** The client's key package as the secret carries it. */
        JsonObject clientKp = keys.client;
        /** The caller's pinnedFingerprints, if any. */
        java.util.Map<String, List<String>> pins;

        Server(String quoteFixture, int sources) {
            JsonObject q = ContractTest.fixture(quoteFixture).getAsJsonObject("response").getAsJsonObject("body").deepCopy();
            q.addProperty("sources", sources);
            this.quote = q;
        }

        @Override
        public Http.Response send(Http.Request r) {
            assertEquals("Bearer vk_live_test", r.headers.get("authorization"));
            String path = java.net.URI.create(r.url).getRawPath();
            if (path.equals("/vault/v1/assets"))
                return ok(assets);
            if (path.startsWith("/vault/v1/quote/"))
                return ok(quote);
            if (path.endsWith("/sign/begin")) {
                beginCalls++;
                lastCommitments = JsonParser.parseString(r.body).getAsJsonObject().getAsJsonArray("commitments");
                packages.clear();
                serverShares.clear();
                JsonArray disclosed = new JsonArray();
                JsonArray pkgs = new JsonArray();
                int n = lastCommitments.size();
                long per = Long.parseLong(quote.getAsJsonObject("debit").get("amount").getAsString()) / n;
                for (int i = 0; i < n; i++) {
                    String msg = message.apply(i, Long.toString(per));
                    byte[] nn = nonce(i);
                    JsonObject sc = TestNative.call("{\"op\":\"commit\",\"key_package\":" + keys.server + "}");
                    JsonObject sp = TestNative.call("{\"op\":\"build_signing_package\",\"commitments\":[[1,"
                        + lastCommitments.get(i) + "],[2," + sc.get("commitments") + "]],\"message_hex\":\""
                        + digest.apply(msg, nn) + "\"}").getAsJsonObject("signing_package");
                    JsonObject share = TestNative.call("{\"op\":\"sign\",\"signing_package\":" + sp
                        + ",\"nonces\":" + sc.get("nonces") + ",\"key_package\":" + keys.server + "}");
                    packages.add(sp);
                    serverShares.add(share.getAsJsonObject("signature_share"));
                    pkgs.add(sp);
                    JsonObject d = new JsonObject();
                    d.addProperty("message", msg);
                    d.addProperty("nonce", hex(nn));
                    d.addProperty("recipient", RECIPIENT);
                    disclosed.add(d);
                }
                JsonObject out = new JsonObject();
                out.addProperty("token", "tkn");
                out.add("signing_packages", pkgs);
                if (discloseMessages) out.add("messages", disclosed);
                return ok(out);
            }
            if (path.endsWith("/sign/aggregate")) {
                aggregateCalls++;
                JsonObject body = JsonParser.parseString(r.body).getAsJsonObject();
                assertEquals("tkn", body.get("token").getAsString());
                JsonArray shares = body.getAsJsonArray("shares");
                assertEquals(packages.size(), shares.size(), "one share per package");
                for (int i = 0; i < shares.size(); i++) {
                    JsonObject agg = TestNative.call("{\"op\":\"aggregate\",\"signing_package\":" + packages.get(i)
                        + ",\"signature_shares\":[[1," + shares.get(i) + "],[2," + serverShares.get(i) + "]]"
                        + ",\"public_key_package\":" + keys.publicKeyPackage + "}");
                    assertTrue(agg.get("verified").getAsBoolean(), "session " + i + " verifies");
                }
                // The recorded answer, verbatim.
                return ok(ContractTest.fixture("sign_aggregate").getAsJsonObject("response").get("body"));
            }
            if (path.startsWith("/vault/v1/movements/")) {
                JsonObject mv = ContractTest.fixture("movement").getAsJsonObject("response").getAsJsonObject("body").deepCopy();
                mv.addProperty("id", quote.get("movement_id").getAsString());
                mv.addProperty("status", "processing");
                return ok(mv);
            }
            throw new AssertionError("unexpected path " + path);
        }

        Wallet wallet() {
            return new Wallet(VaultSecret.pack("vk_live_test", 1, clientKp.toString()),
                "https://vault.test", Duration.ofSeconds(5), this, pins);
        }

        private static Http.Response ok(JsonElement body) {
            return new Http.Response(200, body.toString(), null);
        }
    }

    @Test
    void anHonestSwapCoSignsAndVerifies() {
        Server s = new Server("quote_swap", 1);
        Types.Movement mv = s.wallet().swap("USDC@base", "USDT@base", "5", 50, null, null, null);
        assertEquals(1, s.beginCalls);
        assertEquals(1, s.aggregateCalls);
        assertEquals(1, s.lastCommitments.size());
        assertEquals("mv_3", mv.id);
        assertEquals("processing", mv.status);
    }

    @Test
    void anHonestTwoSourceWithdrawSignsEachSource() {
        Server s = new Server("quote_withdraw", 2);
        s.wallet().withdraw("USDC@base", "10", "0xabc0000000000000000000000000000000000000", "exact_out", null, null);
        assertEquals(2, s.lastCommitments.size());
        assertEquals(1, s.aggregateCalls);
    }

    @Test
    void refusesWhenTheServerDisclosesNothing() {
        Server s = new Server("quote_swap", 1);
        s.discloseMessages = false;
        refused(s, "blind-sign");
    }

    @Test
    void refusesAPackageThatDoesNotBindToTheDisclosure() {
        Server s = new Server("quote_swap", 1);
        s.digest = (m, n) -> Digest.payloadDigestHex(m.replace("acct.example", "thief.example"), n, RECIPIENT, null);
        refused(s, "does not bind");
    }

    @Test
    void refusesAMessageFromAnotherVault() {
        Server s = new Server("quote_swap", 1);
        s.message = (i, amount) -> transfer(amount, "someone-else");
        refused(s, "different vault");
    }

    @Test
    void refusesSourcesThatMoveMoreThanTheDebit() {
        Server s = new Server("quote_swap", 1);
        s.message = (i, amount) -> transfer("5000001", vk);
        refused(s, "above the approved debit");
    }

    @Test
    void refusesANegativeSourceThatHidesAnInflatedOne() {
        // 10025000 approved. Source 0 moves 1 000 000 000; source 1 "moves" a negative amount
        // that brings the sum back under the debit. Only the first would ever settle.
        Server s = new Server("quote_withdraw", 2);
        s.message = (i, amount) -> transfer(i == 0 ? "1000000000" : "-989975000", vk);
        PaymosException ex = assertThrows(PaymosException.class,
            () -> s.wallet().withdraw("USDC@base", "10", "0xabc0000000000000000000000000000000000000", "exact_out", null, null));
        assertTrue(ex.getMessage().contains("bad transfer amount"), ex.getMessage());
        assertEquals(0, s.aggregateCalls);
    }

    @Test
    void refusesAMessageThatNamesNoSigner() {
        Server s = new Server("quote_swap", 1);
        s.message = (i, amount) -> "{\"intents\":[{\"intent\":\"transfer\",\"tokens\":{\"t\":\"1\"}}]}";
        refused(s, "no signer_id");
    }

    @Test
    void refusesAMalformedNonceAsATypedError() {
        Server s = new Server("quote_swap", 1) {
            @Override
            public Http.Response send(Http.Request r) {
                Http.Response resp = super.send(r);
                if (!r.url.endsWith("/sign/begin")) return resp;
                return new Http.Response(200, resp.body.replaceAll("\"nonce\":\"[0-9a-f]+\"", "\"nonce\":\"zz\""), null);
            }
        };
        refused(s, "malformed disclosure");
    }

    @Test
    void refusesATransferOfAnotherAsset() {
        // "usdt-base" hashes to USDT@base's published fingerprint: a real asset, just not the one
        // the debit was approved in.
        Server s = new Server("quote_swap", 1);
        s.message = (i, amount) -> transferTokens("{\"usdt-base\":\"" + amount + "\"}");
        refused(s, "token other than the quote's send asset");
    }

    @Test
    void refusesWhenTheServerPublishesNoFingerprint() {
        Server s = new Server("quote_swap", 1);
        JsonArray stripped = s.assets.getAsJsonArray().deepCopy();
        for (JsonElement a : stripped) a.getAsJsonObject().remove("fingerprint");
        s.assets = stripped;
        refused(s, "did not publish an asset fingerprint");
    }

    @Test
    void refusesAKeyPackageWithoutAVerifyingKey() {
        Server s = new Server("quote_swap", 1);
        s.clientKp = keys.client.deepCopy();
        s.clientKp.remove("verifying_key");
        PaymosException ex = assertThrows(PaymosException.class,
            () -> s.wallet().swap("USDC@base", "USDT@base", "5", 50, null, null, null));
        assertTrue(ex.getMessage().contains("no verifying key"), ex.getMessage());
        assertEquals(0, s.beginCalls, "refused before a commitment left the process");
        assertEquals(0, s.aggregateCalls);
    }

    @Test
    void refusesEveryAmountThatIsNotAPositiveDigitString() {
        for (String bad : new String[] { "\"0\"", "\"00\"", "\"-1\"", "\"+5\"", "\"\"", "\" 5\"", "\"5 \"",
                                         "\"1_000\"", "\"\u0665\"", "5", "5.0", "null", "true" }) {
            Server s = new Server("quote_swap", 1);
            s.message = (i, amount) -> transferTokens("{\"usdc-base\":" + bad + "}");
            refused(s, "bad transfer amount");
        }
    }

    static String sha256(String s) {
        try {
            return hex(java.security.MessageDigest.getInstance("SHA-256").digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    /** The recorded catalog plus a second USDC@base entry: another contract of the same coin. */
    static Server withTwoUsdcContracts() {
        Server s = new Server("quote_swap", 1);
        JsonArray cat = s.assets.getAsJsonArray().deepCopy();
        JsonObject second = cat.get(0).getAsJsonObject().deepCopy();
        second.addProperty("fingerprint", sha256("usdc-base-bridged"));
        cat.add(second);
        s.assets = cat;
        return s;
    }

    @Test
    void aSecondEntryInOtherDecimalsIsRefused() {
        // Same label, 18 decimals: a raw amount under the 6-decimal debit would be worth 10^12 more.
        Server s = withTwoUsdcContracts();
        s.assets.getAsJsonArray().get(2).getAsJsonObject().addProperty("decimals", 18);
        s.message = (i, amount) -> transferTokens("{\"usdc-base-bridged\":\"" + amount + "\"}");
        refused(s, "token other than the quote's send asset");
    }

    @Test
    void oneLabelWithTwoFingerprintsAcceptsEither() {
        for (String key : new String[] { "usdc-base", "usdc-base-bridged" }) {
            Server s = withTwoUsdcContracts();
            s.message = (i, amount) -> transferTokens("{\"" + key + "\":\"" + amount + "\"}");
            s.wallet().swap("USDC@base", "USDT@base", "5", 50, null, null, null);
            assertEquals(1, s.aggregateCalls, key + " signs");
        }
    }

    @Test
    void oneLabelWithTwoFingerprintsStillRefusesAThird() {
        Server s = withTwoUsdcContracts();
        s.message = (i, amount) -> transferTokens("{\"usdt-base\":\"" + amount + "\"}");
        refused(s, "token other than the quote's send asset");
    }

    @Test
    void aPinnedFingerprintSigns() {
        Server s = new Server("quote_swap", 1);
        // Upper case on purpose: pins compare lowercase.
        s.pins = java.util.Map.of("USDC@base", List.of(sha256("usdc-base").toUpperCase()));
        s.wallet().swap("USDC@base", "USDT@base", "5", 50, null, null, null);
        assertEquals(1, s.aggregateCalls);
    }

    @Test
    void aPinOverridesWhatTheServerPublishes() {
        // The server publishes usdc-base's fingerprint and discloses a usdc-base transfer — self-
        // consistent, and still refused, because the caller pinned a different token for the label.
        Server s = new Server("quote_swap", 1);
        s.pins = java.util.Map.of("USDC@base", List.of(sha256("usdc-base-pinned")));
        refused(s, "token other than the quote's send asset");
    }

    @Test
    void aPinCoversAServerThatPublishesNoFingerprint() {
        Server s = new Server("quote_swap", 1);
        JsonArray stripped = s.assets.getAsJsonArray().deepCopy();
        for (JsonElement a : stripped) a.getAsJsonObject().remove("fingerprint");
        s.assets = stripped;
        s.pins = java.util.Map.of("USDC@base", List.of(sha256("usdc-base")));
        s.wallet().swap("USDC@base", "USDT@base", "5", 50, null, null, null);
        assertEquals(1, s.aggregateCalls);
    }

    @Test
    void anEmptyPinIsRejectedUpFront() {
        assertThrows(PaymosException.class, () -> new Wallet(VaultSecret.pack("vk_live_test", 1, null),
            "https://vault.test", null, java.util.Map.of("USDC@base", List.<String>of())));
    }

    private static void refused(Server s, String why) {
        PaymosException ex = assertThrows(PaymosException.class,
            () -> s.wallet().swap("USDC@base", "USDT@base", "5", 50, null, null, null));
        assertTrue(ex.getMessage().startsWith("co-sign refused"), ex.getMessage());
        assertTrue(ex.getMessage().contains(why), ex.getMessage());
        assertEquals(1, s.beginCalls);
        assertEquals(0, s.aggregateCalls, "nothing was signed");
    }
}
