package io.paymos.wallet;

// The wire contract, read from disk. Every response here is a file the REAL server pipeline
// recorded (sdk/contract/fixtures, vendored into a public mirror as contract/fixtures) — not a
// shape somebody remembered. The previous suite mocked {"assets": [...]}, passed, and shipped an
// SDK whose every money call failed with "unknown asset" against the real bare array.
//
// No socket: the fixtures are served through Http.Transport, and every request the SDK sends is
// recorded so it can be compared with the request the fixture was recorded from.
//
// If the fixtures cannot be found this FAILS. A contract test that skips when the contract is
// missing is how a suite goes green on nothing.

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ContractTest {
    private static final String BASE = "https://vault.test";
    private static final String TO = "0xabc0000000000000000000000000000000000000";

    // Python's sets, verbatim (sdk/python/paymos/_wallet.py). The Java SDK must classify every
    // status the server can send exactly the way the reference does.
    private static final Set<String> PY_TERMINAL = Set.of("completed", "failed", "refunded", "expired", "cancelled");
    private static final Set<String> PY_PROGRESSED = Set.of("processing", "completed", "refunded");

    private static Path fixtures;
    /** A real client key package from a 2-of-2 DKG, so a full secret can commit for real. */
    private static String clientKeyPackage;

    @BeforeAll
    static void setUp() {
        fixtures = findFixtures();
        TestNative.ensureNativeLib();
        clientKeyPackage = TestNative.dkg2of2().client.toString();
    }

    /** contract/fixtures (a public mirror), then sdk/contract/fixtures (this repo), walking up. */
    static Path findFixtures() {
        List<Path> starts = new ArrayList<>();
        try {
            starts.add(Paths.get(ContractTest.class.getProtectionDomain().getCodeSource().getLocation().toURI()));
        } catch (Exception ignored) {
            // fall through to the working directory
        }
        starts.add(Paths.get("").toAbsolutePath());
        for (Path start : starts) {
            for (Path dir = start; dir != null; dir = dir.getParent()) {
                for (String rel : new String[] { "contract/fixtures", "sdk/contract/fixtures" }) {
                    Path p = dir.resolve(rel);
                    if (Files.isRegularFile(p.resolve("assets.json"))) return p;
                }
            }
        }
        fail("contract fixtures not found: looked for contract/fixtures and sdk/contract/fixtures above " + starts);
        return null;
    }

    static JsonObject fixture(String name) {
        // Other test classes read fixtures too, and JUnit runs classes in no promised order.
        if (fixtures == null) fixtures = findFixtures();
        try {
            return JsonParser.parseString(Files.readString(fixtures.resolve(name + ".json"), StandardCharsets.UTF_8))
                .getAsJsonObject();
        } catch (IOException e) {
            throw new AssertionError("cannot read fixture " + name, e);
        }
    }

    // ── the transport ────────────────────────────────────────────────────────

    /** Answers "METHOD /path?query" from fixtures and records what was sent. */
    static final class FixtureTransport implements Http.Transport {
        final Map<String, Http.Response> routes = new HashMap<>();
        final List<Http.Request> sent = new ArrayList<>();

        FixtureTransport serve(String name) {
            JsonObject f = fixture(name);
            JsonObject req = f.getAsJsonObject("request");
            return serve(req.get("method").getAsString() + " " + req.get("path").getAsString(), f.getAsJsonObject("response"));
        }

        FixtureTransport serve(String route, JsonObject response) {
            return raw(route, response.get("status").getAsInt(), response.get("body").toString());
        }

        FixtureTransport raw(String route, int status, String body) {
            routes.put(route, new Http.Response(status, body, null));
            return this;
        }

        @Override
        public Http.Response send(Http.Request r) {
            sent.add(r);
            URI u = URI.create(r.url);
            String key = r.method + " " + u.getRawPath() + (u.getRawQuery() == null ? "" : "?" + u.getRawQuery());
            Http.Response resp = routes.get(key);
            if (resp == null) throw new AssertionError("the SDK sent a request no fixture answers: " + key);
            return resp;
        }

        Http.Request last(String method, String path) {
            for (int i = sent.size() - 1; i >= 0; i--) {
                Http.Request r = sent.get(i);
                if (r.method.equals(method) && URI.create(r.url).getRawPath().equals(path)) return r;
            }
            throw new AssertionError("no " + method + " " + path + " was sent");
        }

        boolean sentTo(String pathSuffix) {
            return sent.stream().anyMatch(r -> URI.create(r.url).getRawPath().endsWith(pathSuffix));
        }
    }

    private static Wallet readWallet(FixtureTransport t) {
        return new Wallet(VaultSecret.pack("vk_live_test", 1, null), BASE, Duration.ofSeconds(5), t);
    }

    private static Wallet fullWallet(FixtureTransport t) {
        return new Wallet(VaultSecret.pack("vk_live_test", 1, clientKeyPackage), BASE, Duration.ofSeconds(5), t);
    }

    /** The request the SDK sent carries every field of the recorded one with the same value; the
     *  only extra it may add is "dry" — false where the fixture relied on the server's default. */
    private static void assertSentBodyMatches(String fixtureName, Http.Request sent) {
        JsonObject want = fixture(fixtureName).getAsJsonObject("request");
        URI u = URI.create(sent.url);
        assertEquals(want.get("method").getAsString(), sent.method, fixtureName + ": method");
        assertEquals(want.get("path").getAsString(), u.getRawPath(), fixtureName + ": path");
        JsonObject wantBody = want.getAsJsonObject("body");
        JsonObject got = JsonParser.parseString(sent.body).getAsJsonObject();
        for (Map.Entry<String, JsonElement> e : wantBody.entrySet())
            assertEquals(e.getValue(), got.get(e.getKey()), fixtureName + ": body field " + e.getKey());
        for (String k : got.keySet()) {
            if (wantBody.has(k)) continue;
            assertEquals("dry", k, fixtureName + ": the SDK sent a field the server was never recorded receiving");
            assertFalse(got.get(k).getAsBoolean(), fixtureName + ": dry defaults to false on the server");
        }
        // amount a decimal STRING, slippage_bps an integer, dry a boolean — types, not just values.
        assertTrue(got.get("amount").getAsJsonPrimitive().isString(), "amount is a string");
        if (got.has("slippage_bps")) assertTrue(got.get("slippage_bps").getAsJsonPrimitive().isNumber());
        assertTrue(got.get("dry").getAsJsonPrimitive().isBoolean(), "dry is a boolean");
    }

    // ── reads ────────────────────────────────────────────────────────────────

    @Test
    void assetsParseTheBareArray() {
        FixtureTransport t = new FixtureTransport().serve("assets");
        List<Types.Asset> assets = readWallet(t).assets();
        assertEquals(2, assets.size());
        Types.Asset a = assets.get(0);
        assertEquals("USDC@base", a.asset);
        assertEquals("USDC", a.symbol);
        assertEquals("base", a.chain);
        assertEquals(6, a.decimals);
        assertEquals("a42c7e46411394e7c7719eef5be19239b2716b91d3a4a843fd3d2c0b6ca16b7c", a.fingerprint);
        assertEquals("USDT@base", assets.get(1).asset);
        assertEquals(6, assets.get(1).decimals);
        assertEquals("4aa51775b928a58a1ff49de71caf2cd78e1bf728d2853d7193d14cf30728f039", assets.get(1).fingerprint);
        assertEquals("GET", t.sent.get(0).method);
    }

    @Test
    void aFingerprintIsSha256OfTheRawTokenId() throws Exception {
        byte[] d = java.security.MessageDigest.getInstance("SHA-256").digest("usdc-base".getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b : d) hex.append(String.format("%02x", b));
        String published = fixture("assets").getAsJsonObject("response").getAsJsonArray("body")
            .get(0).getAsJsonObject().get("fingerprint").getAsString();
        assertEquals(published, hex.toString());
    }

    @Test
    void anOlderServerWithoutFingerprintsStillReads() {
        FixtureTransport t = new FixtureTransport().raw("GET /vault/v1/assets", 200,
            "[{\"asset\":\"USDC@base\",\"symbol\":\"USDC\",\"chain\":\"base\",\"decimals\":6}]");
        Types.Asset a = readWallet(t).assets().get(0);
        assertEquals("USDC@base", a.asset);
        assertNull(a.fingerprint);
    }

    @Test
    void balancesParseTheBareArray() {
        FixtureTransport t = new FixtureTransport().serve("balances");
        List<Types.Balance> bs = readWallet(t).balances();
        assertEquals(1, bs.size());
        Types.Balance b = bs.get(0);
        assertEquals("USDC@base", b.asset);
        assertEquals("USDC", b.symbol);
        assertEquals("base", b.chain);
        assertEquals(6, b.decimals);
        assertEquals("1000000000", b.amountRaw);
        assertEquals("1000", b.usd);
    }

    @Test
    void anOmittedUsdIsNullNotAnError() {
        FixtureTransport t = new FixtureTransport().raw("GET /vault/v1/balances", 200,
            "[{\"asset\":\"USDC@base\",\"symbol\":\"USDC\",\"chain\":\"base\",\"decimals\":6,\"amount_raw\":\"1\"}]");
        assertNull(readWallet(t).balances().get(0).usd);
    }

    @Test
    void movementCarriesItsFees() {
        FixtureTransport t = new FixtureTransport().serve("movement");
        Types.Movement m = readWallet(t).movement("mv_3");
        assertEquals("mv_3", m.id);
        assertEquals("swap", m.type);
        assertEquals("pending", m.status);
        assertEquals("5000000", m.send.amount);
        assertEquals("USDC@base", m.send.asset);
        assertEquals("5000000", m.receive.amount);
        assertEquals("5000000", m.receive.min);
        assertEquals("USDT@base", m.receive.asset);
        assertNotNull(m.fees);
        assertFees(m.fees, "USDC@base", "0", "0", "0", true, "0", Map.of("platform", "0", "network", "0", "route", "0", "total", "0"));
        assertEquals("2026-01-01T00:00:00.0000000+00:00", m.createdAt);
        // Omitted by the server while the movement is in flight.
        assertNull(m.destChainTxHash);
        assertNull(m.destChainExplorerUrl);
        assertNull(m.completedAt);
    }

    @Test
    void movementsPageAndItsCursor() {
        FixtureTransport t = new FixtureTransport().serve("movements_page")
            .raw("GET /vault/v1/movements?limit=2&cursor=cursor_1", 200, "{\"items\":[]}");
        Wallet w = readWallet(t);

        Map.Entry<List<Types.Movement>, String> page = w.movements(2, null);
        assertEquals(BASE + fixture("movements_page").getAsJsonObject("request").get("path").getAsString(), t.sent.get(0).url);
        assertEquals(2, page.getKey().size());
        assertEquals("cursor_1", page.getValue());

        Types.Movement first = page.getKey().get(0);
        assertEquals("mv_3", first.id);
        assertEquals("swap", first.type);
        assertEquals("pending", first.status);
        assertEquals("5000000", first.send.amount);
        assertEquals("USDT@base", first.receive.asset);
        assertNull(first.fees, "summary rows carry no fees");
        assertEquals("2026-01-01T00:00:00.0000000+00:00", first.createdAt);

        Types.Movement second = page.getKey().get(1);
        assertEquals("mv_2", second.id);
        assertEquals("withdrawal", second.type);
        assertEquals("10000000", second.send.amount);
        assertEquals("9975062", second.receive.amount);
        assertEquals("9975062", second.receive.min);
        assertEquals("USDC@base", second.receive.asset);

        // The last page omits next_cursor. That is the end of history, not a NullPointerException.
        Map.Entry<List<Types.Movement>, String> last = w.movements(2, page.getValue());
        assertTrue(last.getKey().isEmpty());
        assertNull(last.getValue());
    }

    // ── dry quotes ───────────────────────────────────────────────────────────

    @Test
    void quoteWithdrawDry() {
        FixtureTransport t = new FixtureTransport().serve("assets").serve("quote_withdraw_dry");
        Types.Quote q = readWallet(t).quoteWithdraw("USDC@base", "10", TO, "exact_out");

        Http.Request sent = t.last("POST", "/vault/v1/quote/withdraw");
        assertSentBodyMatches("quote_withdraw_dry", sent);
        assertFalse(sent.headers.containsKey("idempotency-key"), "a dry preview carries no idempotency key");

        assertNull(q.movementId);
        assertNull(q.sources, "a dry preview has nothing to sign");
        assertEquals("exact_out", q.mode);
        assertLeg(q.send, "10000000", "USDC@base");
        assertLeg(q.debit, "10025000", "USDC@base");
        assertEquals("10000000", q.receive.amount);
        assertEquals("10000000", q.receive.min);
        assertEquals("USDC@base", q.receive.asset);
        assertFees(q.fees, "USDC@base", "25000", "0", "0", false, "25000",
            Map.of("platform", "0.025", "network", "0", "route", "0", "total", "0.025"));
        assertEquals("2026-01-01T00:00:00.0000000+00:00", q.expiresAt);
    }

    @Test
    void quoteSwapDry() {
        FixtureTransport t = new FixtureTransport().serve("assets").serve("quote_swap_dry");
        Types.Quote q = readWallet(t).quoteSwap("USDC@base", "USDT@base", "5", 50);

        Http.Request sent = t.last("POST", "/vault/v1/quote/swap");
        assertSentBodyMatches("quote_swap_dry", sent);
        assertFalse(sent.headers.containsKey("idempotency-key"));

        assertNull(q.movementId);
        assertNull(q.sources);
        assertEquals("exact_in", q.mode);
        assertLeg(q.send, "5000000", "USDC@base");
        assertLeg(q.debit, "5000000", "USDC@base");
        assertEquals("5000000", q.receive.amount);
        assertEquals("5000000", q.receive.min);
        assertEquals("USDT@base", q.receive.asset);
        assertFees(q.fees, "USDC@base", "0", "0", "0", true, "0",
            Map.of("platform", "0", "network", "0", "route", "0", "total", "0"));
        assertEquals("2026-01-01T00:00:00.0000000+00:00", q.expiresAt);
    }

    @Test
    void zeroSlippageIsSentAsZero() {
        FixtureTransport t = new FixtureTransport().serve("assets")
            .serve("POST /vault/v1/quote/swap", fixture("quote_swap_dry").getAsJsonObject("response"));
        readWallet(t).quoteSwap("USDC@base", "USDT@base", "5", 0);
        JsonObject body = JsonParser.parseString(t.last("POST", "/vault/v1/quote/swap").body).getAsJsonObject();
        assertEquals(0, body.get("slippage_bps").getAsInt());
    }

    // ── non-dry quotes: the money path up to the co-sign ─────────────────────

    @Test
    void quoteParsesEveryNonDryFixture() {
        Types.Quote w = new Types.Quote(fixture("quote_withdraw").getAsJsonObject("response").getAsJsonObject("body"));
        assertEquals("mv_1", w.movementId);
        assertEquals(2, w.sources);
        assertEquals("exact_out", w.mode);
        assertLeg(w.send, "10000000", "USDC@base");
        assertLeg(w.debit, "10025000", "USDC@base");
        assertEquals("10000000", w.receive.amount);
        assertEquals("10000000", w.receive.min);
        assertFees(w.fees, "USDC@base", "25000", "0", "0", false, "25000",
            Map.of("platform", "0.025", "network", "0", "route", "0", "total", "0.025"));
        assertEquals("2026-01-01T00:00:00.0000000+00:00", w.expiresAt);

        Types.Quote ti = new Types.Quote(fixture("quote_withdraw_total_in").getAsJsonObject("response").getAsJsonObject("body"));
        assertEquals("mv_2", ti.movementId);
        assertEquals(2, ti.sources);
        assertEquals("total_in", ti.mode);
        assertLeg(ti.send, "9975062", "USDC@base");
        assertLeg(ti.debit, "10000000", "USDC@base");
        assertEquals("9975062", ti.receive.amount);
        assertEquals("9975062", ti.receive.min);
        assertFees(ti.fees, "USDC@base", "24938", "0", "0", false, "24938",
            Map.of("platform", "0.024938", "network", "0", "route", "0", "total", "0.024938"));

        Types.Quote s = new Types.Quote(fixture("quote_swap").getAsJsonObject("response").getAsJsonObject("body"));
        assertEquals("mv_3", s.movementId);
        assertEquals(1, s.sources);
        assertEquals("exact_in", s.mode);
        assertLeg(s.send, "5000000", "USDC@base");
        assertLeg(s.debit, "5000000", "USDC@base");
        assertEquals("USDT@base", s.receive.asset);
        assertFees(s.fees, "USDC@base", "0", "0", "0", true, "0",
            Map.of("platform", "0", "network", "0", "route", "0", "total", "0"));
    }

    /**
     * withdraw() sends exactly the recorded exact_out request with an Idempotency-Key, passes the
     * echo check against the recorded answer, commits once per source, and surfaces the recorded
     * sign/begin rejection as a typed error because the movement is still pending.
     */
    @Test
    void withdrawExactOut() {
        FixtureTransport t = new FixtureTransport().serve("assets").serve("quote_withdraw")
            .serve("POST /vault/v1/movements/mv_1/sign/begin", fixture("sign_begin_error").getAsJsonObject("response"))
            .raw("GET /vault/v1/movements/mv_1", 200, movementWithStatus("mv_1", "pending"));
        PaymosException ex = assertThrows(PaymosException.class,
            () -> fullWallet(t).withdraw("USDC@base", "10", TO, "exact_out", null, "job-1"));
        assertEquals("commitments are required", ex.getMessage());
        assertEquals(400, ex.status());

        Http.Request quote = t.last("POST", "/vault/v1/quote/withdraw");
        assertSentBodyMatches("quote_withdraw", quote);
        assertEquals("job-1", quote.headers.get("idempotency-key"));

        JsonObject begin = JsonParser.parseString(t.last("POST", "/vault/v1/movements/mv_1/sign/begin").body).getAsJsonObject();
        assertEquals(2, begin.getAsJsonArray("commitments").size(), "one commitment per source");
        assertFalse(t.sentTo("/sign/aggregate"));
    }

    @Test
    void withdrawTotalIn() {
        FixtureTransport t = new FixtureTransport().serve("assets").serve("quote_withdraw_total_in")
            .serve("POST /vault/v1/movements/mv_2/sign/begin", fixture("sign_begin_error").getAsJsonObject("response"))
            .raw("GET /vault/v1/movements/mv_2", 200, movementWithStatus("mv_2", "pending"));
        assertThrows(PaymosException.class,
            () -> fullWallet(t).withdraw("USDC@base", "10", TO, "total_in", null, null));

        Http.Request quote = t.last("POST", "/vault/v1/quote/withdraw");
        assertSentBodyMatches("quote_withdraw_total_in", quote);
        assertNotNull(quote.headers.get("idempotency-key"), "a generated key when the caller gives none");
        // The debit echo passed (send is total minus fees and was deliberately not pinned), so the
        // co-sign began: two sources, two commitments.
        JsonObject begin = JsonParser.parseString(t.last("POST", "/vault/v1/movements/mv_2/sign/begin").body).getAsJsonObject();
        assertEquals(2, begin.getAsJsonArray("commitments").size());
    }

    /** The recorded catalog with USDC@base listed again at the end, with 18 decimals. */
    private static String catalogWithUsdcTwice() {
        JsonArray cat = fixture("assets").getAsJsonObject("response").getAsJsonArray("body").deepCopy();
        JsonObject again = cat.get(0).getAsJsonObject().deepCopy();
        again.addProperty("decimals", 18);
        again.addProperty("fingerprint", "00".repeat(32));
        cat.add(again);
        return cat.toString();
    }

    /** One label listed twice: the server resolves it to the FIRST entry, and so must decimals. */
    @Test
    void aRepeatedLabelTakesTheFirstEntrysDecimals() {
        // Amount conversion: 7 fractional digits is too many for the first entry's 6.
        FixtureTransport local = new FixtureTransport().raw("GET /vault/v1/assets", 200, catalogWithUsdcTwice());
        assertThrows(PaymosException.class, () -> readWallet(local).quoteWithdraw("USDC@base", "10.1234567", TO, "exact_out"));
        assertTrue(local.sent.stream().noneMatch(r -> r.method.equals("POST")), "refused before anything was sent");

        // Echo check: "10" at 6 decimals is the recorded 10000000, so the echo passes and the
        // co-sign begins. At 18 decimals it would be 10^19 and refuse as a mismatch.
        FixtureTransport t = new FixtureTransport().raw("GET /vault/v1/assets", 200, catalogWithUsdcTwice())
            .serve("quote_withdraw")
            .serve("POST /vault/v1/movements/mv_1/sign/begin", fixture("sign_begin_error").getAsJsonObject("response"))
            .raw("GET /vault/v1/movements/mv_1", 200, movementWithStatus("mv_1", "pending"));
        PaymosException ex = assertThrows(PaymosException.class,
            () -> fullWallet(t).withdraw("USDC@base", "10", TO, "exact_out", "10.025", null));
        assertEquals("commitments are required", ex.getMessage(), "the echo and the maxDebit cap passed at 6 decimals");
    }

    @Test
    void maxDebitBelowTheQuoteSignsNothing() {
        FixtureTransport t = new FixtureTransport().serve("assets").serve("quote_withdraw");
        PaymosException ex = assertThrows(PaymosException.class,
            () -> fullWallet(t).withdraw("USDC@base", "10", TO, "exact_out", "10.02", null));
        assertTrue(ex.getMessage().contains("10025000"), ex.getMessage());
        assertFalse(t.sentTo("/sign/begin"), "refused before a commitment existed");
    }

    /**
     * The recorded sign/begin answer carries placeholder crypto: its package does not bind to its
     * disclosure and its nonce is two bytes. The SDK must parse it all the way to the blind-sign
     * guard — and the guard must refuse it before a single share exists.
     */
    @Test
    void swapReachesTheBlindSignGuardAndItRefusesThePlaceholders() {
        FixtureTransport t = new FixtureTransport().serve("assets").serve("quote_swap").serve("sign_begin");
        PaymosException ex = assertThrows(PaymosException.class,
            () -> fullWallet(t).swap("USDC@base", "USDT@base", "5", 50, null, null, "swap-1"));
        assertTrue(ex.getMessage().startsWith("co-sign refused"), ex.getMessage());

        Http.Request quote = t.last("POST", "/vault/v1/quote/swap");
        assertSentBodyMatches("quote_swap", quote);
        assertEquals("swap-1", quote.headers.get("idempotency-key"));
        JsonObject begin = JsonParser.parseString(t.last("POST", "/vault/v1/movements/mv_3/sign/begin").body).getAsJsonObject();
        assertEquals(1, begin.getAsJsonArray("commitments").size());
        assertFalse(t.sentTo("/sign/aggregate"), "nothing was signed");
    }

    @Test
    void minReceiveAboveTheGuaranteeSignsNothing() {
        FixtureTransport t = new FixtureTransport().serve("assets").serve("quote_swap");
        assertThrows(PaymosException.SlippageExceeded.class,
            () -> fullWallet(t).swap("USDC@base", "USDT@base", "5", 50, "5.01", null, null));
        assertFalse(t.sentTo("/sign/begin"));
    }

    @Test
    void signAggregateParses() {
        JsonObject ok = fixture("sign_aggregate").getAsJsonObject("response").getAsJsonObject("body");
        Wallet.checkAggregate(ok); // ok:true — no throw
        assertEquals("processing", ok.get("status").getAsString());

        // The same ok:false envelope, whether it arrives under a 200 …
        JsonObject err = fixture("sign_aggregate_error").getAsJsonObject("response").getAsJsonObject("body");
        PaymosException ex = assertThrows(PaymosException.class, () -> Wallet.checkAggregate(err));
        assertEquals("token and shares are required", ex.getMessage());

        // … or, as recorded, under a 400 through the transport.
        FixtureTransport t = new FixtureTransport().serve("sign_aggregate_error");
        Http http = new Http(BASE, "vk_live_test", null, t);
        PaymosException viaHttp = assertThrows(PaymosException.class,
            () -> http.post("/vault/v1/movements/mv_3/sign/aggregate", "{\"token\":\"\",\"shares\":[]}", null));
        assertEquals(PaymosException.class, viaHttp.getClass());
        assertEquals(400, viaHttp.status());
        assertEquals("token and shares are required", viaHttp.getMessage());
    }

    // ── status vocabulary ────────────────────────────────────────────────────

    @Test
    void everyServerStatusIsClassifiedLikePython() {
        JsonObject vocab = fixture("vocabulary");
        Set<String> all = new HashSet<>();
        for (String list : new String[] { "movement_statuses", "sign_statuses" })
            for (JsonElement s : vocab.getAsJsonArray(list)) all.add(s.getAsString());
        assertFalse(all.isEmpty());
        for (String s : all) {
            assertEquals(PY_TERMINAL.contains(s), Wallet.isTerminal(s), "terminal? " + s);
            assertEquals(PY_PROGRESSED.contains(s), Wallet.isProgressed(s), "progressed? " + s);
        }
        // No word the server never sends ("signed", "relaying", "settling" …) may drive a decision.
        Set<String> movement = new HashSet<>();
        for (JsonElement s : vocab.getAsJsonArray("movement_statuses")) movement.add(s.getAsString());
        assertTrue(movement.containsAll(Wallet.TERMINAL), "terminal set uses only server words: " + Wallet.TERMINAL);
        assertTrue(movement.containsAll(Wallet.PROGRESSED), "progressed set uses only server words: " + Wallet.PROGRESSED);
    }

    /** A rejected sign/begin converges only when the movement really is past the co-sign. */
    @Test
    void signBeginRejectionConvergesOnlyOnProgressedStatuses() {
        for (JsonElement el : fixture("vocabulary").getAsJsonArray("movement_statuses")) {
            String status = el.getAsString();
            FixtureTransport t = new FixtureTransport().serve("assets").serve("quote_swap")
                .serve("POST /vault/v1/movements/mv_3/sign/begin", fixture("sign_begin_error").getAsJsonObject("response"))
                .raw("GET /vault/v1/movements/mv_3", 200, movementWithStatus("mv_3", status));
            Wallet w = fullWallet(t);
            if (PY_PROGRESSED.contains(status)) {
                Types.Movement mv = w.swap("USDC@base", "USDT@base", "5", 50, null, null, "k");
                assertEquals(status, mv.status, "converged on " + status);
            } else {
                PaymosException ex = assertThrows(PaymosException.class,
                    () -> w.swap("USDC@base", "USDT@base", "5", 50, null, null, "k"), status);
                assertEquals("commitments are required", ex.getMessage(), status);
            }
            assertFalse(t.sentTo("/sign/aggregate"), status);
        }
    }

    @Test
    void waitPollsThroughNonTerminalStatuses() {
        List<String> seq = new ArrayList<>(List.of("pending", "processing", "completed"));
        Http.Transport t = r -> new Http.Response(200, movementWithStatus("mv_3", seq.size() > 1 ? seq.remove(0) : seq.get(0)), null);
        Wallet w = new Wallet(VaultSecret.pack("vk_live_test", 1, null), BASE, null, t);
        assertEquals("completed", w.wait("mv_3", Duration.ofSeconds(5), Duration.ofMillis(1)).status);
    }

    // ── errors ───────────────────────────────────────────────────────────────

    @Test
    void error400InvalidMode() {
        FixtureTransport t = new FixtureTransport().serve("assets").serve("error_400");
        PaymosException ex = assertThrows(PaymosException.class,
            () -> readWallet(t).quoteWithdraw("USDC@base", "10", TO, "exact-out"));
        assertEquals(PaymosException.class, ex.getClass());
        assertEquals(400, ex.status());
        assertEquals("invalid mode", ex.getMessage());
        JsonObject body = JsonParser.parseString(t.last("POST", "/vault/v1/quote/withdraw").body).getAsJsonObject();
        assertEquals("exact-out", body.get("mode").getAsString());
    }

    @Test
    void error400BodyNotJson() {
        FixtureTransport t = new FixtureTransport().serve("error_400_body");
        Http http = new Http(BASE, "vk_live_test", null, t);
        PaymosException ex = assertThrows(PaymosException.class,
            () -> http.post("/vault/v1/quote/withdraw", "{not json", null));
        assertEquals(PaymosException.class, ex.getClass());
        assertEquals(400, ex.status());
        assertEquals("invalid request — the body must be JSON matching this endpoint", ex.getMessage());
    }

    @Test
    void error401() {
        FixtureTransport t = new FixtureTransport().serve("error_401");
        PaymosException ex = assertThrows(PaymosException.Auth.class, () -> readWallet(t).balances());
        assertEquals(401, ex.status());
        assertEquals("invalid or missing API key", ex.getMessage());
    }

    @Test
    void error403() {
        FixtureTransport t = new FixtureTransport().serve("assets").serve("error_403");
        PaymosException ex = assertThrows(PaymosException.Forbidden.class,
            () -> fullWallet(t).withdraw("USDC@base", "10", TO, "exact_out", null, null));
        assertEquals(403, ex.status());
        assertEquals("this key lacks the required scope", ex.getMessage());
        assertSentBodyMatches("error_403", t.last("POST", "/vault/v1/quote/withdraw"));
    }

    @Test
    void error404Movement() {
        FixtureTransport t = new FixtureTransport().serve("error_404_movement");
        PaymosException ex = assertThrows(PaymosException.class, () -> readWallet(t).movement("does-not-exist"));
        assertEquals(PaymosException.class, ex.getClass(), "404 has no type of its own");
        assertEquals(404, ex.status());
        assertEquals("movement not found", ex.getMessage());
    }

    @Test
    void error404Path() {
        FixtureTransport t = new FixtureTransport().serve("error_404_path");
        Http http = new Http(BASE, "vk_live_test", null, t);
        PaymosException ex = assertThrows(PaymosException.class, () -> http.get("/vault/v1/no-such-endpoint", null));
        assertEquals(PaymosException.class, ex.getClass());
        assertEquals(404, ex.status());
        assertEquals("not found", ex.getMessage());
    }

    @Test
    void error409Idempotency() {
        FixtureTransport t = new FixtureTransport().serve("assets").serve("error_409_idempotency");
        PaymosException ex = assertThrows(PaymosException.Conflict.class,
            () -> fullWallet(t).withdraw("USDC@base", "11", TO, "exact_out", null, "reused"));
        assertEquals(409, ex.status());
        assertEquals("idempotency key reused with a different request", ex.getMessage());
        assertSentBodyMatches("error_409_idempotency", t.last("POST", "/vault/v1/quote/withdraw"));
    }

    @Test
    void signBeginError() {
        FixtureTransport t = new FixtureTransport().serve("sign_begin_error");
        Http http = new Http(BASE, "vk_live_test", null, t);
        PaymosException ex = assertThrows(PaymosException.class,
            () -> http.post("/vault/v1/movements/mv_3/sign/begin", "{\"commitments\":[]}", null));
        assertEquals(400, ex.status());
        assertEquals("commitments are required", ex.getMessage());
    }

    @Test
    void anHtml404FromAProxyIsATypedError() {
        String html = "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
            + "<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>";
        FixtureTransport t = new FixtureTransport().raw("GET /vault/v1/assets", 404, html);
        PaymosException ex = assertThrows(PaymosException.class, () -> readWallet(t).assets());
        assertEquals(PaymosException.class, ex.getClass());
        assertEquals(404, ex.status());
        assertTrue(ex.getMessage().contains("not JSON"), ex.getMessage());
        assertTrue(ex.getMessage().contains("404"), ex.getMessage());
    }

    @Test
    void anHtml200IsATypedErrorNotAnEmptyCatalog() {
        // The failure this whole contract exists for: a page that is not the API, read as "no assets".
        FixtureTransport t = new FixtureTransport().raw("GET /vault/v1/assets", 200, "<html><body>Wallet</body></html>");
        PaymosException ex = assertThrows(PaymosException.class, () -> readWallet(t).assets());
        assertEquals(200, ex.status());
        assertTrue(ex.getMessage().contains("not JSON"), ex.getMessage());
    }

    @Test
    void anObjectWhereTheArrayBelongsIsATypedError() {
        FixtureTransport t = new FixtureTransport().raw("GET /vault/v1/assets", 200, "{\"assets\":[]}");
        PaymosException ex = assertThrows(PaymosException.class, () -> readWallet(t).assets());
        assertTrue(ex.getMessage().contains("JSON array"), ex.getMessage());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /** movement.json with its id and status swapped — the recorded shape, a chosen state. */
    private static String movementWithStatus(String id, String status) {
        JsonObject body = fixture("movement").getAsJsonObject("response").getAsJsonObject("body").deepCopy();
        body.addProperty("id", id);
        body.addProperty("status", status);
        return body.toString();
    }

    private static void assertLeg(Types.Amount a, String amount, String asset) {
        assertEquals(amount, a.amount);
        assertEquals(asset, a.asset);
    }

    private static void assertFees(Types.Fees f, String asset, String platform, String network, String route,
                                   boolean estimate, String total, Map<String, String> usd) {
        assertNotNull(f);
        assertEquals(asset, f.asset);
        assertEquals(platform, f.platform);
        assertEquals(network, f.network);
        assertNotNull(f.route);
        assertEquals(route, f.route.amount);
        assertEquals(estimate, f.route.estimate);
        assertEquals(total, f.total);
        assertEquals(usd, f.usd);
    }
}
