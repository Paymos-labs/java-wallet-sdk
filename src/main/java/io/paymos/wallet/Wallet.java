package io.paymos.wallet;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import io.paymos.wallet.Types.Asset;
import io.paymos.wallet.Types.Balance;
import io.paymos.wallet.Types.Movement;
import io.paymos.wallet.Types.Quote;

/**
 * The entry point, ported from the Python SDK via the TypeScript, Rust, .NET, Go and Ruby ones.
 * Same methods, same guarantees, same refusals.
 *
 * <p>Everything that moves money goes through a 2-of-2 co-sign in which this process holds one
 * half of the key and never sends it anywhere. The server cannot sign alone and neither can
 * this — which is only worth anything if this side refuses to sign things it has not checked:
 *
 * <ul>
 *   <li>the quote must echo what was approved — a decimals bug or a server answering with other
 *       numbers changes them, and the numbers are compared before a commitment
 *   <li>the debit may be capped — for an exact_out payout the input side is computed by the
 *       server, so {@code maxDebit} is the caller's ceiling
 *   <li>never blind-sign — the server discloses each message, this side recomputes the digest
 *       and refuses unless the package binds to it, signs from this vault, moves no more than the
 *       approved debit, and moves the token whose fingerprint the catalog publishes for the send
 *       asset
 * </ul>
 *
 * Any of those failing throws before a single signature share exists.
 *
 * <p>What this does not check: the transfer's recipient. The route's deposit address is chosen by
 * the server and taken as given. And "the approved debit" is only as tight as the approval: for an
 * exact_out payout the server computes it, so an unattended payout should pass {@code maxDebit}.
 *
 * <p>The fingerprint comes from the same server that builds the messages. Checking against it
 * catches a server bug or a compromised signing path, not a server compromised end to end — that
 * one could publish a false fingerprint too. For a trust anchor the server does not control, pin
 * the fingerprints out of band with {@code pinnedFingerprints}.
 */
public final class Wallet {
    /**
     * A movement in any of these states has already been signed; a retry must not sign again.
     * These are the words the server actually sends (sdk/contract/fixtures/vocabulary.json) and
     * exactly Python's set. "failed" is deliberately absent: a sign/begin rejection on a failed
     * movement is an error the caller must see, not a retry that quietly converged.
     */
    static final Set<String> PROGRESSED = Set.of("processing", "completed", "refunded");

    /** A movement is settled (no more polling) once it reaches one of these. */
    static final Set<String> TERMINAL = Set.of("completed", "failed", "refunded", "expired", "cancelled");

    private static final String DEFAULT_BASE_URL = "https://wallet.paymos.io";

    // transient: a reflective serializer handed the wallet (Gson, a logger's JSON layout) skips the
    // secret and the transport, which carries the API key.
    private final transient VaultSecret secret;
    private final transient Http http;
    private volatile List<Asset> catalogCache;
    private volatile Map<String, Asset> assetCache;
    /** label → lowercase fingerprints the caller pinned. A pinned label ignores what /assets says. */
    private final Map<String, Set<String>> pinnedFingerprints;

    public Wallet(String secret) {
        this(secret, null, null);
    }

    public Wallet(String secret, String baseUrl, Duration timeout) {
        this(secret, baseUrl, timeout, (Map<String, ? extends Collection<String>>) null);
    }

    /**
     * {@code pinnedFingerprints} maps an asset label to the fingerprint(s) you trust for it — the
     * lowercase hex sha256 of the raw token id, obtained out of band, e.g.
     * {@code Map.of("USDC@base", List.of("a42c7e46…"))}. For a pinned label the co-sign accepts only
     * those values and ignores what the server's /assets publishes; an unpinned label is checked
     * against the published set. Null or empty pins nothing.
     */
    public Wallet(String secret, String baseUrl, Duration timeout,
                  Map<String, ? extends Collection<String>> pinnedFingerprints) {
        this(secret, baseUrl, timeout, null, pinnedFingerprints);
    }

    /** Tests hand in a transport that answers from the contract fixtures instead of a socket. */
    Wallet(String secret, String baseUrl, Duration timeout, Http.Transport transport) {
        this(secret, baseUrl, timeout, transport, null);
    }

    Wallet(String secret, String baseUrl, Duration timeout, Http.Transport transport,
           Map<String, ? extends Collection<String>> pinnedFingerprints) {
        this.pinnedFingerprints = normalizePins(pinnedFingerprints);
        this.secret = VaultSecret.parse(secret);
        if (baseUrl == null || baseUrl.isEmpty()) baseUrl = System.getenv("PAYMOS_BASE_URL");
        if (baseUrl == null || baseUrl.isEmpty()) baseUrl = DEFAULT_BASE_URL;
        this.http = new Http(baseUrl, this.secret.apiKey, timeout, transport);
    }

    /** Reads PAYMOS_VAULT_SECRET, the way a deployed process is configured. */
    public static Wallet fromEnv() {
        String secret = System.getenv("PAYMOS_VAULT_SECRET");
        if (secret == null || secret.isEmpty())
            throw new PaymosException("PAYMOS_VAULT_SECRET is not set");
        return new Wallet(secret);
    }

    // ── reads ────────────────────────────────────────────────────────────────

    // /assets and /balances answer a BARE JSON array. An earlier build read {"assets": [...]},
    // got an empty list from every real server, and then refused every quote as "unknown asset".

    public List<Asset> assets() {
        List<Asset> out = new ArrayList<>();
        for (JsonElement a : array(http.get("/vault/v1/assets", null), "/vault/v1/assets"))
            out.add(new Asset(object(a, "an asset")));
        return out;
    }

    public List<Balance> balances() {
        List<Balance> out = new ArrayList<>();
        for (JsonElement b : array(http.get("/vault/v1/balances", null), "/vault/v1/balances"))
            out.add(new Balance(object(b, "a balance")));
        return out;
    }

    public Movement movement(String movementId) {
        return new Movement(object(http.get("/vault/v1/movements/" + urlPath(movementId), null), "a movement"));
    }

    /**
     * A page of the caller's movement history (newest first, summary rows without fee legs) and
     * the next cursor; pass it back for the next page (null when exhausted). The server speaks
     * keyset pagination: items + next_cursor.
     */
    public Map.Entry<List<Movement>, String> movements(int limit, String cursor) {
        Map<String, String> q = new LinkedHashMap<>();
        q.put("limit", Integer.toString(limit));
        q.put("cursor", cursor);
        JsonObject body = object(http.get("/vault/v1/movements", q), "a movements page");
        List<Movement> items = new ArrayList<>();
        if (body.has("items"))
            for (JsonElement m : array(body.get("items"), "a movements page's items"))
                items.add(new Movement(object(m, "a movement")));
        // The last page omits next_cursor. Map.entry() rejects a null value, so it is not used here:
        // it turned the end of history into a NullPointerException.
        String next = Types.strOrNull(body, "next_cursor");
        return new AbstractMap.SimpleImmutableEntry<>(items, next);
    }

    /** Polls until the movement leaves the states that are still in flight. */
    public Movement wait(String movementId, Duration timeout, Duration interval) {
        if (timeout == null) timeout = Duration.ofMinutes(5);
        if (interval == null) interval = Duration.ofSeconds(2);
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            Movement mv = movement(movementId);
            if (isTerminal(mv.status)) return mv;
            if (System.nanoTime() >= deadline)
                throw new PaymosException("timed out waiting for movement " + movementId);
            try {
                Thread.sleep(interval.toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new PaymosException("interrupted waiting for movement " + movementId);
            }
        }
    }

    // ── quotes ───────────────────────────────────────────────────────────────

    /**
     * A dry preview. Nothing is created and nothing is signed.
     *
     * <p>{@code amount} is a HUMAN decimal string in the send asset ("100", "0.5"); the server
     * scales it by the asset's decimals. The quote comes back in raw integer strings. Never pass
     * {@link Amounts#parseUnits} output here: "10000" is ten thousand of the asset, not 0.01.
     */
    public Quote quoteSwap(String send, String receive, String amount, int slippageBps) {
        validateAmount(amount, send);
        decimalsOf(receive);
        return quote("/vault/v1/quote/swap", swapBody(send, receive, amount, slippageBps), true, null);
    }

    /**
     * A dry preview. Nothing is created and nothing is signed.
     *
     * <p>{@code amount} is a HUMAN decimal string in {@code asset} ("25", "0.01"); the server scales
     * it. The quote comes back in raw integer strings. Never pass {@link Amounts#parseUnits} output
     * here.
     */
    public Quote quoteWithdraw(String asset, String amount, String to, String mode) {
        validateAmount(amount, asset);
        JsonObject body = new JsonObject();
        body.addProperty("asset", asset);
        body.addProperty("amount", amount);
        body.addProperty("to", to);
        body.addProperty("mode", mode == null || mode.isEmpty() ? "exact_out" : mode);
        return quote("/vault/v1/quote/withdraw", body, true, null);
    }

    // ── money ────────────────────────────────────────────────────────────────

    /**
     * Full-key secrets only. Creates a real movement and drives the 2-of-2 co-sign.
     *
     * <p>{@code amount}, {@code minReceive} and {@code maxDebit} are HUMAN decimal strings ("100",
     * "99.5") that the server scales by each asset's decimals — never {@link Amounts#parseUnits}
     * output, which would be read as that many whole units: {@code swap("USDC@base", "USDT@base",
     * "10000", …)} swaps ten thousand USDC.
     *
     * <p>{@code idempotencyKey}: a durable key (a payout or job id) under which a retry replays the
     * same movement; null gets a fresh key per call, so a retry is a new payment. An empty or blank
     * key is refused.
     */
    public Movement swap(String send, String receive, String amount, int slippageBps,
                         String minReceive, String maxDebit, String idempotencyKey) {
        requireShare("swap");
        String key = idempotencyKeyOf(idempotencyKey);
        int sendDec = validateAmount(amount, send);
        int recvDec = decimalsOf(receive);

        Quote q = quote("/vault/v1/quote/swap", swapBody(send, receive, amount, slippageBps), false, key);

        if (minReceive != null && !minReceive.isEmpty()) {
            BigInteger floor = new BigInteger(Amounts.parseUnits(minReceive, recvDec));
            if (rawInt(q.receive.min).compareTo(floor) < 0)
                throw new PaymosException.SlippageExceeded(
                    "guaranteed receive " + q.receive.min + " is below the requested minimum " + floor
                        + " (" + minReceive + " " + receive + ")", null);
        }
        // A swap is exact_in, so the send leg must be exactly what was approved.
        verifyQuoteEcho(q, send, receive, new BigInteger(Amounts.parseUnits(amount, sendDec)), null, null);
        enforceMaxDebit(q, maxDebit, sendDec);
        cosign(q);
        return movement(requireMovementId(q));
    }

    /**
     * Full-key secrets only. Creates a real payout movement and drives the 2-of-2 co-sign.
     *
     * <p>{@code amount} and {@code maxDebit} are HUMAN decimal strings ("25", "0.01") that the
     * server scales by the asset's decimals — never {@link Amounts#parseUnits} output.
     * {@code withdraw("USDC@base", "10000", …)}, which is what {@code parseUnits("0.01", 6)}
     * returns, pays out ten thousand USDC; the SDK and the server agree on that number, so no check
     * can tell it from an intended one.
     *
     * <p>{@code idempotencyKey}: a durable key (a payout or job id) under which a retry replays the
     * same movement; null gets a fresh key per call, so a retry is a new payment. An empty or blank
     * key is refused.
     */
    public Movement withdraw(String asset, String amount, String to, String mode,
                             String maxDebit, String idempotencyKey) {
        requireShare("withdraw");
        String key = idempotencyKeyOf(idempotencyKey);
        int dec = validateAmount(amount, asset);
        if (mode == null || mode.isEmpty()) mode = "exact_out";

        JsonObject body = new JsonObject();
        body.addProperty("asset", asset);
        body.addProperty("amount", amount);
        body.addProperty("to", to);
        body.addProperty("mode", mode);
        Quote q = quote("/vault/v1/quote/withdraw", body, false, key);

        // A withdraw is same-asset. For exact_out the approved amount is the guaranteed OUT; for
        // total_in it is the total DEBIT — and the send leg is total minus fees, so pinning send
        // would false-fail every time.
        BigInteger expected = new BigInteger(Amounts.parseUnits(amount, dec));
        if (mode.equals("total_in")) verifyQuoteEcho(q, asset, asset, null, null, expected);
        else verifyQuoteEcho(q, asset, asset, null, expected, null);

        enforceMaxDebit(q, maxDebit, dec);
        cosign(q);
        return movement(requireMovementId(q));
    }

    // ── internals ────────────────────────────────────────────────────────────

    /**
     * The swap request. {@code slippage_bps} goes out exactly as given, the way Python sends it: an
     * earlier build turned 0 into 50, so a caller who asked for no slippage got half a percent. The
     * server clamps to 0..5000. {@code mode} is always exact_in — the only mode the swap surface has.
     */
    private static JsonObject swapBody(String send, String receive, String amount, int slippageBps) {
        JsonObject body = new JsonObject();
        body.addProperty("send", send);
        body.addProperty("receive", receive);
        body.addProperty("amount", amount);
        body.addProperty("mode", "exact_in");
        body.addProperty("slippage_bps", slippageBps);
        return body;
    }

    private void requireShare(String op) {
        if (!secret.hasShare())
            throw new PaymosException(op + " needs a full-scope secret: this one carries no co-signing share");
    }

    /** The catalog as the server listed it, fetched once. One label may appear more than once. */
    private List<Asset> catalog() {
        List<Asset> cache = catalogCache;
        if (cache == null) {
            cache = Collections.unmodifiableList(assets());
            catalogCache = cache;
        }
        return cache;
    }

    private Map<String, Asset> assetMap() {
        Map<String, Asset> cache = assetCache;
        if (cache == null) {
            cache = new HashMap<>();
            // One label can be listed twice; the server resolves a label to its FIRST catalog entry,
            // so decimals come from that one too. (The fingerprint check takes the whole set.)
            for (Asset a : catalog()) cache.putIfAbsent(a.asset, a);
            assetCache = cache;
        }
        return cache;
    }

    private static Map<String, Set<String>> normalizePins(Map<String, ? extends Collection<String>> pins) {
        if (pins == null || pins.isEmpty()) return Map.of();
        Map<String, Set<String>> out = new HashMap<>();
        for (Map.Entry<String, ? extends Collection<String>> e : pins.entrySet()) {
            if (e.getKey() == null || e.getValue() == null || e.getValue().isEmpty())
                throw new PaymosException("pinnedFingerprints: " + e.getKey() + " pins no fingerprint");
            Set<String> set = new HashSet<>();
            for (String fp : e.getValue()) {
                if (fp == null || fp.isBlank())
                    throw new PaymosException("pinnedFingerprints: an empty fingerprint for " + e.getKey());
                set.add(fp.trim().toLowerCase(Locale.ROOT));
            }
            out.put(e.getKey(), Set.copyOf(set));
        }
        return Map.copyOf(out);
    }

    private int decimalsOf(String asset) {
        Asset found = assetMap().get(asset);
        if (found == null) throw new PaymosException("unknown asset: " + asset);
        return found.decimals;
    }

    private int validateAmount(String amount, String asset) {
        int dec = decimalsOf(asset);
        Amounts.parseUnits(amount, dec); // throws on a bad decimal before anything reaches the server
        return dec;
    }

    private Quote quote(String path, JsonObject body, boolean dry, String idempotencyKey) {
        body.addProperty("dry", dry);
        Map<String, String> headers = idempotencyKey == null
            ? null : Map.of("idempotency-key", idempotencyKey);
        return new Quote(object(http.post(path, body.toString(), headers), "a quote"));
    }

    private static String requireMovementId(Quote q) {
        if (q.movementId == null || q.movementId.isEmpty())
            throw new PaymosException("quote created no movement — cannot sign a dry preview");
        return q.movementId;
    }

    /** Drives the 2-of-2 round: commit per source, verify the disclosure, sign, aggregate. */
    private void cosign(Quote q) {
        String mid = requireMovementId(q);
        int n = q.sources == null ? 0 : q.sources;
        if (n < 1) throw new PaymosException("quote is missing its source count — cannot co-sign");

        JsonObject kp = clientKeyPackage();
        signerOf(kp); // no group key, no signer check — refused before a commitment exists
        List<JsonObject> commitments = new ArrayList<>();
        List<JsonObject> nonces = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            JsonObject[] pair = NativeCore.commit(kp);
            commitments.add(pair[0]);
            nonces.add(pair[1]);
        }

        JsonObject begin;
        try {
            JsonObject beginBody = new JsonObject();
            JsonArray arr = new JsonArray();
            commitments.forEach(arr::add);
            beginBody.add("commitments", arr);
            begin = object(http.post("/vault/v1/movements/" + mid + "/sign/begin", beginBody.toString(), null),
                "a sign/begin answer");
        } catch (PaymosException e) {
            // An ambiguous failure after the server already progressed the movement is not a
            // reason to sign it a second time.
            Movement mv = movement(mid);
            if (isProgressed(mv.status)) return;
            throw e;
        }

        String token = Types.strOrNull(begin, "token");
        if (token == null || token.isEmpty())
            throw new PaymosException("co-sign protocol mismatch: sign/begin returned no session token");
        JsonArray packages = begin.has("signing_packages") && begin.get("signing_packages").isJsonArray()
            ? begin.getAsJsonArray("signing_packages") : new JsonArray();
        if (packages.size() != n)
            throw new PaymosException(
                "co-sign protocol mismatch: expected " + n + " signing packages, got " + packages.size());

        verifySigningDisclosure(q, packages, begin.get("messages"), kp, sendAssetFingerprints(q));

        JsonArray shares = new JsonArray();
        for (int i = 0; i < packages.size(); i++)
            shares.add(NativeCore.sign(packages.get(i).getAsJsonObject(), nonces.get(i), kp));
        JsonObject aggBody = new JsonObject();
        aggBody.addProperty("token", token);
        aggBody.add("shares", shares);
        // A non-2xx aggregate ({"ok":false,"status":"failed","error":…} under a 400) is raised by
        // the transport. This covers the same envelope arriving under a 200. Either way a round-2
        // failure always propagates — it is never converged on.
        checkAggregate(object(http.post("/vault/v1/movements/" + mid + "/sign/aggregate", aggBody.toString(), null),
            "a sign/aggregate answer"));
    }

    /** Throws unless the sign/aggregate answer says {@code "ok": true}. */
    static void checkAggregate(JsonObject res) {
        JsonElement ok = res.get("ok");
        boolean signed = ok != null && ok.isJsonPrimitive() && ok.getAsJsonPrimitive().isBoolean() && ok.getAsBoolean();
        if (!signed) {
            String msg = Types.strOrNull(res, "error");
            throw new PaymosException(msg == null || msg.isEmpty() ? "sign failed" : msg);
        }
    }

    /** Terminal: {@link #wait} stops polling. Package-private so the vocabulary test can ask. */
    static boolean isTerminal(String status) {
        return TERMINAL.contains(status);
    }

    /** Already past the co-sign: a retried sign/begin rejection converges instead of failing. */
    static boolean isProgressed(String status) {
        return PROGRESSED.contains(status);
    }

    private static JsonObject object(JsonElement e, String what) {
        if (e == null || !e.isJsonObject())
            throw new PaymosException("unexpected response: expected " + what + " as a JSON object, got "
                + kind(e));
        return e.getAsJsonObject();
    }

    private static JsonArray array(JsonElement e, String what) {
        if (e == null || !e.isJsonArray())
            throw new PaymosException("unexpected response: expected " + what + " as a JSON array, got "
                + kind(e));
        return e.getAsJsonArray();
    }

    private static String kind(JsonElement e) {
        if (e == null || e.isJsonNull()) return "nothing";
        if (e.isJsonObject()) return "an object";
        if (e.isJsonArray()) return "an array";
        return "a " + (e.getAsJsonPrimitive().isString() ? "string" : "scalar");
    }

    private JsonObject clientKeyPackage() {
        if (secret.share == null)
            throw new PaymosException("this secret carries no co-signing share");
        return JsonParser.parseString(secret.share).getAsJsonObject();
    }

    private static BigInteger rawInt(String raw) {
        try {
            return new BigInteger(raw);
        } catch (NumberFormatException e) {
            throw new PaymosException("bad raw amount: " + raw);
        }
    }

    /**
     * The key a money call is sent under: the caller's, or a fresh one when they passed null. An
     * empty or blank key is refused. It used to be swapped for a fresh random key, so a retry
     * carried a different key and paid again while the caller believed it was deduplicated.
     */
    private static String idempotencyKeyOf(String key) {
        if (key == null) return freshIdempotencyKey();
        if (key.isBlank())
            throw new PaymosException("idempotencyKey is empty — pass a durable key (a payout or job id) so a retry "
                + "replays the same movement, or pass null for a fresh one per call");
        return key;
    }

    private static String freshIdempotencyKey() {
        byte[] b = new byte[16];
        new SecureRandom().nextBytes(b);
        StringBuilder sb = new StringBuilder(32);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        return sb.toString();
    }

    private static String urlPath(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8).replace("+", "%20");
    }

    /**
     * Refuse to sign unless the server's quote echoes what the caller approved. A units bug,
     * contract drift or a server answering with other numbers changes one of these, and the change
     * is caught before a commitment exists. It pins what the caller typed; the side the server
     * computes (the exact_out debit) is bounded only by {@code maxDebit}.
     */
    private static void verifyQuoteEcho(Quote q, String sendAsset, String receiveAsset,
                                        BigInteger expectSendRaw, BigInteger expectReceiveRaw,
                                        BigInteger maxDebitRaw) {
        if (!q.send.asset.equals(sendAsset) || !q.receive.asset.equals(receiveAsset))
            throw new PaymosException(
                "quote is for " + q.send.asset + "→" + q.receive.asset + ", not the "
                    + sendAsset + "→" + receiveAsset + " that was approved");
        if (expectSendRaw != null && rawInt(q.send.amount).compareTo(expectSendRaw) != 0)
            throw new PaymosException("quote sends " + q.send.amount + ", not the approved " + expectSendRaw);
        // exact_out: the recipient gets exactly the approved amount — pinned, as Python pins it —
        // and the guaranteed floor may not sit under it either.
        if (expectReceiveRaw != null && rawInt(q.receive.amount).compareTo(expectReceiveRaw) != 0)
            throw new PaymosException("quote receives " + q.receive.amount + ", not the approved " + expectReceiveRaw);
        if (expectReceiveRaw != null && rawInt(q.receive.min).compareTo(expectReceiveRaw) < 0)
            throw new PaymosException("quote guarantees " + q.receive.min + ", below the approved " + expectReceiveRaw);
        if (maxDebitRaw != null && rawInt(q.debit.amount).compareTo(maxDebitRaw) > 0)
            throw new PaymosException("quote debits " + q.debit.amount + ", above the approved " + maxDebitRaw);
    }

    private static void enforceMaxDebit(Quote q, String maxDebit, int decimals) {
        if (maxDebit == null || maxDebit.isEmpty()) return;
        BigInteger cap = new BigInteger(Amounts.parseUnits(maxDebit, decimals));
        if (rawInt(q.debit.amount).compareTo(cap) > 0)
            throw new PaymosException("quote debits " + q.debit.amount + ", above the cap " + cap + " (" + maxDebit + ")");
    }

    /**
     * The fingerprints a source of the quote's send asset may carry: sha256 of the raw token id.
     * Pinned by the caller, only the pins count (the caller vouches for them). Otherwise every
     * fingerprint /assets publishes under that label with the first entry's decimals — one label can
     * list two contracts of one coin, and the server resolves a label to its first match. None at
     * all leaves the token unchecked, and that is refused, never skipped.
     */
    private Set<String> sendAssetFingerprints(Quote q) {
        Set<String> pinned = pinnedFingerprints.get(q.send.asset);
        if (pinned != null) return pinned;
        // Only entries in the first entry's decimals: the debit was computed in those, and a token
        // of the same label in other decimals would pass the raw-unit sum while worth 10^Δ more.
        Asset first = assetMap().get(q.send.asset);
        Set<String> published = new HashSet<>();
        for (Asset a : catalog())
            if (first != null && a.asset.equals(q.send.asset) && a.decimals == first.decimals
                && a.fingerprint != null && !a.fingerprint.isEmpty())
                published.add(a.fingerprint.toLowerCase(Locale.ROOT));
        if (published.isEmpty())
            throw new PaymosException(
                "co-sign refused: the server did not publish an asset fingerprint — update the server");
        return published;
    }

    /**
     * This vault's group key, which every disclosed message must be signed from. Every key package
     * the core's DKG produces carries it; without it there is nothing to hold signer_id against,
     * and an unchecked signer is exactly "sign from another vault". Refused, never skipped.
     */
    private static String signerOf(JsonObject kp) {
        String vk = Types.strOrNull(kp, "verifying_key");
        if (vk == null || vk.isEmpty())
            throw new PaymosException(
                "co-sign refused: the vault key package has no verifying key to check the signer against");
        return vk.toLowerCase(java.util.Locale.ROOT);
    }

    /**
     * Never blind-sign. The server discloses, per source, the plaintext message it wants signed.
     * For each one this recomputes the digest and confirms the package about to be signed binds
     * to exactly that message; confirms the message is a single transfer from THIS vault, of the
     * quote's send asset and a positive amount; and confirms the sources together move no more
     * than the approved debit. Any mismatch aborts before a share is produced.
     *
     * <p>Not checked: the recipient of the transfer — the route's deposit address is chosen by the
     * server. And the debit it caps against is the quote's, which for exact_out the server
     * computed; {@code maxDebit} is what bounds it from the caller's side.
     */
    private static void verifySigningDisclosure(Quote q, JsonArray packages, JsonElement messagesEl,
                                                JsonObject kp, Set<String> sendFingerprints) {
        if (messagesEl == null || !messagesEl.isJsonArray()
            || messagesEl.getAsJsonArray().size() != packages.size())
            throw new PaymosException(
                "co-sign refused: the server did not disclose the signing messages — refusing to blind-sign");
        JsonArray messages = messagesEl.getAsJsonArray();
        String expectedSigner = signerOf(kp);
        BigInteger total = BigInteger.ZERO;

        for (int i = 0; i < packages.size(); i++) {
            try {
                total = total.add(verifyOneSource(i, packages.get(i), messages.get(i), expectedSigner, sendFingerprints));
            } catch (PaymosException e) {
                throw e;
            } catch (RuntimeException e) {
                // A disclosure shaped wrong in a way no check below names (a number where an object
                // goes, a non-hex nonce) is still a refusal, and still a typed one.
                throw new PaymosException("co-sign refused: malformed disclosure for source " + i + ": " + e.getMessage());
            }
        }

        // (3) no inflation past the approved debit — the quote's figure, already checked against
        // the caller's own numbers and maxDebit where given, not an independent bound.
        BigInteger approved = rawInt(q.debit.amount);
        if (total.compareTo(approved) > 0)
            throw new PaymosException(
                "co-sign refused: sources move " + total + ", above the approved debit " + approved);
    }

    /** One source of the blind-sign guard. Returns the raw amount it moves. */
    private static BigInteger verifyOneSource(int i, JsonElement pkgEl, JsonElement discEl, String expectedSigner,
                                              Set<String> sendFingerprints) {
        if (!discEl.isJsonObject())
            throw new PaymosException("co-sign refused: malformed disclosure for source " + i);
        JsonObject disc = discEl.getAsJsonObject();
        String message = Types.strOrNull(disc, "message");
        String nonceHex = Types.strOrNull(disc, "nonce");
        String recipient = Types.strOrNull(disc, "recipient");
        if (message == null || nonceHex == null || recipient == null)
            throw new PaymosException("co-sign refused: malformed disclosure for source " + i);

        // (1) binding: the package about to be signed hashes to EXACTLY the disclosed message.
        String want;
        try {
            want = Digest.payloadDigestHex(message, hexToBytes(nonceHex), recipient, null);
        } catch (PaymosException e) {
            throw new PaymosException("co-sign refused: malformed disclosure for source " + i + ": " + e.getMessage());
        }
        String got = pkgEl.isJsonObject() ? Types.strOrNull(pkgEl.getAsJsonObject(), "message") : null;
        if (got == null || !got.equalsIgnoreCase(want))
            throw new PaymosException(
                "co-sign refused: signing package " + i + " does not bind to the disclosed message");

        // (2) structure and own-vault: one transfer, signed from this vault and no other. Parsed
        // strictly (StrictJson): the verifier on chain re-parses these exact bytes as RFC JSON and
        // rejects a repeated key, where JsonParser is lenient and keeps the last one.
        JsonObject parsed;
        try {
            parsed = StrictJson.parse(message).getAsJsonObject();
        } catch (Exception e) {
            throw new PaymosException("co-sign refused: unreadable message for source " + i + ": " + e.getMessage());
        }
        // Python reads signer_id as a required key; a message that names no signer is unreadable.
        String signerId = Types.strOrNull(parsed, "signer_id");
        if (signerId == null)
            throw new PaymosException("co-sign refused: unreadable message for source " + i + ": no signer_id");
        if (!parsed.has("intents") || !parsed.get("intents").isJsonArray()
            || parsed.getAsJsonArray("intents").size() != 1
            || !parsed.getAsJsonArray("intents").get(0).isJsonObject())
            throw new PaymosException("co-sign refused: source " + i + " is not a single transfer");
        JsonObject one = parsed.getAsJsonArray("intents").get(0).getAsJsonObject();
        if (!"transfer".equals(Types.strOrNull(one, "intent")))
            throw new PaymosException("co-sign refused: source " + i + " is not a single transfer");
        if (!signerId.toLowerCase(java.util.Locale.ROOT).equals(expectedSigner))
            throw new PaymosException("co-sign refused: source " + i + " signs from a different vault");
        if (!one.has("tokens") || !one.get("tokens").isJsonObject()
            || one.getAsJsonObject("tokens").size() != 1)
            throw new PaymosException("co-sign refused: source " + i + " does not transfer exactly one token");
        Map.Entry<String, JsonElement> token = one.getAsJsonObject("tokens").entrySet().iterator().next();
        // The token: every source moves the send asset, as the catalog fingerprints it (or as the
        // caller pinned it). This binds the token to the server's own published fingerprint — it
        // catches a bug or a subverted signing path; only a pin also holds against the server.
        if (!sendFingerprints.contains(sha256Hex(token.getKey())))
            throw new PaymosException("co-sign refused: source " + i + " moves a token other than the quote's send asset");
        // A JSON string of ASCII digits, above zero — exactly what the server builds. A signed
        // "-990" in one source would let another move 1000 and still sum under the approved debit;
        // the negative one never settles, the large one does. A zero source is nothing to sign.
        JsonElement amountEl = token.getValue();
        String amount = amountEl.isJsonPrimitive() && amountEl.getAsJsonPrimitive().isString()
            ? amountEl.getAsString() : null;
        if (amount == null || !amount.matches("[0-9]+") || new BigInteger(amount).signum() == 0)
            throw new PaymosException("co-sign refused: bad transfer amount for source " + i);
        return new BigInteger(amount);
    }

    private static String sha256Hex(String s) {
        try {
            byte[] d = java.security.MessageDigest.getInstance("SHA-256")
                .digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : d) sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 missing from this JVM", e);
        }
    }

    private static byte[] hexToBytes(String hex) {
        if (hex.length() % 2 != 0)
            throw new PaymosException("odd-length hex: " + hex.length() + " chars");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new PaymosException("not hex at position " + (i * 2));
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
