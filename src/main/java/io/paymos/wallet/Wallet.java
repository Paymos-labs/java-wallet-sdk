package io.paymos.wallet;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
 *   <li>the quote must echo what was approved — a decimals bug or a lying server changes the
 *       numbers, and the numbers are compared before a commitment
 *   <li>the debit may be capped — for an exact_out payout the input side is computed by the
 *       server, so {@code maxDebit} is the caller's ceiling
 *   <li>never blind-sign — the server discloses each message, this side recomputes the digest
 *       and refuses unless the package binds to it
 * </ul>
 *
 * Any of those failing throws before a single signature share exists.
 */
public final class Wallet {
    /** A movement in any of these states has already been signed; a retry must not sign again. */
    private static final List<String> PROGRESSED =
        List.of("signed", "relaying", "relayed", "settling", "completed", "failed");

    /** A movement is settled (no more polling) once it reaches one of these. */
    private static final List<String> TERMINAL =
        List.of("completed", "failed", "refunded", "expired", "cancelled");

    private static final String DEFAULT_BASE_URL = "https://wallet.paymos.io";

    private final VaultSecret secret;
    private final Http http;
    private volatile Map<String, Asset> assetCache;

    public Wallet(String secret) {
        this(secret, null, null);
    }

    public Wallet(String secret, String baseUrl, Duration timeout) {
        this.secret = VaultSecret.parse(secret);
        if (baseUrl == null || baseUrl.isEmpty()) baseUrl = System.getenv("PAYMOS_BASE_URL");
        if (baseUrl == null || baseUrl.isEmpty()) baseUrl = DEFAULT_BASE_URL;
        this.http = new Http(baseUrl, this.secret.apiKey, timeout);
    }

    /** Reads PAYMOS_VAULT_SECRET, the way a deployed process is configured. */
    public static Wallet fromEnv() {
        String secret = System.getenv("PAYMOS_VAULT_SECRET");
        if (secret == null || secret.isEmpty())
            throw new PaymosException("PAYMOS_VAULT_SECRET is not set");
        return new Wallet(secret);
    }

    // ── reads ────────────────────────────────────────────────────────────────

    public List<Asset> assets() {
        JsonObject body = http.get("/vault/v1/assets", null);
        List<Asset> out = new ArrayList<>();
        if (body.has("assets"))
            for (JsonElement a : body.getAsJsonArray("assets")) out.add(new Asset(a.getAsJsonObject()));
        return out;
    }

    public List<Balance> balances() {
        JsonObject body = http.get("/vault/v1/balances", null);
        List<Balance> out = new ArrayList<>();
        if (body.has("balances"))
            for (JsonElement b : body.getAsJsonArray("balances")) out.add(new Balance(b.getAsJsonObject()));
        return out;
    }

    public Movement movement(String movementId) {
        return new Movement(http.get("/vault/v1/movements/" + urlPath(movementId), null));
    }

    /**
     * A page of the caller's movement history (newest first, summary rows without fee legs) and
     * the next cursor; pass it back for the next page (null when exhausted). The server speaks
     * keyset pagination: items + next_cursor.
     */
    public Map.Entry<List<Movement>, String> movements(int limit, String cursor) {
        Map<String, String> q = new HashMap<>();
        q.put("limit", Integer.toString(limit));
        q.put("cursor", cursor);
        JsonObject body = http.get("/vault/v1/movements", q);
        List<Movement> items = new ArrayList<>();
        if (body.has("items"))
            for (JsonElement m : body.getAsJsonArray("items")) items.add(new Movement(m.getAsJsonObject()));
        String next = Types.strOrNull(body, "next_cursor");
        return Map.entry(items, next);
    }

    /** Polls until the movement leaves the states that are still in flight. */
    public Movement wait(String movementId, Duration timeout, Duration interval) {
        if (timeout == null) timeout = Duration.ofMinutes(5);
        if (interval == null) interval = Duration.ofSeconds(2);
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            Movement mv = movement(movementId);
            if (TERMINAL.contains(mv.status)) return mv;
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

    /** A dry preview. Nothing is created and nothing is signed. */
    public Quote quoteSwap(String send, String receive, String amount, int slippageBps) {
        validateAmount(amount, send);
        decimalsOf(receive);
        JsonObject body = new JsonObject();
        body.addProperty("send", send);
        body.addProperty("receive", receive);
        body.addProperty("amount", amount);
        body.addProperty("slippage_bps", slippageBps <= 0 ? 50 : slippageBps);
        return quote("/vault/v1/quote/swap", body, true, null);
    }

    /** A dry preview. Nothing is created and nothing is signed. */
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

    /** Full-key secrets only. Creates a real movement and drives the 2-of-2 co-sign. */
    public Movement swap(String send, String receive, String amount, int slippageBps,
                         String minReceive, String maxDebit, String idempotencyKey) {
        requireShare("swap");
        int sendDec = validateAmount(amount, send);
        int recvDec = decimalsOf(receive);

        JsonObject body = new JsonObject();
        body.addProperty("send", send);
        body.addProperty("receive", receive);
        body.addProperty("amount", amount);
        body.addProperty("slippage_bps", slippageBps <= 0 ? 50 : slippageBps);
        Quote q = quote("/vault/v1/quote/swap", body, false,
            idempotencyKey == null || idempotencyKey.isEmpty() ? freshIdempotencyKey() : idempotencyKey);

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

    /** Full-key secrets only. Creates a real payout movement and drives the 2-of-2 co-sign. */
    public Movement withdraw(String asset, String amount, String to, String mode,
                             String maxDebit, String idempotencyKey) {
        requireShare("withdraw");
        int dec = validateAmount(amount, asset);
        if (mode == null || mode.isEmpty()) mode = "exact_out";

        JsonObject body = new JsonObject();
        body.addProperty("asset", asset);
        body.addProperty("amount", amount);
        body.addProperty("to", to);
        body.addProperty("mode", mode);
        Quote q = quote("/vault/v1/quote/withdraw", body, false,
            idempotencyKey == null || idempotencyKey.isEmpty() ? freshIdempotencyKey() : idempotencyKey);

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

    private void requireShare(String op) {
        if (!secret.hasShare())
            throw new PaymosException(op + " needs a full-scope secret: this one carries no co-signing share");
    }

    private Map<String, Asset> assetMap() {
        Map<String, Asset> cache = assetCache;
        if (cache == null) {
            cache = new HashMap<>();
            for (Asset a : assets()) cache.put(a.asset, a);
            assetCache = cache;
        }
        return cache;
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
        return new Quote(http.post(path, body.toString(), headers));
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
            begin = http.post("/vault/v1/movements/" + mid + "/sign/begin", beginBody.toString(), null);
        } catch (PaymosException e) {
            // An ambiguous failure after the server already progressed the movement is not a
            // reason to sign it a second time.
            Movement mv = movement(mid);
            if (PROGRESSED.contains(mv.status)) return;
            throw e;
        }

        JsonArray packages = begin.has("signing_packages") && begin.get("signing_packages").isJsonArray()
            ? begin.getAsJsonArray("signing_packages") : new JsonArray();
        if (packages.size() != n)
            throw new PaymosException(
                "co-sign protocol mismatch: expected " + n + " signing packages, got " + packages.size());

        verifySigningDisclosure(q, packages, begin.get("messages"), kp);

        JsonArray shares = new JsonArray();
        for (int i = 0; i < packages.size(); i++)
            shares.add(NativeCore.sign(packages.get(i).getAsJsonObject(), nonces.get(i), kp));
        JsonObject aggBody = new JsonObject();
        aggBody.add("token", begin.get("token"));
        aggBody.add("shares", shares);
        JsonObject res = http.post("/vault/v1/movements/" + mid + "/sign/aggregate", aggBody.toString(), null);
        if (!res.has("ok") || !res.get("ok").getAsBoolean()) {
            String msg = res.has("error") && res.get("error").isJsonPrimitive()
                ? res.get("error").getAsString() : "sign failed";
            throw new PaymosException(msg);
        }
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
     * Refuse to sign unless the server's quote echoes what the caller approved. This is what
     * makes co-signing a server-built movement safe: a units bug, contract drift or a compromised
     * server changes one of these numbers, and the change is caught before a commitment exists.
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
     * Never blind-sign. The server discloses, per source, the plaintext message it wants signed.
     * For each one this recomputes the digest and confirms the package about to be signed binds
     * to exactly that message; confirms the message is a single transfer from THIS vault; and
     * confirms the sources together move no more than the approved debit. Any mismatch aborts
     * before a share is produced.
     */
    private static void verifySigningDisclosure(Quote q, JsonArray packages, JsonElement messagesEl,
                                                JsonObject kp) {
        if (messagesEl == null || !messagesEl.isJsonArray()
            || messagesEl.getAsJsonArray().size() != packages.size())
            throw new PaymosException(
                "co-sign refused: the server did not disclose the signing messages — refusing to blind-sign");
        JsonArray messages = messagesEl.getAsJsonArray();
        String expectedSigner = kp.has("verifying_key") && kp.get("verifying_key").isJsonPrimitive()
            ? kp.get("verifying_key").getAsString().toLowerCase(java.util.Locale.ROOT) : "";
        BigInteger total = BigInteger.ZERO;

        for (int i = 0; i < packages.size(); i++) {
            JsonElement discEl = messages.get(i);
            if (!discEl.isJsonObject())
                throw new PaymosException("co-sign refused: malformed disclosure for source " + i);
            JsonObject disc = discEl.getAsJsonObject();
            String message = Types.strOrNull(disc, "message");
            String nonceHex = Types.strOrNull(disc, "nonce");
            String recipient = Types.strOrNull(disc, "recipient");
            if (message == null || nonceHex == null || recipient == null)
                throw new PaymosException("co-sign refused: malformed disclosure for source " + i);

            // (1) binding: the package about to be signed hashes to EXACTLY the disclosed message.
            String want = Digest.payloadDigestHex(message, hexToBytes(nonceHex), recipient, null);
            String got = Types.strOrNull(packages.get(i).getAsJsonObject(), "message");
            if (got == null || !got.equalsIgnoreCase(want))
                throw new PaymosException(
                    "co-sign refused: signing package " + i + " does not bind to the disclosed message");

            // (2) structure and own-vault: one transfer, signed from this vault and no other.
            JsonObject parsed;
            try {
                parsed = JsonParser.parseString(message).getAsJsonObject();
            } catch (Exception e) {
                throw new PaymosException("co-sign refused: unreadable message for source " + i + ": " + e.getMessage());
            }
            if (!parsed.has("intents") || !parsed.get("intents").isJsonArray()
                || parsed.getAsJsonArray("intents").size() != 1)
                throw new PaymosException("co-sign refused: source " + i + " is not a single transfer");
            JsonObject one = parsed.getAsJsonArray("intents").get(0).getAsJsonObject();
            if (!one.has("intent") || !one.get("intent").getAsString().equals("transfer"))
                throw new PaymosException("co-sign refused: source " + i + " is not a single transfer");
            String signerId = Types.strOrNull(parsed, "signer_id");
            signerId = signerId == null ? "" : signerId.toLowerCase(java.util.Locale.ROOT);
            if (!expectedSigner.isEmpty() && !signerId.equals(expectedSigner))
                throw new PaymosException("co-sign refused: source " + i + " signs from a different vault");
            if (!one.has("tokens") || !one.get("tokens").isJsonObject()
                || one.getAsJsonObject("tokens").size() != 1)
                throw new PaymosException("co-sign refused: source " + i + " does not transfer exactly one token");
            JsonElement amountEl = one.getAsJsonObject("tokens").entrySet().iterator().next().getValue();
            if (!amountEl.isJsonPrimitive())
                throw new PaymosException("co-sign refused: bad transfer amount for source " + i);
            total = total.add(rawInt(amountEl.getAsString()));
        }

        // (3) no inflation: the sources together move no more than the approved debit.
        BigInteger approved = rawInt(q.debit.amount);
        if (total.compareTo(approved) > 0)
            throw new PaymosException(
                "co-sign refused: sources move " + total + ", above the approved debit " + approved);
    }

    private static byte[] hexToBytes(String hex) {
        if (hex.length() % 2 != 0)
            throw new PaymosException("odd-length hex: " + hex.length() + " chars");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
