package io.paymos.wallet;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The "vs_live_…" vault secret: an API key, the vault id, and — for a full key — this side's
 * FROST signing share. Ported from the Python SDK, same envelope, same field names, so one
 * secret works with any of the SDKs.
 */
public final class VaultSecret {
    private static final String PREFIX = "vs_live_";

    public final String apiKey;
    public final long vaultId;
    /** This side's FROST key package JSON. Null on a read-only secret. Never rendered. */
    public final String share;

    private VaultSecret(String apiKey, long vaultId, String share) {
        this.apiKey = apiKey;
        this.vaultId = vaultId;
        this.share = share;
    }

    public boolean hasShare() {
        return share != null;
    }

    public static String pack(String apiKey, long vaultId, String share) {
        JsonObject o = new JsonObject();
        o.addProperty("k", apiKey);
        o.addProperty("v", vaultId);
        if (share == null) o.add("s", null);
        else o.addProperty("s", share);
        return PREFIX + Base64.getUrlEncoder().withoutPadding()
            .encodeToString(o.toString().getBytes(StandardCharsets.UTF_8));
    }

    public static VaultSecret parse(String secret) {
        if (secret == null || !secret.startsWith(PREFIX))
            throw new PaymosException("not a vs_live_ vault secret");
        JsonObject o;
        try {
            byte[] raw = Base64.getUrlDecoder().decode(pad(secret.substring(PREFIX.length())));
            o = JsonParser.parseString(new String(raw, StandardCharsets.UTF_8)).getAsJsonObject();
        } catch (Exception e) {
            throw new PaymosException("malformed vault secret: " + e.getMessage());
        }
        String apiKey = o.has("k") && o.get("k").isJsonPrimitive() ? o.get("k").getAsString() : null;
        if (apiKey == null || !apiKey.startsWith("vk_live_"))
            throw new PaymosException("vault secret carries no valid api key");
        if (!o.has("v") || !o.get("v").isJsonPrimitive())
            throw new PaymosException("vault secret carries no valid vault id");
        long vaultId;
        try {
            vaultId = o.get("v").getAsLong();
        } catch (NumberFormatException e) {
            throw new PaymosException("vault secret carries no valid vault id");
        }
        String share = o.has("s") && o.get("s").isJsonPrimitive() ? o.get("s").getAsString() : null;
        return new VaultSecret(apiKey, vaultId, share);
    }

    /** The urlsafe decoder wants canonical padding; the envelope drops it. */
    private static String pad(String s) {
        int rem = s.length() % 4;
        return rem == 0 ? s : s + "====".substring(rem);
    }

    /** Never renders the share, and masks the key: a stray log line must not leak either. */
    @Override
    public String toString() {
        String mask = apiKey.isEmpty() ? "…" : apiKey.substring(0, Math.min(8, apiKey.length())) + "…";
        return "VaultSecret(apiKey=" + mask + ", vaultId=" + vaultId + ", hasShare=" + hasShare() + ")";
    }
}
