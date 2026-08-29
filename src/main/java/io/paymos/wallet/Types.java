package io.paymos.wallet;

import java.util.Map;

import com.google.gson.JsonObject;

/**
 * The read model, ported field-for-field from the Python SDK.
 *
 * <p>Every amount is a STRING of raw integer units, never a number. A token with 18 decimals runs
 * past what a double holds exactly, so a JSON parser that produced numbers here would round
 * somebody's balance without saying so. Use {@link Amounts#formatUnits} to show one and
 * {@link Amounts#parseUnits} to build one.
 */
public final class Types {
    private Types() {}

    /** One asset the vault can hold, as the server names it. */
    public static final class Asset {
        public final String asset;
        public final String symbol;
        public final String chain;
        public final int decimals;

        Asset(JsonObject o) {
            this.asset = str(o, "asset");
            this.symbol = str(o, "symbol");
            this.chain = str(o, "chain");
            this.decimals = o != null && o.has("decimals") ? o.get("decimals").getAsInt() : 0;
        }
    }

    /** What the vault holds of one asset. {@code usd} is a display estimate and may be null. */
    public static final class Balance {
        public final String asset;
        public final String symbol;
        public final String chain;
        public final int decimals;
        public final String amountRaw;
        public final String usd;

        Balance(JsonObject o) {
            this.asset = str(o, "asset");
            this.symbol = str(o, "symbol");
            this.chain = str(o, "chain");
            this.decimals = o != null && o.has("decimals") ? o.get("decimals").getAsInt() : 0;
            this.amountRaw = str(o, "amount_raw");
            this.usd = strOrNull(o, "usd");
        }
    }

    /** The routing layer's own fee. {@code estimate} marks a figure that can still move. */
    public static final class RouteFee {
        public final String amount;
        public final boolean estimate;

        RouteFee(JsonObject o) {
            this.amount = str(o, "amount");
            this.estimate = o != null && o.has("estimate") && o.get("estimate").getAsBoolean();
        }
    }

    /** Every charge on an operation, split so none of them can hide inside another. */
    public static final class Fees {
        public final String asset;
        public final String platform;
        public final String network;
        public final RouteFee route;
        public final String total;
        public final Map<String, String> usd;

        @SuppressWarnings("unchecked")
        Fees(JsonObject o) {
            this.asset = str(o, "asset");
            this.platform = str(o, "platform");
            this.network = str(o, "network");
            this.route = obj(o, "route") != null ? new RouteFee(obj(o, "route")) : null;
            this.total = str(o, "total");
            this.usd = o != null && o.has("usd") && o.get("usd").isJsonObject()
                ? new com.google.gson.Gson().fromJson(o.get("usd"), Map.class)
                : null;
        }
    }

    public static final class Amount {
        public final String amount;
        public final String asset;

        Amount(JsonObject o) {
            this.amount = str(o, "amount");
            this.asset = str(o, "asset");
        }
    }

    /** What arrives. {@code min} is the floor the operation is allowed to deliver, and it is guaranteed. */
    public static final class Receive {
        public final String amount;
        public final String min;
        public final String asset;

        Receive(JsonObject o) {
            this.amount = str(o, "amount");
            this.min = str(o, "min");
            this.asset = str(o, "asset");
        }
    }

    public static final class Quote {
        public final String movementId;
        public final String mode;
        public final Amount send;
        /**
         * The MAXIMUM this quote may take from the vault, reserve against slippage included — a
         * ceiling, not a prediction. Approve against this and nothing can debit more than you
         * agreed to; an exact-output route routinely spends less and returns the difference.
         * Compare the finished movement's {@code send} to see what it actually cost.
         */
        public final Amount debit;
        public final Receive receive;
        public final Fees fees;
        public final String expiresAt;
        public final Integer sources;

        Quote(JsonObject o) {
            this.movementId = strOrNull(o, "movement_id");
            this.mode = str(o, "mode");
            this.send = new Amount(obj(o, "send"));
            this.debit = new Amount(obj(o, "debit"));
            this.receive = new Receive(obj(o, "receive"));
            this.fees = obj(o, "fees") != null ? new Fees(obj(o, "fees")) : null;
            this.expiresAt = str(o, "expires_at");
            this.sources = o != null && o.has("sources") && o.get("sources").isJsonPrimitive()
                ? o.get("sources").getAsInt() : null;
        }
    }

    public static final class Movement {
        public final String id;
        public final String type;
        public final String status;
        /**
         * What the movement actually cost the vault: the approved maximum minus anything the
         * route handed back. This is the figure that matches the on-chain balance — reconcile on
         * it. It is NOT the quote's {@code debit}, which is the ceiling that was approved before
         * the route ran.
         */
        public final Amount send;
        public final Receive receive;
        public final Fees fees;
        public final String destChainTxHash;
        public final String destChainExplorerUrl;
        public final String createdAt;
        public final String completedAt;

        Movement(JsonObject o) {
            this.id = str(o, "id");
            this.type = str(o, "type");
            this.status = str(o, "status");
            this.send = new Amount(obj(o, "send"));
            this.receive = new Receive(obj(o, "receive"));
            this.fees = obj(o, "fees") != null ? new Fees(obj(o, "fees")) : null;
            this.destChainTxHash = strOrNull(o, "dest_chain_tx_hash");
            this.destChainExplorerUrl = strOrNull(o, "dest_chain_explorer_url");
            this.createdAt = str(o, "created_at");
            this.completedAt = strOrNull(o, "completed_at");
        }
    }

    static String str(JsonObject o, String key) {
        String v = strOrNull(o, key);
        return v == null ? "" : v;
    }

    static String strOrNull(JsonObject o, String key) {
        if (o == null || !o.has(key) || !o.get(key).isJsonPrimitive()) return null;
        return o.get(key).getAsString();
    }

    static JsonObject obj(JsonObject o, String key) {
        if (o == null || !o.has(key) || !o.get(key).isJsonObject()) return null;
        return o.getAsJsonObject(key);
    }
}
