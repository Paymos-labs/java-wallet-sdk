package io.paymos.wallet;

/**
 * The ten error types of the SDK spec. PaymosException is the base case; the nine nested
 * subclasses are the classifications a caller branches on. The set is fixed by the SDK spec —
 * deliberately no NotFound, since a 404 surfaces as the base PaymosException.
 *
 * <p>{@code message} is the server's already client-safe reason; {@code status} is the HTTP
 * status that produced it, or null when the error did not come from a response.
 *
 * <p>Unchecked, deliberately: every method on Wallet would otherwise declare it, and a caller
 * who never branches gains nothing but noise.
 */
public class PaymosException extends RuntimeException {
    private final Integer status;

    public PaymosException(String message, Integer status) {
        super(message);
        this.status = status;
    }

    public PaymosException(String message) {
        this(message, null);
    }

    /** The HTTP status that produced this error, or null for local refusals and transport wraps. */
    public Integer status() {
        return status;
    }

    /** 401 — the API key is missing, malformed, or not recognised. */
    public static class Auth extends PaymosException {
        public Auth(String message, Integer status) { super(message, status); }
    }

    /** 403 — the key is valid but lacks the scope this call requires. */
    public static class Forbidden extends PaymosException {
        public Forbidden(String message, Integer status) { super(message, status); }
    }

    /** 400 — the vault's available balance cannot cover the amount plus fees. */
    public static class InsufficientFunds extends PaymosException {
        public InsufficientFunds(String message, Integer status) { super(message, status); }
    }

    /** 400 — the referenced quote has expired; fetch a fresh one and retry. */
    public static class QuoteExpired extends PaymosException {
        public QuoteExpired(String message, Integer status) { super(message, status); }
    }

    /** 400 — the delivered amount fell outside the accepted slippage bound. */
    public static class SlippageExceeded extends PaymosException {
        public SlippageExceeded(String message, Integer status) { super(message, status); }
    }

    /** 400 — a withdraw changed the asset; that is a swap, and it is rejected here. */
    public static class CrossAssetWithdrawNotAllowed extends PaymosException {
        public CrossAssetWithdrawNotAllowed(String message, Integer status) { super(message, status); }
    }

    /** 400 — no route could be quoted for this pair right now; retry shortly. */
    public static class RouteUnavailable extends PaymosException {
        public RouteUnavailable(String message, Integer status) { super(message, status); }
    }

    /** 429 — too many requests. {@code retryAfter} is the Retry-After seconds when the server sent one. */
    public static class RateLimited extends PaymosException {
        private final Long retryAfter;

        public RateLimited(String message, Integer status, Long retryAfter) {
            super(message, status);
            this.retryAfter = retryAfter;
        }

        public Long retryAfter() {
            return retryAfter;
        }
    }

    /** 409 — idempotency-key conflict: reused with a different request, or a quote still forming. */
    public static class Conflict extends PaymosException {
        public Conflict(String message, Integer status) { super(message, status); }
    }
}
