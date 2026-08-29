package io.paymos.wallet;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Authenticated transport, ported from the Python SDK so every language fails the same way.
 *
 * <p>Attaches "Authorization: Bearer &lt;api key&gt;" to every request, returns parsed JSON on a
 * 2xx, and maps anything else onto a typed error through the server's envelope. The server's
 * contract: business errors are {"error": "…"} and the sign flow answers
 * {"ok":false,"status":"failed","error":"…"} — both carry the message under "error". Those
 * messages arrive already client-safe, so this layer maps them and never rewrites them, and it
 * never logs or echoes a request body.
 *
 * <p>Transport failures are wrapped into a typed error with no status, so a caller on the money
 * path never catches a raw HttpClient exception.
 */
final class Http {
    /** The sign/aggregate round can trigger a relay that takes a while. */
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(60);

    private final String baseUrl;
    private final String apiKey;
    private final HttpClient client;
    private final Duration timeout;

    Http(String baseUrl, String apiKey, Duration timeout) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.apiKey = apiKey;
        this.timeout = timeout == null ? DEFAULT_TIMEOUT : timeout;
        this.client = HttpClient.newBuilder()
            .connectTimeout(this.timeout)
            .build();
    }

    JsonObject get(String path, Map<String, String> query) {
        StringBuilder url = new StringBuilder(baseUrl).append(path);
        if (query != null && !query.isEmpty()) {
            url.append('?');
            query.forEach((k, v) -> {
                if (v != null)
                    url.append(encode(k)).append('=').append(encode(v)).append('&');
            });
            url.setLength(url.length() - 1);
        }
        HttpRequest req = HttpRequest.newBuilder(URI.create(url.toString()))
            .timeout(timeout)
            .header("authorization", "Bearer " + apiKey)
            .GET()
            .build();
        return send(req);
    }

    JsonObject post(String path, String jsonBody, Map<String, String> extraHeaders) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path))
            .timeout(timeout)
            .header("authorization", "Bearer " + apiKey)
            .header("content-type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody));
        if (extraHeaders != null) extraHeaders.forEach(b::header);
        return send(b.build());
    }

    private JsonObject send(HttpRequest req) {
        HttpResponse<String> resp;
        try {
            resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new PaymosException("transport error: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PaymosException("transport error: interrupted");
        }
        String text = resp.body() == null ? "" : resp.body();
        JsonObject body = null;
        try {
            if (!text.isEmpty()) {
                var parsed = JsonParser.parseString(text);
                if (parsed.isJsonObject()) body = parsed.getAsJsonObject();
            }
        } catch (Exception ignored) {
            body = null;
        }
        int status = resp.statusCode();
        if (status >= 200 && status < 300) {
            return body == null ? new JsonObject() : body;
        }
        throw raiseFor(status, body, text, resp.headers().firstValue("retry-after").orElse(null));
    }

    private static String messageOf(JsonObject body, int status, String text) {
        if (body != null) {
            for (String key : new String[] { "error", "detail" }) {
                if (body.has(key) && body.get(key).isJsonPrimitive()) {
                    String msg = body.get(key).getAsString();
                    if (!msg.isEmpty()) return msg;
                }
            }
        }
        String trimmed = text.trim();
        return trimmed.isEmpty() ? "request failed with status " + status : trimmed;
    }

    /** Map a 400's message to a type. First match wins, in this exact order. */
    private static PaymosException classify400(String message, int status) {
        String m = message.toLowerCase();
        if (m.contains("cross-asset")) return new PaymosException.CrossAssetWithdrawNotAllowed(message, status);
        if (m.contains("slippage")) return new PaymosException.SlippageExceeded(message, status);
        if (m.contains("expired")) return new PaymosException.QuoteExpired(message, status);
        for (String t : new String[] { "insufficient", "not enough balance", "exceeds the vault", "available balance" })
            if (m.contains(t)) return new PaymosException.InsufficientFunds(message, status);
        // The server's route and liquidity rejections come back sounding transient — "No liquidity
        // available … try again in a moment", "route can't be quoted". That whole family is one type.
        for (String t : new String[] { "route", "can't be quoted", "liquidity", "try again in a moment" })
            if (m.contains(t)) return new PaymosException.RouteUnavailable(message, status);
        return new PaymosException(message, status);
    }

    private static PaymosException raiseFor(int status, JsonObject body, String text, String retryAfterHeader) {
        String message = messageOf(body, status, text);
        switch (status) {
            case 401: return new PaymosException.Auth(message, status);
            case 403: return new PaymosException.Forbidden(message, status);
            case 409: return new PaymosException.Conflict(message, status);
            case 429:
                Long retryAfter = null;
                try {
                    if (retryAfterHeader != null) retryAfter = Long.parseLong(retryAfterHeader.trim());
                } catch (NumberFormatException ignored) {}
                return new PaymosException.RateLimited(message, status, retryAfter);
            case 400: return classify400(message, status);
            // 404 has no type of its own by design; it and every other non-2xx land on the base.
            default: return new PaymosException(message, status);
        }
    }

    private static String encode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
