package io.paymos.wallet;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.JsonElement;
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
 * <p>A 2xx body is returned as whatever JSON it is: /assets and /balances answer a bare array,
 * everything else an object, and the caller says which it expects. A body that is not JSON at all
 * — a proxy's HTML page, a truncated read — is a typed error on either side of 2xx, never a raw
 * parse exception.
 *
 * <p>Transport failures are wrapped into a typed error with no status, so a caller on the money
 * path never catches a raw HttpClient exception.
 */
final class Http {
    /** The sign/aggregate round can trigger a relay that takes a while. */
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(60);

    /** How much of a non-JSON body an error message quotes. The rest is noise, often a whole page. */
    private static final int SNIPPET = 200;

    /** What a request looked like on the wire. Tests read it back; nothing else does. */
    static final class Request {
        final String method;
        final String url;
        final Map<String, String> headers;
        final String body;

        Request(String method, String url, Map<String, String> headers, String body) {
            this.method = method;
            this.url = url;
            this.headers = headers;
            this.body = body;
        }
    }

    static final class Response {
        final int status;
        final String body;
        final String retryAfter;

        Response(int status, String body, String retryAfter) {
            this.status = status;
            this.body = body;
            this.retryAfter = retryAfter;
        }
    }

    /** The one seam under the SDK: the real one is java.net.http, a test's is a fixture file. */
    interface Transport {
        Response send(Request request) throws IOException, InterruptedException;
    }

    private final String baseUrl;
    private final String apiKey;
    private final Transport transport;

    Http(String baseUrl, String apiKey, Duration timeout) {
        this(baseUrl, apiKey, timeout, null);
    }

    Http(String baseUrl, String apiKey, Duration timeout, Transport transport) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.apiKey = apiKey;
        this.transport = transport != null ? transport
            : new JdkTransport(timeout == null ? DEFAULT_TIMEOUT : timeout);
    }

    JsonElement get(String path, Map<String, String> query) {
        StringBuilder url = new StringBuilder(baseUrl).append(path);
        if (query != null && !query.isEmpty()) {
            StringBuilder qs = new StringBuilder();
            query.forEach((k, v) -> {
                if (v != null) qs.append(qs.length() == 0 ? "" : "&").append(encode(k)).append('=').append(encode(v));
            });
            if (qs.length() > 0) url.append('?').append(qs);
        }
        return send(new Request("GET", url.toString(), headers(null), null));
    }

    JsonElement post(String path, String jsonBody, Map<String, String> extraHeaders) {
        Map<String, String> h = headers(extraHeaders);
        h.put("content-type", "application/json");
        return send(new Request("POST", baseUrl + path, h, jsonBody));
    }

    private Map<String, String> headers(Map<String, String> extra) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("authorization", "Bearer " + apiKey);
        if (extra != null) h.putAll(extra);
        return h;
    }

    private JsonElement send(Request req) {
        Response resp;
        try {
            resp = transport.send(req);
        } catch (IOException e) {
            throw new PaymosException("transport error: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PaymosException("transport error: interrupted");
        }
        String text = resp.body == null ? "" : resp.body;
        JsonElement body = null;
        try {
            if (!text.isBlank()) body = JsonParser.parseString(text);
        } catch (Exception ignored) {
            body = null;
        }
        int status = resp.status;
        if (status >= 200 && status < 300) {
            // Every 2xx under /vault/ is JSON. One that is not came from something standing in
            // front of the server, and an empty result built from it would read as "no assets".
            if (body == null || body.isJsonNull())
                throw new PaymosException(
                    "the server answered " + status + " with a body that is not JSON" + snippet(text)
                        + " — is the base URL pointing at the wallet API?", status);
            return body;
        }
        throw raiseFor(status, body != null && body.isJsonObject() ? body.getAsJsonObject() : null,
            text, resp.retryAfter);
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
        if (trimmed.isEmpty()) return "request failed with status " + status;
        // A proxy's HTML page as an exception message is a screenful of markup that says nothing.
        if (trimmed.startsWith("<"))
            return "request failed with status " + status + ": the response is not JSON" + snippet(trimmed)
                + " — is the base URL pointing at the wallet API?";
        return trimmed.length() > SNIPPET ? trimmed.substring(0, SNIPPET) + "…" : trimmed;
    }

    private static String snippet(String text) {
        String t = text.trim().replaceAll("\\s+", " ");
        if (t.isEmpty()) return " (empty body)";
        return " (" + (t.length() > SNIPPET ? t.substring(0, SNIPPET) + "…" : t) + ")";
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

    /** The production transport: java.net.http, one client per wallet. */
    private static final class JdkTransport implements Transport {
        private final HttpClient client;
        private final Duration timeout;

        JdkTransport(Duration timeout) {
            this.timeout = timeout;
            this.client = HttpClient.newBuilder().connectTimeout(timeout).build();
        }

        @Override
        public Response send(Request r) throws IOException, InterruptedException {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(r.url)).timeout(timeout);
            r.headers.forEach(b::header);
            if (r.method.equals("POST")) b.POST(HttpRequest.BodyPublishers.ofString(r.body));
            else b.GET();
            HttpResponse<String> resp = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
            return new Response(resp.statusCode(), resp.body(),
                resp.headers().firstValue("retry-after").orElse(null));
        }
    }
}
