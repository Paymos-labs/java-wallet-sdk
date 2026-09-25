package io.paymos.wallet;

// The error mapping, which is the whole reason this layer exists: a caller branches on a type
// instead of matching a string, and the types must land the same way they do in Python.

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HttpTest {
    private HttpServer server;
    private final Map<String, String> seenHeaders = new HashMap<>();

    private Wallet walletOver(int status, String body) throws IOException {
        return walletOver(status, body, Map.of());
    }

    private Wallet walletOver(int status, String body, Map<String, String> headers) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getRequestHeaders().forEach((k, v) -> seenHeaders.put(k.toLowerCase(), String.join(",", v)));
            headers.forEach((k, v) -> exchange.getResponseHeaders().set(k, v));
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
        server.start();
        return new Wallet(VaultSecret.pack("vk_live_x", 1, null),
            "http://127.0.0.1:" + server.getAddress().getPort(), null);
    }

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    @Test
    void returnsParsedJsonOn2xx() throws IOException {
        // The real shape: /assets answers a bare array, never {"assets": [...]}.
        Wallet w = walletOver(200,
            "[{\"asset\":\"USDC@base\",\"symbol\":\"USDC\",\"chain\":\"base\",\"decimals\":6}]");
        var assets = w.assets();
        assertEquals(1, assets.size());
        assertEquals("USDC@base", assets.get(0).asset);
    }

    @Test
    void mapsStatusCodesToTypes() {
        int[][] cases = { {401}, {403}, {409}, {404}, {500} };
        Class<?>[] types = {
            PaymosException.Auth.class, PaymosException.Forbidden.class, PaymosException.Conflict.class,
            PaymosException.class, PaymosException.class
        };
        for (int i = 0; i < cases.length; i++) {
            try {
                Wallet w = walletOver(cases[i][0], "{\"error\":\"boom\"}");
                int status = cases[i][0];
                PaymosException ex = assertThrows(PaymosException.class, w::assets);
                assertEquals(types[i], ex.getClass(), "status " + status);
                assertEquals(status, ex.status());
            } catch (IOException e) {
                fail(e);
            }
        }
    }

    @Test
    void classifies400ByMessageFirstMatchWins() throws IOException {
        String[][] cases = {
            {"cross-asset withdraw is not allowed", "CrossAssetWithdrawNotAllowed"},
            {"slippage exceeded", "SlippageExceeded"},
            {"quote expired", "QuoteExpired"},
            {"insufficient balance", "InsufficientFunds"},
            {"available balance is lower", "InsufficientFunds"},
            {"No liquidity available, try again in a moment", "RouteUnavailable"},
            {"route can't be quoted", "RouteUnavailable"},
            {"something else entirely", "PaymosException"},
        };
        for (String[] c : cases) {
            Wallet w = walletOver(400, "{\"error\":\"" + c[0] + "\"}");
            PaymosException ex = assertThrows(PaymosException.class, w::assets);
            assertEquals(c[1], ex.getClass().getSimpleName(), c[0]);
        }
    }

    @Test
    void carriesRetryAfterOn429() throws IOException {
        Wallet with = walletOver(429, "{\"error\":\"slow down\"}", Map.of("retry-after", "12"));
        PaymosException.RateLimited ex1 =
            assertThrows(PaymosException.RateLimited.class, with::assets);
        assertEquals(12L, ex1.retryAfter());

        Wallet without = walletOver(429, "{\"error\":\"slow down\"}");
        PaymosException.RateLimited ex2 =
            assertThrows(PaymosException.RateLimited.class, without::assets);
        assertNull(ex2.retryAfter());
    }

    @Test
    void fallsBackToRawBodyWithoutEnvelope() throws IOException {
        Wallet w = walletOver(500, "upstream exploded");
        PaymosException ex = assertThrows(PaymosException.class, w::assets);
        assertEquals("upstream exploded", ex.getMessage());
    }

    @Test
    void sendsTheBearerTokenAndTheIdempotencyKey() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getRequestHeaders().forEach((k, v) -> seenHeaders.put(k.toLowerCase(), String.join(",", v)));
            String path = exchange.getRequestURI().getPath();
            String body;
            if (path.equals("/vault/v1/assets")) {
                body = "[{\"asset\":\"USDC@base\",\"symbol\":\"USDC\",\"chain\":\"base\",\"decimals\":6}]";
            } else if (path.equals("/vault/v1/quote/withdraw")) {
                // A deliberately wrong asset: the echo check fails AFTER the request was seen.
                body = "{\"movement_id\":\"m1\",\"mode\":\"exact_out\","
                    + "\"send\":{\"amount\":\"24000000\",\"asset\":\"OTHER\"},"
                    + "\"debit\":{\"amount\":\"25000000\",\"asset\":\"USDC@base\"},"
                    + "\"receive\":{\"amount\":\"25000000\",\"min\":\"25000000\",\"asset\":\"USDC@base\"},"
                    + "\"expires_at\":\"\",\"sources\":1}";
            } else {
                body = "{}";
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
        server.start();
        Wallet w = new Wallet(VaultSecret.pack("vk_live_secret", 1, "{\"k\":1}"),
            "http://127.0.0.1:" + server.getAddress().getPort(), null);

        assertThrows(PaymosException.class,
            () -> w.withdraw("USDC@base", "25", "0xRecipient", "exact_out", null, "abc"));
        assertEquals("Bearer vk_live_secret", seenHeaders.get("authorization"));
        assertEquals("abc", seenHeaders.get("idempotency-key"));
    }
}
