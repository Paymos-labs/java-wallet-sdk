package io.paymos.wallet;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecretTest {
    private static final String FULL = VaultSecret.pack("vk_live_abc123", 42, "{\"share\":\"x\"}");
    private static final String READ = VaultSecret.pack("vk_live_abc123", 42, null);

    @Test
    void packsThenParsesFullAndReadOnly() {
        VaultSecret full = VaultSecret.parse(FULL);
        assertEquals("vk_live_abc123", full.apiKey);
        assertEquals(42, full.vaultId);
        assertTrue(full.hasShare());

        VaultSecret read = VaultSecret.parse(READ);
        assertFalse(read.hasShare());
        assertNull(read.share);
    }

    @Test
    void rejectsAnythingThatIsNotAVaultSecret() {
        for (String bad : new String[] { "sk_prod_not_ours", "vk_test_dev_key", "", "vs_live_@@@" })
            assertThrows(PaymosException.class, () -> VaultSecret.parse(bad));
    }

    @Test
    void rejectsASecretWhoseApiKeyIsNotOurs() {
        assertThrows(PaymosException.class, () -> VaultSecret.parse(VaultSecret.pack("nope", 1, null)));
    }

    @Test
    void neverRendersTheShareAndMasksTheKey() {
        String rendered = VaultSecret.parse(FULL).toString();
        assertFalse(rendered.contains("share\":\"x"), "the share must never be rendered");
        assertFalse(rendered.contains("abc123"), "the key must be masked");
        assertTrue(rendered.contains("vk_live_"), "the non-secret prefix is fine to show");
    }

    @Test
    void anEmptyIdempotencyKeyIsRefusedBeforeAnythingReachesTheServer() {
        // It used to be swapped for a fresh random key: a retry carried another key and paid again.
        java.util.List<String> seen = new java.util.ArrayList<>();
        Http.Transport nothing = r -> {
            seen.add(r.url);
            throw new AssertionError("nothing may reach the server: " + r.url);
        };
        Wallet w = new Wallet(VaultSecret.pack("vk_live_test", 1, "{\"verifying_key\":\"vk\"}"),
            "https://vault.test", null, nothing);
        for (String key : new String[] { "", " ", "\t" }) {
            PaymosException ex = assertThrows(PaymosException.class,
                () -> w.withdraw("USDC@base", "10", "0xabc", "exact_out", null, key));
            assertTrue(ex.getMessage().startsWith("idempotencyKey is empty"), ex.getMessage());
            ex = assertThrows(PaymosException.class,
                () -> w.swap("USDC@base", "USDT@base", "5", 50, null, null, key));
            assertTrue(ex.getMessage().startsWith("idempotencyKey is empty"), ex.getMessage());
        }
        assertTrue(seen.isEmpty(), seen.toString());
    }

    @Test
    void aReflectiveSerializerOrToStringCarriesNoCredential() {
        // What a JSON log layout does with an object it is handed: serialize it field by field.
        VaultSecret s = VaultSecret.parse(FULL);
        Wallet w = new Wallet(FULL, "https://vault.test", null);
        com.google.gson.Gson gson = new com.google.gson.Gson();
        for (String rendered : new String[] {
                gson.toJson(s), gson.toJson(w), gson.toJson(java.util.Map.of("secret", s, "wallet", w)),
                String.valueOf(w), s + " " + w }) {
            assertFalse(rendered.contains("abc123"), "the key leaked: " + rendered);
            assertFalse(rendered.contains("\"share\"") || rendered.contains("share\\\""), "the share leaked: " + rendered);
        }
        assertEquals("{\"vaultId\":42}", gson.toJson(s));
    }
}
