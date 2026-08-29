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
}
