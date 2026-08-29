package io.paymos.wallet;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AmountsTest {
    @Test
    void parsesHumanDecimalsIntoRawUnits() {
        assertEquals("1500000", Amounts.parseUnits("1.5", 6));
        assertEquals("1000000", Amounts.parseUnits("1", 6));
        assertEquals("1", Amounts.parseUnits("0.000001", 6));
        assertEquals("12", Amounts.parseUnits("12", 0));
    }

    @Test
    void rejectsAnythingThatIsNotANonNegativeDecimal() {
        for (String bad : new String[] { "-1", "abc", "", "1,5", "1.2.3", " ", "1." })
            assertThrows(PaymosException.class, () -> Amounts.parseUnits(bad, 6));
        assertThrows(PaymosException.class, () -> Amounts.parseUnits("1.1234567", 6));
    }

    @Test
    void survivesAmountsADoubleWouldRound() {
        // 18 decimals: past what an IEEE 754 double holds exactly, which is the reason these are
        // strings.
        String raw = Amounts.parseUnits("123456789.123456789123456789", 18);
        assertEquals("123456789123456789123456789", raw);
        assertEquals("123456789.123456789123456789", Amounts.formatUnits(raw, 18));
    }

    @Test
    void formatsRawUnitsBackDroppingTrailingZeros() {
        assertEquals("1.5", Amounts.formatUnits("1500000", 6));
        assertEquals("1", Amounts.formatUnits("1000000", 6));
        assertEquals("0.000001", Amounts.formatUnits("1", 6));
        assertEquals("12", Amounts.formatUnits("12", 0));
    }

    @Test
    void roundTrips() {
        String[][] cases = { {"1.5", "6"}, {"0.000001", "6"}, {"1000", "18"}, {"7", "0"} };
        for (String[] c : cases)
            assertEquals(c[0], Amounts.formatUnits(Amounts.parseUnits(c[0], Integer.parseInt(c[1])),
                Integer.parseInt(c[1])));
    }
}
