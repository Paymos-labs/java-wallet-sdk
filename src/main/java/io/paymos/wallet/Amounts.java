package io.paymos.wallet;

/**
 * Human decimal ↔ raw integer, ported from the Python SDK.
 *
 * <p>Raw amounts are strings rather than numbers on purpose. A token with 18 decimals overflows
 * the exact range of an IEEE 754 double at nine significant digits of whole units, so a double
 * would round silently — the one failure nobody notices until it is somebody's balance. This
 * class is string-only: no numeric conversion ever happens, so no amount is too long to parse
 * exactly.
 */
public final class Amounts {
    private Amounts() {}

    /** "1.5", 6 → "1500000". Throws on anything that is not a non-negative decimal. */
    public static String parseUnits(String human, int decimals) {
        if (decimals < 0) throw new PaymosException("decimals must be >= 0");
        String s = human == null ? "" : human.trim();
        String whole = s;
        String frac = "";
        int dot = s.indexOf('.');
        if (dot >= 0) {
            whole = s.substring(0, dot);
            frac = s.substring(dot + 1);
            // The wire format is ^\d+(\.\d+)?$ — a second dot is not a decimal.
            if (frac.contains(".")) throw new PaymosException("not a non-negative decimal: " + human);
        }
        if (!isDigits(whole) || (!frac.isEmpty() && !isDigits(frac)) || (dot >= 0 && frac.isEmpty()))
            throw new PaymosException("not a non-negative decimal: " + human);
        if (frac.length() > decimals)
            throw new PaymosException("more than " + decimals + " fractional digits: " + human);
        StringBuilder raw = new StringBuilder(whole).append(frac);
        for (int i = frac.length(); i < decimals; i++) raw.append('0');
        return stripLeadingZeros(raw.toString());
    }

    /** "1500000", 6 → "1.5". Trailing zeros in the fraction are dropped. */
    public static String formatUnits(String raw, int decimals) {
        if (raw == null || raw.isEmpty()) throw new PaymosException("not a raw integer amount: " + raw);
        String sign = "";
        String digits = raw;
        if (digits.startsWith("-")) {
            sign = "-";
            digits = digits.substring(1);
        }
        if (!isDigits(digits)) throw new PaymosException("not a raw integer amount: " + raw);
        digits = stripLeadingZeros(digits);
        if (digits.equals("0")) sign = ""; // the sign of nothing is nothing
        if (decimals == 0) return sign + digits;
        while (digits.length() <= decimals) digits = "0" + digits;
        String whole = digits.substring(0, digits.length() - decimals);
        String frac = digits.substring(digits.length() - decimals).replaceAll("0+$", "");
        return frac.isEmpty() ? sign + whole : sign + whole + "." + frac;
    }

    private static boolean isDigits(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    private static String stripLeadingZeros(String s) {
        int i = 0;
        while (i < s.length() - 1 && s.charAt(i) == '0') i++;
        return s.substring(i);
    }
}
