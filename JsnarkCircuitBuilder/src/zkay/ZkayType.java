/*******************************************************************************
 * Base class for all emulated types, also defines type singletons
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class ZkayType {
    public final int bitwidth;
    public final boolean signed;
    public final BigInteger minusOne;

    private ZkayType(int bitwidth, boolean signed) {
        this.bitwidth = bitwidth;
        this.signed = signed;
        this.minusOne = BigInteger.ONE.shiftLeft(bitwidth).subtract(BigInteger.ONE);
    }

    private static final Map<Integer, ZkayType> utypes = new HashMap<>();
    private static final Map<Integer, ZkayType> stypes = new HashMap<>();
    public static final ZkayType ZkBool = new ZkayType(1, false);
    public static final ZkayType Zk124 = new ZkayType(124, false);
    static {
        for (int i = 8; i <= 256; i += 8) {
            utypes.put(i, new ZkayType(i, false));
            if (i < 256) {
                // There can be no int256 inside the circuit, since the sign bit is outside field prime range -> unclear how to defined negative numbers
                stypes.put(i, new ZkayType(i, true));
            }
        }
    }

    public static ZkayType ZkUint(int bitwidth) {
        if (!utypes.containsKey(bitwidth)) {
            throw new IllegalArgumentException("No uint type with bitwidth " + bitwidth + " exists.");
        }
        return utypes.get(bitwidth);
    }
    public static ZkayType ZkInt(int bitwidth) {
        if (!stypes.containsKey(bitwidth)) {
            throw new IllegalArgumentException("No int type with bitwidth " + bitwidth + " exists.");
        }
        return stypes.get(bitwidth);
    }

    public static BigInteger GetNegativeConstant(BigInteger val, int bitwidth) {
        BigInteger m1 = ZkInt(bitwidth).minusOne;
        return m1.multiply(val).and(m1);
    }

    public static ZkayType checkType(ZkayType expected, ZkayType actual) {
        return checkType(expected, actual, true);
    }
    public static ZkayType checkType(ZkayType expected, ZkayType actual, boolean allow_field_type) {
        if (actual == null || expected == null) throw new IllegalArgumentException("Tried to use untyped wires");
        if (expected.bitwidth == 256 && !allow_field_type) {
            throw new IllegalArgumentException("256bit integers are not supported for this operation");
        }
        if (actual != expected) throw new IllegalArgumentException("Type " + actual.toString() + " does not match expected type " + expected.toString());

        return expected;
    }

    @Override
    public String toString() {
        return (signed ? "s" : "u") + bitwidth;
    }
}