/*******************************************************************************
 * Wire wrapper which emulates overflow and/or signed arithmetic
 * for various types
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import circuit.auxiliary.LongElement;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.math.LongIntegerFloorDivGadget;
import examples.gadgets.math.LongIntegerModGadget;

import static zkay.ZkayCircuitBase.negate;
import static zkay.ZkayType.*;

public class TypedWire {
    public final Wire wire;
    public final ZkayType type;
    public final String name;

    public TypedWire(Wire wire, ZkayType type, String name, boolean ...restrict) {
        if (wire == null || type == null) {
            throw new IllegalArgumentException("Arguments cannot be null");
        }
        if ((restrict.length > 0 && restrict[0]) || ZkayUtil.ZKAY_RESTRICT_EVERYTHING) {
            wire.restrictBitLength(type.bitwidth);
        }
        this.wire = wire;
        this.type = type;
        this.name = name;
    }

    /** ARITH OPS **/

    public TypedWire plus(TypedWire rhs) {
        ZkayType resultType = checkType(this.type, rhs.type);
        String op = this.name + " + " + rhs.name;
        return handle_overflow(this.wire.add(rhs.wire, op), resultType, false, op);
    }

    public TypedWire minus(TypedWire rhs) {
        ZkayType resultType = checkType(this.type, rhs.type);
        String op = this.name + " - " + rhs.name;
        Wire ret = this.wire.add(negate(rhs).wire, op);
        return handle_overflow(ret, resultType, false, op);
    }

    public TypedWire times(TypedWire rhs) {
        ZkayType resultType = checkType(this.type, rhs.type);
        String op = this.name + " * " + rhs.name;
        if (resultType.bitwidth == 256) {
            // Don't care about overflow with uint type
            return new TypedWire(this.wire.mul(rhs.wire, op), resultType, op);
        }
        else if (resultType.bitwidth <= 120) {
            // Result always fits into 240 < 253 bits
            return handle_overflow(this.wire.mul(rhs.wire, op), resultType, true, op);
        }
        else {
            // Result could overflow 253 bits -> do it in two halves to get correct overflow behavior
            Wire[] LhsLoHi = this.wire.getBitWires(resultType.bitwidth).packBitsIntoWords(124);
            Wire[] RhsLoHi = rhs.wire.getBitWires(resultType.bitwidth).packBitsIntoWords(124);

            // https://www.codeproject.com/Tips/618570/UInt-Multiplication-Squaring, BSD license
            Wire[] ansLoHi = LhsLoHi[0].mul(RhsLoHi[0], op + "[lo*lo]").getBitWires(resultType.bitwidth).packBitsIntoWords(124);
            Wire hiLoMul = handle_overflow(LhsLoHi[1].mul(RhsLoHi[0], op + "[hi*lo]"), Zk124, true, op + "[hi*lo]").wire;
            Wire loHiMul = handle_overflow(LhsLoHi[0].mul(RhsLoHi[1], op + "[lo*hi]"), Zk124, true, op + "[lo*hi]").wire;
            Wire hiLoPlusloHi = handle_overflow(hiLoMul.add(loHiMul, op + "[hi*lo + lo*hi]"), Zk124, false, op + "[hi*lo + lo*hi]").wire;
            ansLoHi[1] = handle_overflow(ansLoHi[1].add(hiLoPlusloHi, op + "[anshi + hi*lo + lo*hi]"), Zk124, false, op + "[anshi + hi*lo + lo*hi]").wire;

            Wire[] ans = new WireArray(ansLoHi).getBits(124).packBitsIntoWords(resultType.bitwidth, op + "[combine hi and lo]");
            if (ans.length != 1) {
                throw new RuntimeException("Multiplication ans array has wrong length");
            }
            return new TypedWire(ans[0], resultType, op);
        }
    }

    public TypedWire divideBy(TypedWire rhs) {
        ZkayType resultType = checkType(this.type, rhs.type);
        String op = this.name + " / " + rhs.name;
        CircuitGenerator generator = CircuitGenerator.getActiveCircuitGenerator();
        generator.addOneAssertion(rhs.wire.checkNonZero(), "no div by 0");

        // Sign handling...
        Wire resultSign = generator.getZeroWire();
        Wire lhsWire = this.wire;
        Wire rhsWire = rhs.wire;

        if (this.type.signed) {
            Wire lhsSign = lhsWire.getBitWires(this.type.bitwidth).get(this.type.bitwidth - 1);
            lhsWire = lhsSign.mux(negate(this).wire, lhsWire);
            resultSign = resultSign.xorBitwise(lhsSign, 1);
        }
        if (rhs.type.signed) {
            Wire rhsSign = rhsWire.getBitWires(rhs.type.bitwidth).get(rhs.type.bitwidth - 1);
            rhsWire = rhsSign.mux(negate(rhs).wire, rhsWire);
            resultSign = resultSign.xorBitwise(rhsSign, 1);
        }

        // Need to operate on long integers, regular div / mod gadget only works for <= 126 bits
        LongElement lhsLong = new LongElement(lhsWire.getBitWires(this.type.bitwidth));
        LongElement rhsLong = new LongElement(rhsWire.getBitWires(rhs.type.bitwidth));
        LongElement q = new LongIntegerFloorDivGadget(lhsLong, rhsLong, op).getQuotient();
        Wire resAbs = q.getBits(resultType.bitwidth).packBitsIntoWords(resultType.bitwidth)[0];

        TypedWire resPos = new TypedWire(resAbs, resultType, op);
        TypedWire resNeg = negate(resPos);
        return new TypedWire(resultSign.mux(resNeg.wire, resPos.wire), resultType, op);
    }

    public TypedWire modulo(TypedWire rhs) {
        ZkayType resultType = checkType(this.type, rhs.type);
        String op = this.name + " % " + rhs.name;
        CircuitGenerator generator = CircuitGenerator.getActiveCircuitGenerator();
        generator.addOneAssertion(rhs.wire.checkNonZero(), "no div by 0");

        // Sign handling...
        Wire resultSign = generator.getZeroWire();
        Wire lhsWire = this.wire;
        Wire rhsWire = rhs.wire;

        if (this.type.signed) {
            Wire lhsSign = lhsWire.getBitWires(this.type.bitwidth).get(this.type.bitwidth - 1);
            lhsWire = lhsSign.mux(negate(this).wire, lhsWire);
            resultSign = lhsSign;
        }
        if (rhs.type.signed) {
            Wire rhsSign = rhsWire.getBitWires(rhs.type.bitwidth).get(rhs.type.bitwidth - 1);
            rhsWire = rhsSign.mux(negate(rhs).wire, rhsWire);
        }

        // Need to operate on long integers, regular div / mod gadget only works for <= 126 bits
        LongElement lhsLong = new LongElement(lhsWire.getBitWires(this.type.bitwidth));
        LongElement rhsLong = new LongElement(rhsWire.getBitWires(rhs.type.bitwidth));
        LongElement r = new LongIntegerModGadget(lhsLong, rhsLong, true, op).getRemainder();
        Wire resAbs = r.getBits(resultType.bitwidth).packBitsIntoWords(resultType.bitwidth)[0];

        TypedWire resPos = new TypedWire(resAbs, resultType, op);
        TypedWire resNeg = negate(resPos);
        return new TypedWire(resultSign.mux(resNeg.wire, resPos.wire), resultType, op);
    }

    /** BIT OPS */

    public TypedWire bitOr(TypedWire rhs) {
        ZkayType resultType = checkType(this.type, rhs.type, false);
        String op = this.name + " | " + rhs.name;
        Wire res = this.wire.orBitwise(rhs.wire, resultType.bitwidth, op);
        return new TypedWire(res, resultType, op);
    }

    public TypedWire bitAnd(TypedWire rhs) {
        ZkayType resultType = checkType(this.type, rhs.type, false);
        String op = this.name + " & " + rhs.name;
        Wire res = this.wire.andBitwise(rhs.wire, resultType.bitwidth, op);
        return new TypedWire(res, resultType, op);
    }

    public TypedWire bitXor(TypedWire rhs) {
        ZkayType resultType = checkType(this.type, rhs.type, false);
        String op = this.name + " ^ " + rhs.name;
        Wire res = this.wire.xorBitwise(rhs.wire, resultType.bitwidth, op);
        return new TypedWire(res, resultType, op);
    }

    /** SHIFT OPS */

    public TypedWire shiftLeftBy(int amount) {
        ZkayType resultType = checkType(this.type, this.type, false);
        String op = this.name + " << " + amount;
        Wire res = this.wire.shiftLeft(resultType.bitwidth, amount, op);
        return new TypedWire(res, resultType, op);
    }

    public TypedWire shiftRightBy(int amount) {
        ZkayType resultType = checkType(this.type, this.type, false);
        Wire res;
        String op = this.name + " >> " + amount;
        if (resultType.signed) {
            res = this.wire.shiftArithRight(resultType.bitwidth, Math.min(amount, resultType.bitwidth), op);
        } else {
            res = this.wire.shiftRight(resultType.bitwidth, amount, op);
        }
        return new TypedWire(res, resultType, op);
    }

    /** EQ OPS **/

    public TypedWire isEqualTo(TypedWire rhs) {
        checkType(this.type, rhs.type);
        String op = this.name + " == " + rhs.name;
        return new TypedWire(this.wire.isEqualTo(rhs.wire, op), ZkBool, op);
    }

    public TypedWire isNotEqualTo(TypedWire rhs) {
        checkType(this.type, rhs.type);
        String op = this.name + " != " + rhs.name;
        return new TypedWire(this.wire.sub(rhs.wire, op).checkNonZero(op), ZkBool, op);
    }

    /** INEQ OPS **/

    public TypedWire isLessThan(TypedWire rhs) {
        ZkayType commonType = checkType(this.type, rhs.type);
        String op = this.name + " < " + rhs.name;
        if (commonType.signed) {
            Wire lhsSign = this.wire.getBitWires(commonType.bitwidth).get(commonType.bitwidth-1);
            Wire rhsSign = rhs.wire.getBitWires(commonType.bitwidth).get(commonType.bitwidth-1);

            Wire alwaysLt = lhsSign.isGreaterThan(rhsSign, 1);
            Wire sameSign = lhsSign.isEqualTo(rhsSign);
            Wire lhsLess = this.wire.isLessThan(rhs.wire, commonType.bitwidth);
            Wire isLt = alwaysLt.or(sameSign.and(lhsLess), op);
            return new TypedWire(isLt, ZkBool, op);
        } else {
            // Note: breaks if value > 253 bit
            return new TypedWire(this.wire.isLessThan(rhs.wire, Math.min(253, commonType.bitwidth), op), ZkBool, op);
        }
    }

    public TypedWire isLessThanOrEqual(TypedWire rhs) {
        ZkayType commonType = checkType(this.type, rhs.type);
        String op = this.name + " <= " + rhs.name;
        if (commonType.signed) {
            Wire lhsSign = this.wire.getBitWires(commonType.bitwidth).get(commonType.bitwidth-1);
            Wire rhsSign = rhs.wire.getBitWires(commonType.bitwidth).get(commonType.bitwidth-1);

            Wire alwaysLt = lhsSign.isGreaterThan(rhsSign, 1);
            Wire sameSign = lhsSign.isEqualTo(rhsSign);
            Wire lhsLessEq = this.wire.isLessThanOrEqual(rhs.wire, commonType.bitwidth);
            Wire isLt = alwaysLt.or(sameSign.and(lhsLessEq), op);
            return new TypedWire(isLt, ZkBool, op);
        } else {
            // Note: breaks if value > 253 bit
            return new TypedWire(this.wire.isLessThanOrEqual(rhs.wire, Math.min(253, commonType.bitwidth), op), ZkBool, op);
        }
    }

    public TypedWire isGreaterThan(TypedWire rhs) {
        return rhs.isLessThan(this);
    }

    public TypedWire isGreaterThanOrEqual(TypedWire rhs) {
        return rhs.isLessThanOrEqual(this);
    }

    /** BOOL OPS */

    public TypedWire and(TypedWire rhs) {
        checkType(ZkBool, this.type);
        checkType(ZkBool, rhs.type);
        String op = this.name + " && " + rhs.name;
        return new TypedWire(this.wire.and(rhs.wire, op), ZkBool, op);
    }

    public TypedWire or(TypedWire rhs) {
        checkType(ZkBool, this.type);
        checkType(ZkBool, rhs.type);
        String op = this.name + " || " + rhs.name;
        return new TypedWire(this.wire.or(rhs.wire, op), ZkBool, op);
    }

    private static TypedWire handle_overflow(Wire w, ZkayType targetType, boolean was_mul, String name) {
        if (targetType.bitwidth < 256) {
            // Downcast or result with overflow modulo < field prime -> modulo/mask lower bits
            int from_bits = Math.min(256, was_mul ? targetType.bitwidth * 2 : targetType.bitwidth + 1);
            w = w.trimBits(from_bits, targetType.bitwidth, "% 2^" + targetType.bitwidth);
        }
        return new TypedWire(w, targetType, targetType.toString() + "(" + name + ")");
    }
}
