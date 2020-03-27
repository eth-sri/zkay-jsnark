/*******************************************************************************
 * Shared logic for zkay's ECDH pk derivation and ECDH gadgets
 * Based on jsnark's ECDH gadget
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import circuit.config.Config;
import circuit.operations.Gadget;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.math.FieldDivisionGadget;
import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;

import java.math.BigInteger;

/** Constants and common functionality defined in jsnark's ECDHKeyExchangeGadget */
public abstract class ZkayEcGadget extends Gadget {
    public ZkayEcGadget(String... desc) {
        super(desc);
    }

    // Note: this parameterization assumes that the underlying field has
    // Config.FIELD_PRIME =
    // 21888242871839275222246405745257275088548364400416034343698204186575808495617

    public final static int SECRET_BITWIDTH = 253; // number of bits in the
    // exponent. Note that the
    // most significant bit
    // should
    // be set to 1, and the
    // three least significant
    // bits should be be zero.
    // See
    // the constructor

    public final static BigInteger COEFF_A = new BigInteger("126932"); // parameterization
    // in
    // https://eprint.iacr.org/2015/1093.pdf

    public final static BigInteger CURVE_ORDER = new BigInteger(
            "21888242871839275222246405745257275088597270486034011716802747351550446453784");

    // As in curve25519, CURVE_ORDER = SUBGROUP_ORDER * 2^3
    public final static BigInteger SUBGROUP_ORDER = new BigInteger(
            "2736030358979909402780800718157159386074658810754251464600343418943805806723");

    protected static class AffinePoint {
        protected Wire x;
        protected Wire y;

        AffinePoint(Wire x) {
            this.x = x;
        }

        AffinePoint(Wire x, Wire y) {
            this.x = x;
            this.y = y;
        }

        AffinePoint(ZkayEcGadget.AffinePoint p) {
            this.x = p.x;
            this.y = p.y;
        }
    }

    public static void checkSecretBits(CircuitGenerator generator, Wire[] secretBits) {
        /**
         * The secret key bits must be of length SECRET_BITWIDTH and are
         * expected to follow a little endian order. The most significant bit
         * should be 1, and the three least significant bits should be zero.
         */
        generator.addZeroAssertion(secretBits[0],
                "Asserting secret bit conditions");
        generator.addZeroAssertion(secretBits[1],
                "Asserting secret bit conditions");
        generator.addZeroAssertion(secretBits[2],
                "Asserting secret bit conditions");
        generator.addOneAssertion(secretBits[SECRET_BITWIDTH - 1],
                "Asserting secret bit conditions");

        for (int i = 3; i < SECRET_BITWIDTH - 1; i++) {
            // verifying all other bit wires are binary (as this is typically a
            // secret
            // witness by the prover)
            generator.addBinaryAssertion(secretBits[i]);
        }
    }

    // this is only called, when Wire y is provided as witness by the prover
    // (not as input to the gadget)
    protected void assertValidPointOnEC(Wire x, Wire y) {
        Wire ySqr = y.mul(y);
        Wire xSqr = x.mul(x);
        Wire xCube = xSqr.mul(x);
        generator.addEqualityAssertion(ySqr, xCube.add(xSqr.mul(COEFF_A)).add(x));
    }

    protected AffinePoint[] preprocess(AffinePoint p) {
        AffinePoint[] precomputedTable = new AffinePoint[SECRET_BITWIDTH];
        precomputedTable[0] = p;
        for (int j = 1; j < SECRET_BITWIDTH; j += 1) {
            precomputedTable[j] = doubleAffinePoint(precomputedTable[j - 1]);
        }
        return precomputedTable;
    }

    /**
     * Performs scalar multiplication (secretBits must comply with the
     * conditions above)
     */
    protected AffinePoint mul(AffinePoint p, Wire[] secretBits,
                            AffinePoint[] precomputedTable) {

        AffinePoint result = new AffinePoint(
                precomputedTable[secretBits.length - 1]);
        for (int j = secretBits.length - 2; j >= 0; j--) {
            AffinePoint tmp = addAffinePoints(result, precomputedTable[j]);
            Wire isOne = secretBits[j];
            result.x = result.x.add(isOne.mul(tmp.x.sub(result.x)));
            result.y = result.y.add(isOne.mul(tmp.y.sub(result.y)));
        }
        return result;
    }

    protected AffinePoint doubleAffinePoint(AffinePoint p) {
        Wire x_2 = p.x.mul(p.x);
        Wire l1 = new FieldDivisionGadget(x_2.mul(3)
                .add(p.x.mul(COEFF_A).mul(2)).add(1), p.y.mul(2))
                .getOutputWires()[0];
        Wire l2 = l1.mul(l1);
        Wire newX = l2.sub(COEFF_A).sub(p.x).sub(p.x);
        Wire newY = p.x.mul(3).add(COEFF_A).sub(l2).mul(l1).sub(p.y);
        return new AffinePoint(newX, newY);
    }

    protected AffinePoint addAffinePoints(AffinePoint p1, AffinePoint p2) {
        Wire diffY = p1.y.sub(p2.y);
        Wire diffX = p1.x.sub(p2.x);
        Wire q = new FieldDivisionGadget(diffY, diffX).getOutputWires()[0];
        Wire q2 = q.mul(q);
        Wire q3 = q2.mul(q);
        Wire newX = q2.sub(COEFF_A).sub(p1.x).sub(p2.x);
        Wire newY = p1.x.mul(2).add(p2.x).add(COEFF_A).mul(q).sub(q3).sub(p1.y);
        return new AffinePoint(newX, newY);
    }

    public static BigInteger computeYCoordinate(BigInteger x) {
        BigInteger xSqred = x.multiply(x).mod(Config.FIELD_PRIME);
        BigInteger xCubed = xSqred.multiply(x).mod(Config.FIELD_PRIME);
        BigInteger ySqred = xCubed.add(COEFF_A.multiply(xSqred)).add(x)
                .mod(Config.FIELD_PRIME);
        BigInteger y = IntegerFunctions.ressol(ySqred, Config.FIELD_PRIME);
        return y;
    }

    protected void assertPointOrder(AffinePoint p, AffinePoint[] table) {

        Wire o = generator.createConstantWire(SUBGROUP_ORDER);
        Wire[] bits = o.getBitWires(SUBGROUP_ORDER.bitLength()).asArray();

        AffinePoint result = new AffinePoint(table[bits.length - 1]);
        for (int j = bits.length - 2; j >= 1; j--) {
            AffinePoint tmp = addAffinePoints(result, table[j]);
            Wire isOne = bits[j];
            result.x = result.x.add(isOne.mul(tmp.x.sub(result.x)));
            result.y = result.y.add(isOne.mul(tmp.y.sub(result.y)));
        }

        // verify that: result = -p
        generator.addEqualityAssertion(result.x, p.x);
        generator.addEqualityAssertion(result.y, p.y.mul(-1));

        // the reason the last iteration is handled separately is that the
        // addition of
        // affine points will throw an error due to not finding inverse for zero
        // at the last iteration of the scalar multiplication. So, the check in
        // the last iteration is done manually

        // TODO: add more tests to check this method

    }
}
