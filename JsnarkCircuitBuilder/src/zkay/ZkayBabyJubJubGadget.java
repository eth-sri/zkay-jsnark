package zkay;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.eval.Instruction;
import circuit.operations.Gadget;
import circuit.structure.Wire;

import java.math.BigInteger;

/**
 * Gadget for operations on the BabyJubJub elliptic curve (Twisted Edwards curve over BN254).
 * Parameters are from:
 * https://iden3-docs.readthedocs.io/en/latest/iden3_repos/research/publications/zkproof-standards-workshop-2/baby-jubjub/baby-jubjub.html
 */
public abstract class ZkayBabyJubJubGadget extends Gadget {
    public ZkayBabyJubJubGadget(String... desc) {
        super(desc);

        // We assume the underlying field matches the base field of BabyJubJub (so that we can avoid alignment/modulus)
        assert(Config.FIELD_PRIME.toString().equals("21888242871839275222246405745257275088548364400416034343698204186575808495617"));
    }

    public final static BigInteger BASE_ORDER = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");

    public final static BigInteger CURVE_ORDER = new BigInteger("2736030358979909402780800718157159386076813972158567259200215660948447373041");

    public final static BigInteger COFACTOR = new BigInteger("8");

    public final static BigInteger COEFF_A = new BigInteger("1");

    public final static BigInteger COEFF_D = new BigInteger("9706598848417545097372247223557719406784115219466060233080913168975159366771");

    // arbitrary generator
    public final static BigInteger GENERATOR_X = new BigInteger("11904062828411472290643689191857696496057424932476499415469791423656658550213");

    public final static BigInteger GENERATOR_Y = new BigInteger("9356450144216313082194365820021861619676443907964402770398322487858544118183");

    public static class JubJubPoint {
        public Wire x;
        public Wire y;

        public JubJubPoint(Wire x, Wire y) {
            this.x = x;
            this.y = y;
        }
    }

    protected JubJubPoint getInfinity() {
        return new JubJubPoint(generator.getZeroWire(), generator.getOneWire());
    }

    protected JubJubPoint getGenerator() {
        Wire g_x = generator.createConstantWire(GENERATOR_X);
        Wire g_y = generator.createConstantWire(GENERATOR_Y);
        return new JubJubPoint(g_x, g_y);
    }

    protected void assertOnCurve(Wire x, Wire y) {
        // assert COEFF_A*x*x + y*y == 1 + COEFF_D*x*x*y*y
        Wire xSqr = x.mul(x);
        Wire ySqr = y.mul(y);
        Wire prod = xSqr.mul(ySqr);
        Wire lhs = xSqr.mul(COEFF_A).add(ySqr);
        Wire rhs = prod.mul(COEFF_D).add(1);
        generator.addEqualityAssertion(lhs, rhs);
    }

    protected JubJubPoint addPoints(JubJubPoint p1, JubJubPoint p2) {
        // Twisted Edwards addition according to https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Addition_on_twisted_Edwards_curves

        Wire a1 = p1.x.mul(p2.y).add(p1.y.mul(p2.x));
        Wire a2 = p1.x.mul(p2.x).mul(p1.y.mul(p2.y)).mul(COEFF_D).add(1);
        Wire b1 = p1.y.mul(p2.y).sub(p1.x.mul(p2.x).mul(COEFF_A));
        Wire b2 = p1.x.mul(p2.x).mul(p1.y.mul(p2.y)).mul(COEFF_D).negate().add(1);

        Wire x = a1.mul(nativeInverse(a2));
        Wire y = b1.mul(nativeInverse(b2));
        return new JubJubPoint(x, y);
    }

    protected JubJubPoint negatePoint(JubJubPoint p) {
        Wire new_x = p.x.negate();
        return new JubJubPoint(new_x, p.y);
    }

    /**
     * @param scalarBits the scalar bit representation in little-endian order
     */
    protected JubJubPoint mulScalar(JubJubPoint p, Wire[] scalarBits) {
        // Scalar point multiplication using double-and-add algorithm
        JubJubPoint result = getInfinity();
        JubJubPoint doubling = p;

        for (int i = 0; i < scalarBits.length; i++) {
            JubJubPoint q = addPoints(doubling, result);
            Wire new_x = scalarBits[i].mux(q.x, result.x);
            Wire new_y = scalarBits[i].mux(q.y, result.y);
            result = new JubJubPoint(new_x, new_y);
            doubling = addPoints(doubling, doubling);
        }

        return result;
    }

    /**
     * Returns a wire holding the inverse of a in the native base field.
     */
    protected Wire nativeInverse(Wire a) {
        Wire ainv = generator.createProverWitnessWire();
        generator.specifyProverWitnessComputation(new Instruction() {
            @Override
            public void evaluate(CircuitEvaluator evaluator) {
                BigInteger aValue = evaluator.getWireValue(a);
                BigInteger inverseValue = aValue.modInverse(BASE_ORDER);
                evaluator.setWireValue(ainv, inverseValue);
            }
        });

        // check if a * ainv = 1 (natively)
        Wire test = a.mul(ainv);
        generator.addEqualityAssertion(test, generator.getOneWire());

        return ainv;
    }
}
