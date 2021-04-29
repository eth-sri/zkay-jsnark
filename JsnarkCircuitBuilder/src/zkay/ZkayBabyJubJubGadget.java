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
 * https://github.com/HarryR/ethsnarks/blob/2020dec635ee606da1f66118a5f7c6283a4cb6a0/.appendix/ejubjub.sage
 */
public abstract class ZkayBabyJubJubGadget extends Gadget {
    public ZkayBabyJubJubGadget(String... desc) {
        super(desc);

        // Note: this parameterization assumes that the underlying field has
        // Config.FIELD_PRIME =
        // 21888242871839275222246405745257275088548364400416034343698204186575808495617
        // (this is the base field order of BabyJubJub)

        assert(Config.FIELD_PRIME.toString().equals("21888242871839275222246405745257275088548364400416034343698204186575808495617"));
    }

    public final static BigInteger BASE_ORDER = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");

    public final static BigInteger CURVE_ORDER = new BigInteger("21888242871839275222246405745257275088614511777268538073601725287587578984328");

    public final static BigInteger COFACTOR = new BigInteger("8");

    public final static BigInteger COEFF_A = new BigInteger("168700");

    public final static BigInteger COEFF_D = new BigInteger("168696");

    public final static BigInteger MONTGOMERY_A = new BigInteger("168698");

    public final static BigInteger MONTGOMERY_SCALE = new BigInteger("1");

    public final static BigInteger GENERATOR_U = new BigInteger("16540640123574156134436876038791482806971768689494387082833631921987005038935");

    public final static BigInteger GENERATOR_V = new BigInteger("20819045374670962167435360035096875258406992893633759881276124905556507972311");

    // INFINITY = (0, 1)

    protected static class AffinePoint {
        public Wire x;
        public Wire y;

        public AffinePoint(Wire x) {
            this.x = x;
        }

        public AffinePoint(Wire x, Wire y) {
            this.x = x;
            this.y = y;
        }

        public AffinePoint(ZkayBabyJubJubGadget.AffinePoint p) {
            this.x = p.x;
            this.y = p.y;
        }
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

    protected AffinePoint addPoints(AffinePoint p1, AffinePoint p2) {
        // Twisted Edwards addition according to https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Addition_on_twisted_Edwards_curves

        Wire a1 = p1.x.mul(p2.y).add(p1.y.mul(p2.x));
        Wire a2 = p1.x.mul(p2.x).mul(p1.y.mul(p2.y)).mul(COEFF_D).add(1);
        Wire b1 = p1.y.mul(p2.y).sub(p1.x.mul(p2.x).mul(COEFF_A));
        Wire b2 = p1.x.mul(p2.x).mul(p1.y.mul(p2.y)).mul(COEFF_D).negate().add(1);

        Wire x = a1.mul(nativeInverse(a2));
        Wire y = b1.mul(nativeInverse(b2));
        return new AffinePoint(x, y);
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
