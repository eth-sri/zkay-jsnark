package zkay.tests;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import org.junit.Test;
import zkay.ZkayBabyJubJubGadget;

import java.math.BigInteger;

public class BabyJubJubTest {
    protected class TestGadget extends ZkayBabyJubJubGadget {

        public TestGadget() {
            buildCircuit();
        }

        protected void buildCircuit() {
            // check native inverse
            Wire a = generator.createConstantWire(new BigInteger("11985782033876175911769025829561891428638139496693105005957757653258"));
            Wire ainv_expected = generator.createConstantWire(new BigInteger("20950552912096304742729232452120498732043875737213521271262032500972060322340"));
            Wire ainv = nativeInverse(a);
            generator.addEqualityAssertion(ainv, ainv_expected);

            // check generator on curve
            Wire g_x = generator.createConstantWire(GENERATOR_U);
            Wire g_y = generator.createConstantWire(GENERATOR_V);
            assertOnCurve(g_x, g_y);

            // check 2*generator on curve
            AffinePoint g = new AffinePoint(g_x, g_y);
            AffinePoint g2 = addPoints(g, g);
            assertOnCurve(g2.x, g2.y);

            // check generator - generator = INFINITY
            AffinePoint gneg = negatePoint(g);
            assertOnCurve(gneg.x, gneg.y);
            AffinePoint inf = addPoints(g, gneg);
            generator.addEqualityAssertion(inf.x, generator.getZeroWire());
            generator.addEqualityAssertion(inf.y, generator.getOneWire());
        }

        @Override
        public Wire[] getOutputWires() {
            Wire dummy = generator.getOneWire();
            return new Wire[]{ dummy };
        }
    }

    @Test
    public void testBabyJubJubGadget() {
        CircuitGenerator cgen = new CircuitGenerator("test") {
            @Override
            protected void buildCircuit() {
                TestGadget gadget = new TestGadget();
                makeOutput(gadget.getOutputWires()[0]);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator evaluator) {}
        };

        cgen.generateCircuit();
        cgen.evalCircuit();
        CircuitEvaluator evaluator = new CircuitEvaluator(cgen);
        evaluator.evaluate();
    }
}
