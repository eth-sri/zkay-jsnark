package zkay.tests;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import org.junit.Assert;
import org.junit.Test;
import zkay.ZkayECDHGadget;
import zkay.ZkayECDHGenerator;
import zkay.ZkayEcPkDerivationGadget;

import java.math.BigInteger;

public class EcdhTests {
    @Test
    public void testECDH() {
        BigInteger sec1 = ZkayECDHGenerator.rnd_to_secret("0032f06dfe06a7f7d1a4f4292c136ee78b5d4b4bb26904b2363330bd213ccea0");
        BigInteger sec2 = ZkayECDHGenerator.rnd_to_secret("6c0f17e169532e67f0fa96999f652bca942bd97617295a025eaa6c5d1cd3fd5c");

        BigInteger pk1 = new BigInteger(ZkayECDHGenerator.derivePk(sec1), 16);
        BigInteger pk2 = new BigInteger(ZkayECDHGenerator.derivePk(sec2), 16);

        String sk1 = ZkayECDHGenerator.getSharedSecret(pk2, sec1);
        String sk2 = ZkayECDHGenerator.getSharedSecret(pk1, sec2);
        Assert.assertEquals(sk1, sk2);
    }

    @Test
    public void testSameAsGadget() {
        BigInteger sec1 = ZkayECDHGenerator.rnd_to_secret("0032f06dfe06a7f7d1a4f4292c136ee78b5d4b4bb26904b2363330bd213ccea0");
        BigInteger sec2 = ZkayECDHGenerator.rnd_to_secret("6c0f17e169532e67f0fa96999f652bca942bd97617295a025eaa6c5d1cd3fd5c");

        CircuitGenerator cgen = new CircuitGenerator("pkder") {
            @Override
            protected void buildCircuit() {
               Wire s = createConstantWire(sec1);
               makeOutput(new ZkayEcPkDerivationGadget(s, true).getOutputWires()[0]);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator evaluator) {}
        };
        cgen.generateCircuit();
        cgen.evalCircuit();
        CircuitEvaluator evaluator = new CircuitEvaluator(cgen);
        evaluator.evaluate();
        BigInteger pk1_circ = evaluator.getWireValue(cgen.getOutWires().get(0));

        cgen = new CircuitGenerator("pkder") {
            @Override
            protected void buildCircuit() {
                Wire s = createConstantWire(sec2);
                makeOutput(new ZkayEcPkDerivationGadget(s, true).getOutputWires()[0]);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator evaluator) {}
        };
        cgen.generateCircuit();
        cgen.evalCircuit();
        evaluator = new CircuitEvaluator(cgen);
        evaluator.evaluate();
        BigInteger pk2_circ = evaluator.getWireValue(cgen.getOutWires().get(0));

        BigInteger pk1 = new BigInteger(ZkayECDHGenerator.derivePk(sec1), 16);
        BigInteger pk2 = new BigInteger(ZkayECDHGenerator.derivePk(sec2), 16);
        Assert.assertEquals(pk1, pk1_circ);
        Assert.assertEquals(pk2, pk2_circ);

        cgen = new CircuitGenerator("ecdh") {
            @Override
            protected void buildCircuit() {
                Wire p = createConstantWire(pk2);
                Wire s = createConstantWire(sec1);
                makeOutput(new ZkayECDHGadget(p, s, false).getOutputWires()[0]);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator evaluator) {}
        };
        cgen.generateCircuit();
        cgen.evalCircuit();
        evaluator = new CircuitEvaluator(cgen);
        evaluator.evaluate();
        BigInteger sk_circ = evaluator.getWireValue(cgen.getOutWires().get(0));

        BigInteger sk_exp = new BigInteger(ZkayECDHGenerator.getSharedSecret(pk2, sec1), 16);
        Assert.assertEquals(sk_exp, sk_circ);
    }
}
