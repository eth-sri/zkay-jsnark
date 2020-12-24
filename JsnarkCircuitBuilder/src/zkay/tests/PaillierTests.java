package zkay.tests;

import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import org.junit.Test;
import util.Util;
import zkay.ZkayPaillierDecGadget;
import zkay.ZkayPaillierEncGadget;

import java.math.BigInteger;

import static java.lang.Math.max;
import static org.junit.Assert.assertEquals;

public class PaillierTests {

	@Test
	public void testEncryptionExample() {
		BigInteger plain = new BigInteger("42");
		BigInteger random = new BigInteger("25");
		BigInteger n = new BigInteger("9047");
		BigInteger generator = new BigInteger("27");
		PaillierEncCircuitGenerator enc = new PaillierEncCircuitGenerator("Paillier Enc", plain, random, n, generator);
		BigInteger cipher = enc.computeResult();
		assertEquals(new BigInteger("45106492"), cipher);
	}

	@Test
	public void testDecryptionExample() {
		BigInteger n = new BigInteger("9047");
		BigInteger cipher = new BigInteger("2587834");
		BigInteger lambda = new BigInteger("4428");
		BigInteger mu = new BigInteger("1680");
		PaillierDecCircuitGenerator dec = new PaillierDecCircuitGenerator("Paillier Dec", cipher, n, lambda, mu);
		BigInteger plain = dec.computeResult();
		assertEquals(new BigInteger("55"), plain);
	}

	private static class PaillierEncCircuitGenerator extends CircuitGenerator {

		private final BigInteger plain;
		private final BigInteger random;
		private final BigInteger n;
		private final BigInteger generator;

		private LongElement plainWire;
		private LongElement randomWire;
		private LongElement nWire;
		private LongElement generatorWire;

		private PaillierEncCircuitGenerator(String name, BigInteger plain, BigInteger random,
		                                    BigInteger n, BigInteger generator) {
			super(name);
			this.plain = plain;
			this.random = random;
			this.n = n;
			this.generator = generator;
		}

		@Override
		protected void buildCircuit() {
			plainWire = createLongElementInput(max(plain.bitLength(), 1), "plain");
			randomWire = createLongElementInput(max(random.bitLength(), 1), "random");
			int nBits = max(n.bitLength(), 1);
			nWire = createLongElementInput(nBits, "n");
			generatorWire = createLongElementInput(max(generator.bitLength(), 1), "generator");
			ZkayPaillierEncGadget enc = new ZkayPaillierEncGadget(nWire, nBits, generatorWire, plainWire, randomWire);
			makeOutputArray(enc.getOutputWires(), "cipher");
		}

		@Override
		public void generateSampleInput(CircuitEvaluator evaluator) {
			evaluator.setWireValue(plainWire, plain, LongElement.CHUNK_BITWIDTH);
			evaluator.setWireValue(randomWire, random, LongElement.CHUNK_BITWIDTH);
			evaluator.setWireValue(nWire, n, LongElement.CHUNK_BITWIDTH);
			evaluator.setWireValue(generatorWire, generator, LongElement.CHUNK_BITWIDTH);
		}

		public BigInteger computeResult() {
			long t1 = System.nanoTime();
			generateCircuit();
			long t2 = System.nanoTime();
			double ms = 1.e-6 * (t2 - t1);
			System.out.format("Building took %.3f ms\n", ms);
			evalCircuit();

			CircuitEvaluator evaluator = getCircuitEvaluator();
			BigInteger[] outValues = evaluator.getWiresValues(getOutWires().toArray(new Wire[0]));
			return Util.group(outValues, LongElement.CHUNK_BITWIDTH);
		}
	}

	private static class PaillierDecCircuitGenerator extends CircuitGenerator {

		private final BigInteger cipher;
		private final BigInteger n;
		private final BigInteger lambda;
		private final BigInteger mu;

		private LongElement cipherWire;
		private LongElement nWire;
		private LongElement lambdaWire;
		private LongElement muWire;

		private PaillierDecCircuitGenerator(String name, BigInteger cipher, BigInteger n,
		                                    BigInteger lambda, BigInteger mu) {
			super(name);
			this.cipher = cipher;
			this.n = n;
			this.lambda = lambda;
			this.mu = mu;
		}

		@Override
		protected void buildCircuit() {
			cipherWire = createLongElementInput(max(cipher.bitLength(), 1), "cipher");
			int nBits = max(n.bitLength(), 1);
			nWire = createLongElementInput(nBits, "n");
			lambdaWire = createLongElementInput(max(lambda.bitLength(), 1), "lambda");
			muWire = createLongElementInput(max(mu.bitLength(), 1), "mu");
			ZkayPaillierDecGadget dec = new ZkayPaillierDecGadget(nWire, nBits, lambdaWire, muWire, cipherWire);
			makeOutputArray(dec.getOutputWires(), "plain");
		}

		@Override
		public void generateSampleInput(CircuitEvaluator evaluator) {
			evaluator.setWireValue(cipherWire, cipher, LongElement.CHUNK_BITWIDTH);
			evaluator.setWireValue(nWire, n, LongElement.CHUNK_BITWIDTH);
			evaluator.setWireValue(lambdaWire, lambda, LongElement.CHUNK_BITWIDTH);
			evaluator.setWireValue(muWire, mu, LongElement.CHUNK_BITWIDTH);
		}

		public BigInteger computeResult() {
			long t1 = System.nanoTime();
			generateCircuit();
			long t2 = System.nanoTime();
			double ms = 1.e-6 * (t2 - t1);
			System.out.format("Building took %.3f ms\n", ms);
			evalCircuit();

			CircuitEvaluator evaluator = getCircuitEvaluator();
			BigInteger[] outValues = evaluator.getWiresValues(getOutWires().toArray(new Wire[0]));
			return Util.group(outValues, LongElement.CHUNK_BITWIDTH);
		}
	}
}
