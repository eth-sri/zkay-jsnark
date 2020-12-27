package zkay.tests;

import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import org.junit.Test;
import util.Util;
import zkay.ZkayPaillierDecGadget;
import zkay.ZkayPaillierEncGadget;
import zkay.ZkayPaillierFastDecGadget;
import zkay.ZkayPaillierFastEncGadget;

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

	@Test
	public void test256BitEncryption() {
		BigInteger plain = new BigInteger("58620521968995858419238449046464883186412581610038046858008683322252437292505");
		BigInteger random = new BigInteger("66895129274476067543864711343178574027057505369800972938068894913816799963509");
		BigInteger n = new BigInteger("71705678335151044143714697909938764102247769560297862447809589632641441407751");
		BigInteger generator = new BigInteger("27");
		PaillierEncCircuitGenerator enc = new PaillierEncCircuitGenerator("Paillier Enc", plain, random, n, generator);
		BigInteger cipher = enc.computeResult();
		assertEquals(new BigInteger("3507594166975424775795724429703273237581693482251350761249288990776233360058698524194928568270852256828927631672223419615120374443722184016172266681685963"), cipher);
	}

	@Test
	public void test256BitDecryption() {
		BigInteger n = new BigInteger("71705678335151044143714697909938764102247769560297862447809589632641441407751");
		BigInteger cipher = new BigInteger("3507594166975424775795724429703273237581693482251350761249288990776233360058698524194928568270852256828927631672223419615120374443722184016172266681685963");
		BigInteger lambda = new BigInteger("35852839167575522071857348954969382050854184697828828629810896599748215236036");
		BigInteger mu = new BigInteger("38822179779668243734206910236945399376867932682990009748733172869327079310544");
		PaillierDecCircuitGenerator dec = new PaillierDecCircuitGenerator("Paillier Dec", cipher, n, lambda, mu);
		BigInteger plain = dec.computeResult();
		assertEquals(new BigInteger("58620521968995858419238449046464883186412581610038046858008683322252437292505"), plain);
	}

	@Test
	public void test256BitFastEncryption() {
		BigInteger plain = new BigInteger("58620521968995858419238449046464883186412581610038046858008683322252437292505");
		BigInteger random = new BigInteger("66895129274476067543864711343178574027057505369800972938068894913816799963509");
		BigInteger n = new BigInteger("71705678335151044143714697909938764102247769560297862447809589632641441407751");
		PaillierFastEncCircuitGenerator enc = new PaillierFastEncCircuitGenerator("Paillier Enc", n, plain, random);
		BigInteger cipher = enc.computeResult();
		assertEquals(new BigInteger("3505470225408264473467386810920807437821858174488064393364776746993551415781505226520807868351169269605924531821264861279222635802527118722105662515867136"), cipher);
	}

	@Test
	public void test256BitFastDecryption() {
		BigInteger n = new BigInteger("71705678335151044143714697909938764102247769560297862447809589632641441407751");
		BigInteger lambda = new BigInteger("71705678335151044143714697909938764101708369395657657259621793199496430472072");
		BigInteger cipher = new BigInteger("3505470225408264473467386810920807437821858174488064393364776746993551415781505226520807868351169269605924531821264861279222635802527118722105662515867136");
		PaillierFastDecCircuitGenerator dec = new PaillierFastDecCircuitGenerator("Paillier Dec", n, lambda, cipher);
		BigInteger plain = dec.computeResult();
		assertEquals(new BigInteger("58620521968995858419238449046464883186412581610038046858008683322252437292505"), plain);
	}

	// Don't look. Here lies the Land of Copy & Paste

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

	private static class PaillierFastEncCircuitGenerator extends CircuitGenerator {

		private final BigInteger n;
		private final BigInteger plain;
		private final BigInteger random;

		private LongElement nWire;
		private LongElement plainWire;
		private LongElement randomWire;

		private PaillierFastEncCircuitGenerator(String name, BigInteger n, BigInteger plain, BigInteger random) {
			super(name);
			this.n = n;
			this.plain = plain;
			this.random = random;
		}

		@Override
		protected void buildCircuit() {
			int nBits = max(n.bitLength(), 1);
			nWire = createLongElementInput(nBits, "n");
			plainWire = createLongElementInput(max(plain.bitLength(), 1), "plain");
			randomWire = createLongElementInput(max(random.bitLength(), 1), "random");
			ZkayPaillierFastEncGadget enc = new ZkayPaillierFastEncGadget(nWire, nBits, plainWire, randomWire);
			makeOutputArray(enc.getOutputWires(), "cipher");
		}

		@Override
		public void generateSampleInput(CircuitEvaluator evaluator) {
			evaluator.setWireValue(nWire, n, LongElement.CHUNK_BITWIDTH);
			evaluator.setWireValue(plainWire, plain, LongElement.CHUNK_BITWIDTH);
			evaluator.setWireValue(randomWire, random, LongElement.CHUNK_BITWIDTH);
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

	private static class PaillierFastDecCircuitGenerator extends CircuitGenerator {

		private final BigInteger n;
		private final BigInteger lambda;
		private final BigInteger cipher;

		private LongElement nWire;
		private LongElement lambdaWire;
		private LongElement cipherWire;

		private PaillierFastDecCircuitGenerator(String name, BigInteger n, BigInteger lambda, BigInteger cipher) {
			super(name);
			this.n = n;
			this.lambda = lambda;
			this.cipher = cipher;
		}

		@Override
		protected void buildCircuit() {
			int nBits = max(n.bitLength(), 1);
			nWire = createLongElementInput(nBits, "n");
			lambdaWire = createLongElementInput(max(lambda.bitLength(), 1), "lambda");
			cipherWire = createLongElementInput(max(cipher.bitLength(), 1), "cipher");
			ZkayPaillierFastDecGadget dec = new ZkayPaillierFastDecGadget(nWire, nBits, lambdaWire, cipherWire);
			makeOutputArray(dec.getOutputWires(), "plain");
		}

		@Override
		public void generateSampleInput(CircuitEvaluator evaluator) {
			evaluator.setWireValue(nWire, n, LongElement.CHUNK_BITWIDTH);
			evaluator.setWireValue(lambdaWire, lambda, LongElement.CHUNK_BITWIDTH);
			evaluator.setWireValue(cipherWire, cipher, LongElement.CHUNK_BITWIDTH);
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
