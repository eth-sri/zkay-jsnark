package zkay;

import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.eval.Instruction;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import examples.gadgets.math.LongIntegerFloorDivGadget;
import examples.gadgets.math.LongIntegerModGadget;
import examples.gadgets.math.LongIntegerModPowGadget;
import util.Util;

import java.math.BigInteger;

public class ZkayPaillierFastDecGadget extends Gadget {

	private final LongElement n;
	private final LongElement nSquare;
	private final int nBits;
	private final LongElement lambda;
	private final LongElement cipher;
	private LongElement plain;

	public ZkayPaillierFastDecGadget(LongElement n, int nBits, LongElement lambda, LongElement cipher, String... desc) {
		super(desc);
		this.n = n;
		this.nBits = nBits;
		int nSquareMaxBits = 2 * nBits;
		int maxNumChunks = (nSquareMaxBits + (LongElement.CHUNK_BITWIDTH - 1)) / LongElement.CHUNK_BITWIDTH;
		this.nSquare = n.mul(n).align(maxNumChunks);
		this.lambda = lambda;
		this.cipher = cipher;
		buildCircuit();
	}

	private void buildCircuit() {
		int nSquareMinBits = 2 * nBits - 1; // Minimum bit length of n^2
		LongElement lambdaInverse = computeInverse(lambda, n, nBits);

		// plain = L(cipher^lambda mod n^2) / lambda mod n
		LongElement cPowLambda = new LongIntegerModPowGadget(cipher, lambda, nSquare, nSquareMinBits, "c^lambda").getResult();
		LongElement minusOne = subtractOneFrom(cPowLambda);
		LongElement divByN = new LongIntegerFloorDivGadget(minusOne, n, "(c^lambda - 1) / n").getQuotient();
		LongElement timesLambdaInverse = divByN.mul(lambdaInverse);
		plain = new LongIntegerModGadget(timesLambdaInverse, n, nBits, true).getRemainder();
	}

	private LongElement computeInverse(LongElement value, LongElement mod, int modBits) {
		Wire[] inverseWires = generator.createProverWitnessWireArray(mod.getSize());
		LongElement inverse = new LongElement(inverseWires, mod.getCurrentBitwidth());

		generator.specifyProverWitnessComputation(new Instruction() {
			@Override
			public void evaluate(CircuitEvaluator evaluator) {
				BigInteger origValue = evaluator.getWireValue(value, LongElement.CHUNK_BITWIDTH);
				BigInteger modValue = evaluator.getWireValue(mod, LongElement.CHUNK_BITWIDTH);
				BigInteger inverseValue = origValue.modInverse(modValue);
				evaluator.setWireValue(inverseWires, Util.split(inverseValue, LongElement.CHUNK_BITWIDTH));
			}
		});

		inverse.restrictBitwidth();
		LongElement product = value.mul(inverse).align(2 * mod.getSize());
		LongElement modulo = new LongIntegerModGadget(product, mod, modBits, false).getRemainder();
		modulo.assertEquality(new LongElement(new BigInteger[] {BigInteger.ONE}));
		return inverse;
	}

	private LongElement subtractOneFrom(LongElement value) {
		Wire[] minusOneWires = generator.createProverWitnessWireArray(value.getSize());
		LongElement minusOne = new LongElement(minusOneWires, value.getCurrentBitwidth());

		generator.specifyProverWitnessComputation(new Instruction() {
			@Override
			public void evaluate(CircuitEvaluator evaluator) {
				BigInteger origValue = evaluator.getWireValue(value, LongElement.CHUNK_BITWIDTH);
				BigInteger minusOneValue = origValue.subtract(BigInteger.ONE);
				evaluator.setWireValue(minusOneWires, Util.split(minusOneValue, LongElement.CHUNK_BITWIDTH));
			}
		});

		minusOne.restrictBitwidth();
		minusOne.add(new LongElement(new BigInteger[] {BigInteger.ONE})).assertEquality(value);
		return minusOne;
	}

	public LongElement getPlaintext() {
		return plain;
	}

	@Override
	public Wire[] getOutputWires() {
		return plain.getArray();
	}
}
