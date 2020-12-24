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

public class ZkayPaillierDecGadget extends Gadget {

	private final LongElement n;
	private final LongElement nSquare;
	private final int nBits;
	private final LongElement lambda;
	private final LongElement mu;
	private final LongElement cipher;
	private LongElement plain;

	public ZkayPaillierDecGadget(LongElement n, int nBits, LongElement lambda, LongElement mu, LongElement cipher) {
		this.n = n;
		this.nSquare = n.mul(n);
		this.nBits = nBits;
		this.lambda = lambda;
		this.mu = mu;
		this.cipher = cipher;
		buildCircuit();
	}

	private void buildCircuit() {
		int nSquareBits = 2 * nBits - 1; // Minimum bit length of n^2
		LongElement cPowLambda = new LongIntegerModPowGadget(cipher, lambda, nSquare, nSquareBits, "c^lambda").getResult();

		Wire[] minusOneWires = generator.createProverWitnessWireArray(cPowLambda.getSize());
		LongElement minusOne = new LongElement(minusOneWires, cPowLambda.getCurrentBitwidth());
		generator.specifyProverWitnessComputation(new Instruction() {
			@Override
			public void evaluate(CircuitEvaluator evaluator) {
				BigInteger origValue = evaluator.getWireValue(cPowLambda, LongElement.CHUNK_BITWIDTH);
				BigInteger minusOneValue = origValue.subtract(BigInteger.ONE);
				evaluator.setWireValue(minusOne.getArray(), Util.split(minusOneValue, LongElement.CHUNK_BITWIDTH));
			}
		});
		minusOne.add(new LongElement(new BigInteger[] {BigInteger.ONE})).assertEquality(cPowLambda);

		LongElement divByN = new LongIntegerFloorDivGadget(minusOne, n, "(c^lambda - 1) / n").getQuotient();
		LongElement timesMu = divByN.mul(mu);
		plain = new LongIntegerModGadget(timesMu, n, nBits, true).getRemainder();
	}

	public LongElement getPlaintext() {
		return plain;
	}

	@Override
	public Wire[] getOutputWires() {
		return plain.getArray();
	}
}
