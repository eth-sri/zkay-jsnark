package zkay;

import circuit.auxiliary.LongElement;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import examples.gadgets.math.LongIntegerModGadget;
import examples.gadgets.math.LongIntegerModInverseGadget;
import examples.gadgets.math.LongIntegerModPowGadget;

public class ZkayPaillierEncGadget extends Gadget {

	private final LongElement n;
	private final LongElement nSquare;
	private final int nBits;
	private final int nSquareMaxBits;
	private final LongElement g;
	private final LongElement plain;
	private final LongElement random;
	private LongElement cipher;

	public ZkayPaillierEncGadget(LongElement n, int nBits, LongElement generator, LongElement plain, LongElement random,
	                             String... desc) {
		super(desc);
		this.n = n;
		this.nBits = nBits;
		this.nSquareMaxBits = 2 * nBits; // Maximum bit length of n^2
		int maxNumChunks = (nSquareMaxBits + (LongElement.CHUNK_BITWIDTH - 1)) / LongElement.CHUNK_BITWIDTH;
		this.nSquare = n.mul(n).align(maxNumChunks);
		this.g = generator;
		this.plain = plain;
		this.random = random;
		buildCircuit();
	}

	private void buildCircuit() {
		int nSquareMinBits = 2 * nBits - 1; // Minimum bit length of n^2
		// Prove that random is in Z_n* by checking that random has an inverse mod n
		LongElement randInv = new LongIntegerModInverseGadget(random, n, false).getResult();
		generator.addOneAssertion(randInv.checkNonZero());
		// Compute c = g^m * r^n mod n^2
		LongElement gPowPlain = new LongIntegerModPowGadget(g, plain, nBits, nSquare, nSquareMinBits, "g^m").getResult();
		LongElement randPowN = new LongIntegerModPowGadget(random, n, nBits, nSquare, nSquareMinBits, "r^n").getResult();
		LongElement product = gPowPlain.mul(randPowN);
		cipher = new LongIntegerModGadget(product, nSquare, nSquareMinBits, true, "g^m * r^n mod n^2").getRemainder();
	}

	public LongElement getCiphertext() {
		return cipher;
	}

	@Override
	public Wire[] getOutputWires() {
		return cipher.getArray();
	}
}
