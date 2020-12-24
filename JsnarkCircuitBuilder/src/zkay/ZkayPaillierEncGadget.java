package zkay;

import circuit.auxiliary.LongElement;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import examples.gadgets.math.LongIntegerModGadget;
import examples.gadgets.math.LongIntegerModPowGadget;

public class ZkayPaillierEncGadget extends Gadget {

	private final LongElement n;
	private final LongElement nSquare;
	private final int nBits;
	private final LongElement generator;
	private final LongElement plain;
	private final LongElement random;
	private LongElement cipher;

	public ZkayPaillierEncGadget(LongElement n, int nBits, LongElement generator, LongElement plain, LongElement random) {
		this.n = n;
		this.nSquare = n.mul(n);
		this.nBits = nBits;
		this.generator = generator;
		this.plain = plain;
		this.random = random;
		buildCircuit();
	}

	private void buildCircuit() {
		int nSquareBits = 2 * nBits - 1; // Minimum bit length of n^2
		LongElement gPowPlain = new LongIntegerModPowGadget(generator, plain, nSquare, nSquareBits, "g^m").getResult();
		LongElement randPowN = new LongIntegerModPowGadget(random, n, nSquare, nSquareBits, "r^n").getResult();
		LongElement product = gPowPlain.mul(randPowN);
		cipher = new LongIntegerModGadget(product, nSquare, nSquareBits, true, "g^m * r^n mod n^2").getRemainder();
	}

	public LongElement getCiphertext() {
		return cipher;
	}

	@Override
	public Wire[] getOutputWires() {
		return cipher.getArray();
	}
}
