package zkay;

import circuit.auxiliary.LongElement;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import examples.gadgets.math.LongIntegerFloorDivGadget;
import examples.gadgets.math.LongIntegerModGadget;
import examples.gadgets.math.LongIntegerModPowGadget;

public class ZkayPaillierDecGadget extends Gadget {

	private final LongElement n;
	private final LongElement nSquare;
	private final int nBits;
	private final LongElement lambda;
	private final LongElement mu;
	private final LongElement cipher;
	private LongElement plain;

	public ZkayPaillierDecGadget(LongElement n, int nBits, LongElement lambda, LongElement mu, LongElement cipher,
	                             String... desc) {
		super(desc);
		this.n = n;
		this.nBits = nBits;
		int nSquareMaxBits = 2 * nBits;
		int maxNumChunks = (nSquareMaxBits + (LongElement.CHUNK_BITWIDTH - 1)) / LongElement.CHUNK_BITWIDTH;
		this.nSquare = n.mul(n).align(maxNumChunks);
		this.lambda = lambda;
		this.mu = mu;
		this.cipher = cipher;
		buildCircuit();
	}

	private void buildCircuit() {
		int nSquareMinBits = 2 * nBits - 1; // Minimum bit length of n^2

		// plain = L(cipher^lambda mod n^2) * mu mod n
		LongElement cPowLambda = new LongIntegerModPowGadget(cipher, lambda, nSquare, nSquareMinBits, "c^lambda").getResult();
		LongElement lOutput = new LongIntegerFloorDivGadget(cPowLambda.subtract(1), n, "(c^lambda - 1) / n").getQuotient();
		LongElement timesMu = lOutput.mul(mu);
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
