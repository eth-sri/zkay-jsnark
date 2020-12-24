package examples.gadgets.math;

import circuit.auxiliary.LongElement;
import circuit.operations.Gadget;
import circuit.structure.Wire;

import java.math.BigInteger;

/**
 * This gadget computes the result of the modular exponentiation c = b^e mod m,
 * where c, b, e, and m are LongElements.
 */
public class LongIntegerModPowGadget extends Gadget {

	private final LongElement b; // base
	private final LongElement e; // exponent
	private final LongElement m; // modulus
	private final int mMinBitLength; // Minimum number of bits that will ever fit the modulus

	private LongElement c; // c = m^e mod m

	public LongIntegerModPowGadget(LongElement b, LongElement e, LongElement m, int mMinBitLength, String... desc) {
		super(desc);
		this.b = b;
		this.e = e;
		this.m = m;
		this.mMinBitLength = mMinBitLength;
		buildCircuit();
	}

	private void buildCircuit() {
		final LongElement one = new LongElement(new BigInteger[] {BigInteger.ONE});
		Wire[] eBits = e.getBits(-1).asArray();

		// Start with product = 1
		LongElement product = one;
		// From the most significant to the least significant bit of the exponent, proceed as follow:
		// product = product^2 mod m
		// if (eBit == 1) product = (product * base) mod m
		for (int i = eBits.length - 1; i >= 0; --i) {
			LongElement square = product.mul(product);
			LongElement squareModM = new LongIntegerModGadget(square, m, mMinBitLength, false, "modPow: prod^2 mod m").getRemainder();
			LongElement squareTimesBase = squareModM.mul(one.muxBit(b, eBits[i]));
			product = new LongIntegerModGadget(squareTimesBase, m, mMinBitLength, false, "modPow: prod * base mod m").getRemainder();
		}

		c = new LongIntegerModGadget(product, m, true, "modPow: final prod mod m").getRemainder();
	}

	public LongElement getResult() {
		return c;
	}

	@Override
	public Wire[] getOutputWires() {
		return c.getArray();
	}
}
