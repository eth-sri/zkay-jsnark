package zkay;

import circuit.auxiliary.LongElement;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.math.LongIntegerModGadget;
import examples.gadgets.math.LongIntegerModPowGadget;

import java.math.BigInteger;

import static zkay.crypto.PaillierBackend.*;

public class ZkayPaillierFastEncGadget extends Gadget {

	private final LongElement n;
	private final LongElement nSquare;
	private final int nBits;
	private final int nSquareMaxBits;
	private final LongElement plain;
	private final LongElement random;
	private LongElement cipher;

	public ZkayPaillierFastEncGadget(Wire[] plain, LongElement key, Wire[] random, int keyBits, String... desc) {
		this(key, keyBits,
				new LongElement(new WireArray(plain).getBits(256)),
				new LongElement(new WireArray(random).getBits(RND_CHUNK_SIZE)), desc);
	}

	public ZkayPaillierFastEncGadget(LongElement n, int nBits, LongElement plain, LongElement random, String... desc) {
		super(desc);
		this.n = n;
		this.nBits = nBits;
		this.nSquareMaxBits = 2 * nBits; // Maximum bit length of n^2
		int maxNumChunks = (nSquareMaxBits + (LongElement.CHUNK_BITWIDTH - 1)) / LongElement.CHUNK_BITWIDTH;
		this.nSquare = n.mul(n).align(maxNumChunks);
		this.plain = plain;
		this.random = random;
		buildCircuit();
	}

	private void buildCircuit() {
		int nSquareMinBits = 2 * nBits - 1; // Minimum bit length of n^2
		LongElement gPowPlain = n.mul(plain).add(new LongElement(new BigInteger[] {BigInteger.ONE})).align(nSquare.getSize());
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
