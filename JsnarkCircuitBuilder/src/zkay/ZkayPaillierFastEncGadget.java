package zkay;

import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.eval.Instruction;
import circuit.operations.Gadget;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.math.LongIntegerModGadget;
import examples.gadgets.math.LongIntegerModPowGadget;

import java.math.BigInteger;

import static zkay.crypto.PaillierBackend.CHUNK_SIZE;

public class ZkayPaillierFastEncGadget extends Gadget {

	private final LongElement n;
	private final LongElement nSquare;
	private final int nBits;
	private final int nSquareMaxBits;
	private final LongElement plain;
	private final LongElement random;
	private LongElement cipher;

	public ZkayPaillierFastEncGadget(TypedWire plain, LongElement key, Wire[] random, int keyBits, String... desc) {
		this(key, keyBits,
				handleNegativePlaintexts(plain, key),
				new LongElement(new WireArray(random).getBits(CHUNK_SIZE)), desc);
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

	private static LongElement handleNegativePlaintexts(TypedWire input, LongElement key) {
		if (input.type.signed) {
			int bits = input.type.bitwidth;
			CircuitGenerator generator = CircuitGenerator.getActiveCircuitGenerator();
			WireArray inputBits = input.wire.getBitWires(bits);
			Wire signBit = inputBits.get(bits - 1);
			LongElement posValue = new LongElement(input.wire.getBitWires(bits));
			Wire[] negValueWires = generator.createProverWitnessWireArray(key.getSize());
			LongElement negValue = new LongElement(negValueWires, key.getCurrentBitwidth());

			BigInteger maxValue = BigInteger.ONE.shiftLeft(bits);
			generator.specifyProverWitnessComputation(new Instruction() {
				@Override
				public void evaluate(CircuitEvaluator evaluator) {
					BigInteger inputValue = evaluator.getWireValue(input.wire);
					BigInteger negInput = maxValue.subtract(inputValue);
					BigInteger keyValue = evaluator.getWireValue(key, CHUNK_SIZE);
					evaluator.setWireValue(negValue, keyValue.subtract(negInput), CHUNK_SIZE);
				}
			});
			negValue.restrictBitwidth();
			LongElement maxValueElement = new LongElement(generator.createConstantWire(maxValue).getBitWires(bits + 1));
			key.add(posValue).assertEquality(negValue.add(maxValueElement)); // Ensure witness correctness

			return posValue.muxBit(negValue, signBit);
		} else {
			return new LongElement(input.wire.getBitWires(input.type.bitwidth));
		}
	}
}
