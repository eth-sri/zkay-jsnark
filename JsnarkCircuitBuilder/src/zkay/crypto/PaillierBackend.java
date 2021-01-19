package zkay.crypto;

import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.eval.Instruction;
import circuit.operations.Gadget;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.math.LongIntegerModGadget;
import examples.gadgets.math.LongIntegerModInverseGadget;
import examples.gadgets.math.LongIntegerModPowGadget;
import zkay.HomomorphicInput;
import zkay.TypedWire;
import zkay.ZkayPaillierFastEncGadget;
import zkay.ZkayType;

import java.math.BigInteger;
import java.util.Arrays;

public class PaillierBackend extends CryptoBackend.Asymmetric implements HomomorphicBackend {

	// Same chunk size for key, randomness, and ciphertext
	public static final int CHUNK_SIZE = 120;

	static {
		if (CHUNK_SIZE != LongElement.CHUNK_BITWIDTH) {
			throw new IllegalStateException("Paillier chunk size must match LongElement.CHUNK_BITWIDTH.\n" +
					"If LongElement.CHUNK_BITWIDTH needs to be changed, change this _and_ meta.py in jsnark!");
		}
	}

	private final int minNumCipherChunks;
	private final int maxNumCipherChunks;

	public PaillierBackend(int keyBits) {
		super(keyBits); // keyBits = bits of n
		if (keyBits <= CHUNK_SIZE) {
			throw new IllegalArgumentException("Key size too small (" + keyBits + " < " + CHUNK_SIZE + " bits)");
		}

		// n^2 has either length (2 * keyBits - 1) or (2 * keyBits) bits
		// minNumCipherChunks = ceil((2 * keyBits - 1) / CHUNK_SIZE)
		// maxNumCipherChunks = ceil((2 * keyBits) / CHUNK_SIZE)
		int minNSquareBits = 2 * keyBits - 1;
		this.minNumCipherChunks = (minNSquareBits + CHUNK_SIZE - 1) / CHUNK_SIZE;
		this.maxNumCipherChunks = (minNSquareBits + CHUNK_SIZE) / CHUNK_SIZE;
	}

	@Override
	public int getKeyChunkSize() {
		return CHUNK_SIZE;
	}

	@Override
	public Gadget createEncryptionGadget(TypedWire plain, String keyName, Wire[] randomWires, String... desc) {
		LongElement key = getKey(keyName);
		LongElement encodedPlain = encodeSignedToModN(plain, key);
		LongElement random = new LongElement(new WireArray(randomWires).getBits(CHUNK_SIZE).adjustLength(keyBits));
		return new ZkayPaillierFastEncGadget(key, keyBits, encodedPlain, random, desc);
	}

	@Override
	public TypedWire[] doHomomorphicOp(char op, HomomorphicInput arg, String keyName) {
		if (arg == null || arg.isPlain()) throw new IllegalArgumentException("arg");

		LongElement nSquare = getNSquare(keyName);
		LongElement cipherVal = toLongElement(arg);

		if (op == '-') {
			// Enc(m, r)^(-1) = (g^m * r^n)^(-1) = (g^m)^(-1) * (r^n)^(-1) = g^(-m) * (r^(-1))^n = Enc(-m, r^(-1))
			LongElement result = invert(cipherVal, nSquare);
			return toWireArray(result, "-(" + arg.getName() + ")");
		} else {
			throw new UnsupportedOperationException("Unary operation " + op + " not supported");
		}
	}

	@Override
	public TypedWire[] doHomomorphicOp(HomomorphicInput lhs, char op, HomomorphicInput rhs, String keyName) {
		LongElement n = getKey(keyName);
		LongElement nSquare = getNSquare(keyName);

		switch (op) {
			case '+': {
				// Enc(m1, r1) * Enc(m2, r2) = (g^m1 * r1^n) * (g^m2 * r2^n) = g^(m1 + m2) * (r1 * r2)^n = Enc(m1 + m2, r1 * r2)
				String outputName = "(" + lhs.getName() + ") + (" + rhs.getName() + ")";
				LongElement lhsVal = toLongElement(lhs);
				LongElement rhsVal = toLongElement(rhs);
				LongElement result = mulMod(lhsVal, rhsVal, nSquare);
				return toWireArray(result, outputName);
			}
			case '-': {
				// Enc(m1, r1) * Enc(m2, r2)^(-1) = Enc(m1 + (-m2), r1 * r2^(-1)) = Enc(m1 - m2, r1 * r2^(-1))
				String outputName = "(" + lhs.getName() + ") - (" + rhs.getName() + ")";
				LongElement lhsVal = toLongElement(lhs);
				LongElement rhsVal = toLongElement(rhs);
				LongElement result = mulMod(lhsVal, invert(rhsVal, nSquare), nSquare);
				return toWireArray(result, outputName);
			}
			case '*': {
				// Multiplication on additively homomorphic ciphertexts requires 1 ciphertext and 1 plaintext argument
				LongElement cipherVal;
				TypedWire plainWire;

				if (lhs == null) throw new IllegalArgumentException("lhs is null");
				if (rhs == null) throw new IllegalArgumentException("rhs is null");
				if (lhs.isPlain() && rhs.isCipher()) {
					plainWire = lhs.getPlain();
					cipherVal = toLongElement(rhs);
				} else if (lhs.isCipher() && rhs.isPlain()) {
					cipherVal = toLongElement(lhs);
					plainWire = rhs.getPlain();
				} else {
					throw new IllegalArgumentException("Paillier multiplication requires exactly 1 plaintext argument");
				}

				int plainBits;
				LongElement plainVal;
				if (!plainWire.type.signed) {
					// Unsigned, easy case
					plainBits = plainWire.type.bitwidth;
					plainVal = new LongElement(plainWire.wire, plainBits);
				} else {
					// Signed. Enjoy doing this with a cryptographically secure key.
					plainBits = keyBits;
					plainVal = encodeSignedToModN(plainWire, n);
				}
				String outputName = "(" + lhs.getName() + ") * (" + rhs.getName() + ")";

				// Enc(m1, r1) ^ m2 = (g^m1 * r1^n) ^ m2 = (g^m1)^m2 * (r1^n)^m2 = g^(m1*m2) * (r1^m2)^n = Enc(m1 * m2, r1 ^ m2)
				LongElement result = modPow(cipherVal, plainVal, plainBits, nSquare);
				return toWireArray(result, outputName);
			}
			default:
				throw new UnsupportedOperationException("Binary operation " + op + " not supported");
		}
	}

	private LongElement getNSquare(String keyName) {
		LongElement n = getKey(keyName);
		int nSquareMaxBits = 2 * keyBits; // Maximum bit length of n^2
		int maxNumChunks = (nSquareMaxBits + (LongElement.CHUNK_BITWIDTH - 1)) / LongElement.CHUNK_BITWIDTH;
		return n.mul(n).align(maxNumChunks);
	}

	private LongElement invert(LongElement val, LongElement nSquare) {
		return new LongIntegerModInverseGadget(val, nSquare, true, "Paillier negation").getResult();
	}

	private LongElement mulMod(LongElement lhs, LongElement rhs, LongElement nSquare) {
		return new LongIntegerModGadget(lhs.mul(rhs), nSquare, 2 * keyBits, true, "Paillier addition").getRemainder();
	}

	private LongElement modPow(LongElement lhs, LongElement rhs, int rhsBits, LongElement nSquare) {
		return new LongIntegerModPowGadget(lhs, rhs, rhsBits, nSquare, 2 * keyBits, "Paillier multiplication").getResult();
	}

	private LongElement toLongElement(HomomorphicInput input) {
		if (input == null || input.isPlain()) {
			throw new IllegalArgumentException("Input null or not ciphertext");
		}
		TypedWire[] cipher = input.getCipher();
		if (cipher.length < minNumCipherChunks || cipher.length > maxNumCipherChunks) {
			throw new IllegalArgumentException("Ciphertext has invalid length " + cipher.length);
		}

		// Ciphertext inputs seem to be passed as ZkUint(256); sanity check to make sure we got that.
		ZkayType uint256 = ZkayType.ZkUint(256);
		for (TypedWire cipherWire : cipher) {
			ZkayType.checkType(uint256, cipherWire.type);
		}

		// Input is a Paillier ciphertext - front-end must already check that this is the case
		Wire[] wires = new Wire[cipher.length];
		for (int i = 0; i < cipher.length; ++i) {
			wires[i] = cipher[i].wire;
		}
		int[] bitWidths = new int[wires.length];
		Arrays.fill(bitWidths, CHUNK_SIZE);
		bitWidths[bitWidths.length - 1] = 2 * keyBits - (bitWidths.length - 1) * CHUNK_SIZE;

		// Cipher could still be uninitialized-zero, which we need to fix
		return uninitToZero(new LongElement(wires, bitWidths));
	}

	private TypedWire[] toWireArray(LongElement value, String name) {
		// First, sanity check that the result has at most maxNumCipherChunks wires of at most CHUNK_SIZE bits each
		if (value.getSize() > maxNumCipherChunks) {
			throw new IllegalStateException("Paillier output contains too many wires");
		}
		for (int bitWidth : value.getCurrentBitwidth()) {
			if (bitWidth > CHUNK_SIZE) throw new IllegalStateException("Paillier output cipher bit width too large");
		}

		// If ok, wrap the output wires in TypedWire. As with the input, treat ciphertexts as ZkUint(256).
		Wire[] wires = value.getArray();
		TypedWire[] typedWires = new TypedWire[wires.length];
		ZkayType uint256 = ZkayType.ZkUint(256);
		for (int i = 0; i < wires.length; ++i) {
			typedWires[i] = new TypedWire(wires[i], uint256, name);
		}
		return typedWires;
	}

	private static LongElement uninitToZero(LongElement val) {
		// Uninitialized values have a ciphertext of all zeros, which is not a valid Paillier cipher.
		// Instead, replace those values with 1 == g^0 * 0^n = Enc(0, 0)
		Wire[] valWires = val.getArray();
		Wire[] wireNonZero = new Wire[valWires.length];
		for (int i = 0; i < valWires.length; ++i) {
			wireNonZero[i] = valWires[i].checkNonZero();
		}
		Wire allWiresZero = new WireArray(wireNonZero).sumAllElements().checkNonZero().invAsBit();
		LongElement oneIfAllZero = new LongElement(allWiresZero, 1 /* bit */);
		return val.add(oneIfAllZero);
	}

	private static LongElement encodeSignedToModN(TypedWire input, LongElement key) {
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
			// Unsigned, encode as-is, just convert the input wire to a LongElement
			return new LongElement(input.wire.getBitWires(input.type.bitwidth));
		}
	}
}
