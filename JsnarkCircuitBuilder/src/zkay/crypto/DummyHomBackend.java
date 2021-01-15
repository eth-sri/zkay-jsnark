package zkay.crypto;

import circuit.auxiliary.LongElement;
import circuit.operations.Gadget;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import zkay.TypedWire;
import zkay.ZkayDummyHomEncryptionGadget;
import zkay.ZkayType;

public class DummyHomBackend extends CryptoBackend.Asymmetric implements HomomorphicBackend {

	public static final int KEY_CHUNK_SIZE = 256;

	protected DummyHomBackend(int keyBits) {
		super(keyBits);
	}

	@Override
	public int getKeyChunkSize() {
		return KEY_CHUNK_SIZE;
	}

	@Override
	public Gadget createEncryptionGadget(Wire[] plain, String key, Wire[] random, String... desc) {
		return new ZkayDummyHomEncryptionGadget(plain, getKeyWire(key), random, keyBits, desc);
	}

	@Override
	public TypedWire[] doHomomorphicOp(char op, TypedWire[] cipher, String keyName) {
		if (cipher == null || cipher.length != 1) throw new IllegalArgumentException("cipher");

		if (op == '-') {
			// -Enc(msg, p) = -(msg * p) = (-msg) * p = Enc(-msg, p)
			Wire minus = cipher[0].wire.negate();
			return typed(minus, "-(" + cipher[0].name + ")");
		} else {
			throw new UnsupportedOperationException("Unary operation " + op + " not supported");
		}
	}

	@Override
	public TypedWire[] doHomomorphicOp(TypedWire[] lhs, char op, TypedWire[] rhs, String keyName) {
		if (lhs == null || lhs.length != 1) throw new IllegalArgumentException("lhs");
		if (rhs == null || rhs.length != 1) throw new IllegalArgumentException("rhs");

		switch (op) {
			case '+':
				// Enc(m1, p) + Enc(m2, p) = (m1 * p) + (m2 * p) = (m1 + m2) * p = Enc(m1 + m2, p)
				Wire sum = lhs[0].wire.add(rhs[0].wire);
				return typed(sum, "(" + lhs[0].name + ") + (" + rhs[0].name + ")");
			case '-':
				// Enc(m1, p) - Enc(m2, p) = (m1 * p) - (m2 * p) = (m1 - m2) * p = Enc(m1 - m2, p)
				Wire diff = lhs[0].wire.sub(rhs[0].wire);
				return typed(diff, "(" + lhs[0].name + ") - (" + rhs[0].name + ")");
			case '*':
				// Enc(m1, p) * m2 = (m1 * p) * m2 = (m1 * m2) * p = Enc(m1 * m2, p)
				Wire prod = lhs[0].wire.mul(rhs[0].wire);
				return typed(prod, "(" + lhs[0].name + ") - (" + rhs[0].name + ")");
			default:
				throw new UnsupportedOperationException("Binary operation " + op + " not supported");
		}
	}

	private Wire getKeyWire(String keyName) {
		LongElement key = getKey(keyName);
		CircuitGenerator generator = CircuitGenerator.getActiveCircuitGenerator();

		Wire[] keyArr = key.getBits().packBitsIntoWords(256);
		for (int i = 1; i < keyArr.length; ++i) {
			generator.addZeroAssertion(keyArr[i], "Dummy-hom enc pk valid");
		}
		return keyArr[0];
	}

	private static TypedWire[] typed(Wire wire, String name) {
		// Always type cipher wires as ZkUint(256)
		return new TypedWire[] {new TypedWire(wire, ZkayType.ZkUint(256), name)};
	}
}
