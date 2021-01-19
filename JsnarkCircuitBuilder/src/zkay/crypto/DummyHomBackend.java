package zkay.crypto;

import circuit.auxiliary.LongElement;
import circuit.operations.Gadget;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import zkay.HomomorphicInput;
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
	public Gadget createEncryptionGadget(TypedWire plain, String key, Wire[] random, String... desc) {
		return new ZkayDummyHomEncryptionGadget(plain, getKeyWire(key), random, keyBits, desc);
	}

	@Override
	public TypedWire[] doHomomorphicOp(char op, HomomorphicInput arg, String keyName) {
		Wire cipher = getCipherWire(arg, "arg");

		if (op == '-') {
			// -Enc(msg, p) = -(msg * p) = (-msg) * p = Enc(-msg, p)
			Wire minus = cipher.negate();
			return typed(minus, "-(" + arg.getName() + ")");
		} else {
			throw new UnsupportedOperationException("Unary operation " + op + " not supported");
		}
	}

	@Override
	public TypedWire[] doHomomorphicOp(HomomorphicInput lhs, char op, HomomorphicInput rhs, String keyName) {
		switch (op) {
			case '+': {
				// Enc(m1, p) + Enc(m2, p) = (m1 * p) + (m2 * p) = (m1 + m2) * p = Enc(m1 + m2, p)
				Wire l = getCipherWire(lhs, "lhs");
				Wire r = getCipherWire(rhs, "rhs");
				Wire sum = l.add(r);
				return typed(sum, "(" + lhs.getName() + ") + (" + rhs.getName() + ")");
			}
			case '-': {
				// Enc(m1, p) - Enc(m2, p) = (m1 * p) - (m2 * p) = (m1 - m2) * p = Enc(m1 - m2, p)
				Wire l = getCipherWire(lhs, "lhs");
				Wire r = getCipherWire(rhs, "rhs");
				Wire diff = l.sub(r);
				return typed(diff, "(" + lhs.getName() + ") - (" + rhs.getName() + ")");
			}
			case '*': {
				Wire plain;
				Wire cipher;
				if (lhs == null) throw new IllegalArgumentException("lhs is null");
				if (rhs == null) throw new IllegalArgumentException("rhs is null");
				if (lhs.isPlain() && rhs.isCipher()) {
					plain = lhs.getPlain().wire;
					cipher = getCipherWire(rhs, "rhs");
				} else if (lhs.isCipher() && rhs.isPlain()) {
					cipher = getCipherWire(lhs, "lhs");
					plain = rhs.getPlain().wire;
				} else {
					throw new IllegalArgumentException("DummyHom multiplication requires exactly 1 plaintext argument");
				}

				// Enc(m1, p) * m2 = (m1 * p) * m2 = (m1 * m2) * p = Enc(m1 * m2, p)
				Wire prod = cipher.mul(plain);
				return typed(prod, "(" + lhs.getName() + ") - (" + rhs.getName() + ")");
			}
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

	private static Wire getCipherWire(HomomorphicInput input, String name) {
		if (input == null) throw new IllegalArgumentException(name + " is null");
		if (input.isPlain()) throw new IllegalArgumentException(name + " is not a ciphertext");
		if (input.getLength() != 1) throw new IllegalArgumentException(name + " has invalid length");

		// Transform input 0 to ciphertext 0 (= encryption of 0); serialized inputs x+1 to ciphertext x
		Wire cipherWire = input.getCipher()[0].wire;
		Wire isNonZero = cipherWire.checkNonZero();
		return cipherWire.sub(isNonZero);
	}

	private static TypedWire[] typed(Wire wire, String name) {
		// Always type cipher wires as ZkUint(256)
		return new TypedWire[] {new TypedWire(wire.add(1), ZkayType.ZkUint(256), name)};
	}
}
