package zkay;

/**
 * The input to a homomorphic operation which can either be a ciphertext wire array or a plaintext wire.
 *
 * This class exists because some homomorphic operations require plaintext operands, such as when performing
 * multiplication on additively homomorphic ciphertexts encrypted with Paillier or Dummy-Hom, and having
 * arguments of this type is preferable to having dozens of overloads with different combinations of TypedWire[]
 * and TypedWire or having to tell apart plaintext and ciphertext inputs from the length of the TypedWire[] input.
 */
public class HomomorphicInput {

	private final TypedWire[] array;
	private final boolean isCipher;

	private HomomorphicInput(TypedWire[] array, boolean isCipher) {
		this.array = array;
		this.isCipher = isCipher;
	}

	public static HomomorphicInput of(TypedWire[] cipher) {
		return new HomomorphicInput(cipher, true);
	}

	public static HomomorphicInput of(TypedWire plain) {
		return new HomomorphicInput(new TypedWire[] {plain}, false);
	}

	public boolean isCipher() {
		return isCipher;
	}

	public boolean isPlain() {
		return !isCipher;
	}

	public TypedWire[] getCipher() {
		if (!isCipher) throw new IllegalStateException("Homomorphic input was not a ciphertext");
		return array;
	}

	public TypedWire getPlain() {
		if (isCipher) throw new IllegalStateException("Homomorphic input was not a plaintext");
		return array[0];
	}

	public int getLength() {
		return array.length;
	}

	public String getName() {
		return array[0].name;
	}
}
