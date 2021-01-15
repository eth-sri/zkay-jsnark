package zkay;

import circuit.operations.Gadget;
import circuit.structure.Wire;

import java.util.Objects;

/**
 * Dummy encryption gadget whose ciphertext is additively homomorphic.
 * Key: Some prime number p smaller than the field prime.
 * Encryption: Enc(msg, p) = msg * p mod field_prime.
 * Decryption: Dec(cipher) = cipher * p^-1 mod field_prime.
 * Additive homomorphism: Enc(m1, p) + Enc(m2, p)     (all mod field_prime)
 *                        = (m1 * p) + (m2 * p)
 *                        = (m1 + m2) * p
 *                        = Enc(m1 + m2, p)
 */
public class ZkayDummyHomEncryptionGadget extends Gadget {

	private final Wire pk;
	private final Wire[] plain;
	private final Wire[] cipher;

	public ZkayDummyHomEncryptionGadget(Wire[] plain, Wire pk, Wire[] rnd, int keyBits, String... desc) {
		super(desc);

		Objects.requireNonNull(plain, "plain");
		Objects.requireNonNull(pk, "pk");
		Objects.requireNonNull(rnd, "rnd");
		if (plain.length > 1) throw new IllegalArgumentException("Plaintext wire array too long");
		if (rnd.length > 1) throw new IllegalArgumentException("Randomness wire array too long");

		this.plain = plain;
		this.pk = pk;
		this.cipher = new Wire[1];
		buildCircuit();
	}

	protected void buildCircuit() {
		cipher[0] = plain[0].mul(pk, "plain * pk");
	}

	@Override
	public Wire[] getOutputWires() {
		return cipher;
	}
}
