package zkay.crypto;

import circuit.auxiliary.LongElement;
import circuit.operations.Gadget;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import zkay.ZkayCBCSymmetricEncGadget;
import zkay.ZkayECDHGadget;
import zkay.ZkayEcPkDerivationGadget;
import zkay.ZkayRSAEncryptionGadget;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.IntFunction;

public abstract class CryptoBackend {

	private enum Backend {
		DUMMY("dummy", DummyBackend::new),
		DUMMY_HOM("dummy-hom", DummyHomBackend::new),
		ECDH_AES("ecdh-aes", keyBits -> new ECDHBackend(keyBits, ZkayCBCSymmetricEncGadget.CipherType.AES_128)),
		ECDH_CHASKEY("ecdh-chaskey", keyBits -> new ECDHBackend(keyBits, ZkayCBCSymmetricEncGadget.CipherType.CHASKEY)),
		PAILLIER("paillier", PaillierBackend::new),
		RSA_OAEP("rsa-oaep", keyBits -> new RSABackend(keyBits, ZkayRSAEncryptionGadget.PaddingType.OAEP)),
		RSA_PKCS15("rsa-pkcs1.5", keyBits -> new RSABackend(keyBits, ZkayRSAEncryptionGadget.PaddingType.PKCS_1_5));

		private final String cryptoName;
		private final IntFunction<CryptoBackend> backendConstructor;

		Backend(String name, IntFunction<CryptoBackend> constructor) {
			this.cryptoName = name;
			this.backendConstructor = constructor;
		}
	}

	public static CryptoBackend create(String name, int keyBits) {
		for (Backend backend : Backend.values()) {
			if (backend.cryptoName.equals(name)) {
				return backend.backendConstructor.apply(keyBits);
			}
		}
		throw new IllegalArgumentException("Invalid crypto backend: " + name);
	}

	protected final int keyBits;

	protected CryptoBackend(int keyBits) {
		this.keyBits = keyBits;
	}

	public abstract boolean isSymmetric();

	public abstract void addKey(String keyName, Wire[] keyWires);

	public abstract int getKeyChunkSize();

	public abstract Gadget createEncryptionGadget(Wire[] plain, String key, Wire[] random, String... desc);

	public abstract static class Symmetric extends CryptoBackend {

		// These chunk sizes assume a plaintext <= 256 (253) bit.
		// If this should change in the future, the optimal chunk size should be computed on demand based on the plaintext size
		// (optimal: pick such that data has 1. least amount of chunks, 2. for that chunk amount least possible bit amount)
		public static final int CIPHER_CHUNK_SIZE = 192;

		private final Map<String, Wire> publicKeys;
		protected final Map<String, Wire> sharedKeys;
		protected Wire myPk = null;
		protected Wire mySk = null;

		protected Symmetric(int keyBits) {
			super(keyBits);
			publicKeys = new HashMap<>();
			sharedKeys = new HashMap<>();
		}

		@Override
		public boolean isSymmetric() {
			return true;
		}

		@Override
		public void addKey(String keyName, Wire[] keyWires) {
			if (keyWires.length != 1) {
				throw new IllegalArgumentException("Expected key size 1uint for symmetric keys");
			}
			publicKeys.put(keyName, keyWires[0]);
		}

		protected Wire getKey(String keyName) {
			Wire key = sharedKeys.get(keyName);
			if (key == null) {
				key = computeKey(keyName);
				sharedKeys.put(keyName, key);
			}
			return key;
		}

		private Wire computeKey(String keyName) {
			if (myPk == null) {
				throw new IllegalStateException("setKeyPair not called on symmetric crypto backend");
			}

			// Get other public key
			// In the case of decryption with default-initialization, it is possible that the sender pk stored in the
			// cipher struct is 0. In that case -> replace with any valid pk (my_pk for simplicity), to prevent ecdh gadget
			// from crashing (wrong output is not a problem since decryption enforces (pk_zero || cipher_zero) => all_zero
			// and ignores the ecdh result in that case.
			Wire actualOtherPk = publicKeys.get(keyName);
			if (actualOtherPk == null) {
				throw new IllegalStateException("Key variable " + keyName + " is absent");
			}
			actualOtherPk = actualOtherPk.checkNonZero(keyName + " != 0").mux(actualOtherPk, myPk);

			// Compute shared key with me
			String desc = String.format("sha256(ecdh(%s, %s))", keyName, mySk);
			ZkayECDHGadget sharedKeyGadget = new ZkayECDHGadget(actualOtherPk, mySk, false, desc);
			sharedKeyGadget.validateInputs();
			return sharedKeyGadget.getOutputWires()[0];
		}

		public void setKeyPair(Wire myPk, Wire mySk) {
			Objects.requireNonNull(myPk);
			Objects.requireNonNull(mySk);
			if (this.myPk != null) {
				throw new IllegalStateException("Key pair already set");
			}

			// Ensure that provided sender keys form a key pair
			CircuitGenerator generator = CircuitGenerator.getActiveCircuitGenerator();
			ZkayEcPkDerivationGadget pkDerivationGadget = new ZkayEcPkDerivationGadget(mySk, true, "getPk(mySk)");
			generator.addEqualityAssertion(myPk, pkDerivationGadget.getOutputWires()[0]);

			this.myPk = myPk;
			this.mySk = mySk;
		}

		protected static Wire extractIV(Wire[] ivCipher) {
			if (ivCipher == null || ivCipher.length == 0) {
				throw new IllegalArgumentException("IV cipher must not be empty");
			}
			// This assumes as cipher length of 256 bits
			int lastBlockCipherLen = (256 - (((ivCipher.length - 1) * CIPHER_CHUNK_SIZE) % 256)) % 256;
			Wire iv = ivCipher[ivCipher.length - 1];
			if (lastBlockCipherLen > 0) {
				iv = iv.shiftRight(CIPHER_CHUNK_SIZE, lastBlockCipherLen);
			}
			return iv;
		}
	}

	public abstract static class Asymmetric extends CryptoBackend {

		protected final Map<String, LongElement> keys;

		protected Asymmetric(int keyBits) {
			super(keyBits);
			keys = new HashMap<>();
		}

		@Override
		public boolean isSymmetric() {
			return false;
		}

		@Override
		public void addKey(String keyName, Wire[] keyWires) {
			int chunkBits = getKeyChunkSize();
			WireArray keyArray = new WireArray(keyWires).getBits(chunkBits, keyName + "_bits").adjustLength(keyBits);
			keys.put(keyName, new LongElement(keyArray));
		}

		protected LongElement getKey(String keyName) {
			LongElement key = keys.get(keyName);
			if (key == null) {
				throw new IllegalStateException("Key variable " + keyName + " is not associated with a LongElement");
			}
			return key;
		}
	}
}
