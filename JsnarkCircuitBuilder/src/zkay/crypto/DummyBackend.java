package zkay.crypto;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import zkay.ZkayDummyEncryptionGadget;

public class DummyBackend extends CryptoBackend.Asymmetric {

	public static final int CIPHER_CHUNK_SIZE = 256;
	public static final int KEY_CHUNK_SIZE = 256;

	public DummyBackend(int keyBits) {
		super(keyBits);
	}

	@Override
	public int getKeyChunkSize() {
		return KEY_CHUNK_SIZE;
	}

	@Override
	public Gadget createEncryptionGadget(Wire[] plain, String key, Wire[] random, String... desc) {
		return new ZkayDummyEncryptionGadget(plain, getKey(key), random, keyBits, desc);
	}
}
