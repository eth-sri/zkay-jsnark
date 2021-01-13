package zkay.crypto;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import zkay.ZkayPaillierFastEncGadget;

public class PaillierBackend extends CryptoBackend.Asymmetric {

	public static final int KEY_CHUNK_SIZE = 120;
	public static final int RND_CHUNK_SIZE = 120;

	public PaillierBackend(int keyBits) {
		super(keyBits);
	}

	@Override
	public int getKeyChunkSize() {
		return KEY_CHUNK_SIZE;
	}

	@Override
	public Gadget createEncryptionGadget(Wire[] plain, String key, Wire[] random, String... desc) {
		return new ZkayPaillierFastEncGadget(plain, getKey(key), random, keyBits, desc);
	}
}
