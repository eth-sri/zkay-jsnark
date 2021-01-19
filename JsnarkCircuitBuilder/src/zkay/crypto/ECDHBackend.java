package zkay.crypto;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import zkay.TypedWire;
import zkay.ZkayCBCSymmetricEncGadget;
import zkay.ZkayCBCSymmetricEncGadget.CipherType;

public class ECDHBackend extends CryptoBackend.Symmetric {

	public static final int KEY_CHUNK_SIZE = 256;

	private final CipherType cipherType;

	public ECDHBackend(int keyBits, CipherType cipherType) {
		super(keyBits);
		this.cipherType = cipherType;
	}

	@Override
	public int getKeyChunkSize() {
		return KEY_CHUNK_SIZE;
	}

	@Override
	public Gadget createEncryptionGadget(TypedWire plain, String key, Wire[] ivArr, String... desc) {
		return new ZkayCBCSymmetricEncGadget(plain, getKey(key), extractIV(ivArr), cipherType, desc);
	}
}
