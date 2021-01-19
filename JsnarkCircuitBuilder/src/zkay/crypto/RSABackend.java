package zkay.crypto;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import zkay.TypedWire;
import zkay.ZkayRSAEncryptionGadget;

public class RSABackend extends CryptoBackend.Asymmetric {

	public static final int CIPHER_CHUNK_SIZE = 232;
	public static final int KEY_CHUNK_SIZE = 232;
	public static final int PKCS15_RND_CHUNK_SIZE = 224;
	public static final int OAEP_RND_CHUNK_SIZE = 128;

	private final ZkayRSAEncryptionGadget.PaddingType paddingType;

	public RSABackend(int keyBits, ZkayRSAEncryptionGadget.PaddingType padding) {
		super(keyBits);
		this.paddingType = padding;
	}

	@Override
	public int getKeyChunkSize() {
		return KEY_CHUNK_SIZE;
	}

	@Override
	public Gadget createEncryptionGadget(TypedWire plain, String key, Wire[] random, String... desc) {
		return new ZkayRSAEncryptionGadget(plain, getKey(key), random, keyBits, paddingType, desc);
	}
}
