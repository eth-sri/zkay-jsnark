/*******************************************************************************
 * CBC gadget with support for different ciphers, based on jsnark's CBC gadget
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.blockciphers.AES128CipherGadget;
import examples.gadgets.blockciphers.ChaskeyLTS128CipherGadget;
import examples.gadgets.blockciphers.Speck128CipherGadget;
import util.Util;
import zkay.crypto.CryptoBackend;

import java.util.Arrays;

/**
 * Performs symmetric encryption in the CBC mode.
 */
public class ZkayCBCSymmetricEncGadget extends Gadget {

	public enum CipherType {
		SPECK_128,
		AES_128,
		CHASKEY
	}

	private final CipherType cipherType;
	private final Wire[] keyBits;
	private final Wire[] plaintextBits;
	private final Wire[] ivBits;

	private Wire[] cipherBits = null;

	public static final int BLOCK_SIZE = 128;
	public static final int KEY_SIZE = 128;

	public ZkayCBCSymmetricEncGadget(Wire[] plaintext, Wire key, Wire iv, CipherType cipherType, String... desc) {
		super(desc);
		this.plaintextBits = Util.reverseBytes(new WireArray(plaintext).getBits(256).asArray());
		this.keyBits = Util.reverseBytes(key.getBitWires(KEY_SIZE).asArray());
		this.ivBits = Util.reverseBytes(iv.getBitWires(BLOCK_SIZE).asArray());
		this.cipherType = cipherType;

		System.out.println("Plain length [bits]: " + this.plaintextBits.length);
		buildCircuit();
	}

	protected void buildCircuit() {

		int numBlocks = (int) Math.ceil(plaintextBits.length * 1.0 / BLOCK_SIZE);
		Wire[] plaintextArray = new WireArray(plaintextBits).adjustLength(numBlocks * BLOCK_SIZE).asArray();

		Wire[] preparedKey = prepareKey();
		WireArray prevCipher = new WireArray(ivBits);

		cipherBits = new Wire[0];
		for (int i = 0; i < numBlocks; i++) {
			WireArray msgBlock = new WireArray(Arrays.copyOfRange(plaintextArray, i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE));
			Wire[] xored = msgBlock.xorWireArray(prevCipher).asArray();
			switch (cipherType) {
				case SPECK_128: {
					Wire[] tmp = new WireArray(xored).packBitsIntoWords(64);
					Gadget gadget = new Speck128CipherGadget(tmp, preparedKey, description);
					Wire[] outputs = gadget.getOutputWires();
					prevCipher = new WireArray(outputs).getBits(64);
					break;
				}
				case AES_128: {
					Wire[] tmp = new WireArray(xored).packBitsIntoWords(8);
					Gadget gadget = new AES128CipherGadget(tmp, preparedKey, "aes: " + description);
					Wire[] outputs = gadget.getOutputWires();
					prevCipher = new WireArray(outputs).getBits(8);
					break;
				}
				case CHASKEY: {
					Wire[] tmp = new WireArray(xored).packBitsIntoWords(32);
					Gadget gadget = new ChaskeyLTS128CipherGadget(tmp, preparedKey, "chaskey: " + description);
					Wire[] outputs = gadget.getOutputWires();
					prevCipher = new WireArray(outputs).getBits(32);
					break;
				}
				default:
					throw new IllegalStateException("Unknown cipher value: " + cipherType);
			}
			cipherBits = Util.concat(cipherBits, prevCipher.asArray());
		}
	}

	private Wire[] prepareKey() {
		Wire[] preparedKey;
		switch (cipherType) {
			case SPECK_128: {
				Wire[] packedKey = new WireArray(keyBits).packBitsIntoWords(64);
				preparedKey = Speck128CipherGadget.expandKey(packedKey);
				break;
			}
			case AES_128: {
				Wire[] packedKey = new WireArray(keyBits).packBitsIntoWords(8);
				preparedKey = AES128CipherGadget.expandKey(packedKey);
				break;
			}
			case CHASKEY: {
				preparedKey = new WireArray(keyBits).packBitsIntoWords(32);
				break;
			}
			default:
				throw new UnsupportedOperationException("Other Ciphers not supported in this version!");
		}
		return preparedKey;
	}

	@Override
	public Wire[] getOutputWires() {
		System.out.println("Cipher length [bits]: " + cipherBits.length);
		return new WireArray(Util.reverseBytes(Util.concat(ivBits, cipherBits)))
				.packBitsIntoWords(CryptoBackend.Symmetric.CIPHER_CHUNK_SIZE);
	}
}
