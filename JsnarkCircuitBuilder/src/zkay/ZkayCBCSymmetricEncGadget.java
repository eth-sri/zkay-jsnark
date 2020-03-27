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

import java.util.Arrays;

import static zkay.ZkayUtil.ZKAY_SYMM_CIPHER_CHUNK_SIZE;

/**
 * Performs symmetric encryption in the CBC mode.
 */
public class ZkayCBCSymmetricEncGadget extends Gadget {

	private Wire[] cipherbits;
	private String cipherName;

	private Wire[] keyBits;
	private Wire[] plaintextBits;
	private Wire[] ivBits;

	public static final int BLOCKSIZE = 128;
	public static final int KEYSIZE = 128;

	public ZkayCBCSymmetricEncGadget(Wire[] plaintext, Wire key, Wire iv, String cipherName, String... desc) {
		super(desc);
		this.plaintextBits = Util.reverseBytes(new WireArray(plaintext).getBits(256).asArray());
		this.keyBits = Util.reverseBytes(key.getBitWires(KEYSIZE).asArray());
		this.ivBits = Util.reverseBytes(iv.getBitWires(BLOCKSIZE).asArray());
		this.cipherName = cipherName;

		System.out.println("Plain length [bits]: " + this.plaintextBits.length);
		buildCircuit();
	}

	protected void buildCircuit() {

		int numBlocks = (int) Math.ceil(plaintextBits.length * 1.0 / BLOCKSIZE);
		plaintextBits = new WireArray(plaintextBits).adjustLength(numBlocks * BLOCKSIZE).asArray();

		Wire[] preparedKey = prepareKey();
		WireArray prevCipher = new WireArray(ivBits);

		cipherbits = new Wire[0];
		for (int i = 0; i < numBlocks; i++) {
			WireArray msgBlock = new WireArray(Arrays.copyOfRange(plaintextBits, i * BLOCKSIZE, (i + 1) * BLOCKSIZE));
			Wire[] xored = msgBlock.xorWireArray(prevCipher).asArray();
			switch (cipherName) {
				case "speck128": {
					Wire[] tmp = new WireArray(xored).packBitsIntoWords(64);
					Gadget gadget = new Speck128CipherGadget(tmp, preparedKey, description);
					Wire[] outputs = gadget.getOutputWires();
					prevCipher = new WireArray(outputs).getBits(64);
					break;
				}
				case "aes128": {
					Wire[] tmp = new WireArray(xored).packBitsIntoWords(8);
					Gadget gadget = new AES128CipherGadget(tmp, preparedKey, "aes: " + description);
					Wire[] outputs = gadget.getOutputWires();
					prevCipher = new WireArray(outputs).getBits(8);
					break;
				}
				case "chaskey": {
                    Wire[] tmp = new WireArray(xored).packBitsIntoWords(32);
                    Gadget gadget = new ChaskeyLTS128CipherGadget(tmp, preparedKey, "chaskey: " + description);
                    Wire[] outputs = gadget.getOutputWires();
                    prevCipher = new WireArray(outputs).getBits(32);
				    break;
                }
                default:
					throw new UnsupportedOperationException("Other Ciphers not supported in this version!");
			}
			cipherbits = Util.concat(cipherbits, prevCipher.asArray());
		}
	}

	private Wire[] prepareKey() {
		Wire[] preparedKey;
		switch (cipherName) {
			case "speck128": {
				Wire[] packedKey = new WireArray(keyBits).packBitsIntoWords(64);
				preparedKey = Speck128CipherGadget.expandKey(packedKey);
				break;
			}
			case "aes128": {
				Wire[] packedKey = new WireArray(keyBits).packBitsIntoWords(8);
				preparedKey = AES128CipherGadget.expandKey(packedKey);
				break;
			}
            case "chaskey": {
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
		System.out.println("Cipher length [bits]: " + cipherbits.length);
	    return new WireArray(Util.reverseBytes(Util.concat(ivBits, cipherbits))).packBitsIntoWords(ZKAY_SYMM_CIPHER_CHUNK_SIZE);
	}
}
