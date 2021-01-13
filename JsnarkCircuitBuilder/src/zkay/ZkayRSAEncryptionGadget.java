/*******************************************************************************
 * RSA gadget wrapper, which reorders input bytes for zkay compatibility
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import circuit.auxiliary.LongElement;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.rsa.RSAEncryptionOAEPGadget;
import examples.gadgets.rsa.RSAEncryptionV1_5_Gadget;

import java.util.Objects;

import static zkay.ZkayUtil.*;
import static zkay.crypto.RSABackend.*;

public class ZkayRSAEncryptionGadget extends Gadget {

    public enum PaddingType {
        PKCS_1_5,
        OAEP
    }

    private final PaddingType paddingType;
    private final LongElement pk;
    private final Wire[] plain;
    private final Wire[] rnd;
    private final int keyBits;

    private Wire[] cipher = null;

    public ZkayRSAEncryptionGadget(Wire[] plain, LongElement pk, Wire[] rnd, int keyBits, PaddingType paddingType, String... desc) {
        super(desc);

        Objects.requireNonNull(plain, "plain");
        Objects.requireNonNull(pk, "pk");
        Objects.requireNonNull(rnd, "rnd");
        Objects.requireNonNull(paddingType, "paddingType");

        this.paddingType = paddingType;
        this.plain = plain;
        this.pk = pk;
        this.rnd = rnd;
        this.keyBits = keyBits;

        buildCircuit();
    }

    protected void buildCircuit() {
        Wire[] plainBytes = reverseBytes(new WireArray(plain).getBits(256), 8);

        Gadget enc;
        switch (paddingType) {
            case OAEP: {
                Wire[] rndBytes = reverseBytes(new WireArray(rnd).getBits(OAEP_RND_CHUNK_SIZE), 8);
                RSAEncryptionOAEPGadget e = new RSAEncryptionOAEPGadget(pk, plainBytes, rndBytes, keyBits, description);
                e.checkSeedCompliance();
                enc = e;
                break;
            }
            case PKCS_1_5: {
                int rndLen = keyBits / 8 - 3 - plainBytes.length;
                Wire[] rndBytes = reverseBytes(new WireArray(rnd).getBits(PKCS15_RND_CHUNK_SIZE).adjustLength(rndLen * 8), 8);
                enc = new RSAEncryptionV1_5_Gadget(pk, plainBytes, rndBytes, keyBits, description);
                break;
            }
            default:
                throw new IllegalStateException("Unexpected padding type: " + paddingType);
        }

        cipher = new WireArray(enc.getOutputWires()).packWordsIntoLargerWords(8, CIPHER_CHUNK_SIZE / 8);
    }

    @Override
    public Wire[] getOutputWires() {
        return cipher;
    }
}
