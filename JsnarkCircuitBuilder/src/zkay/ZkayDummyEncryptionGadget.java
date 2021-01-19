/*******************************************************************************
 * Dummy encryption gadget (simply add key to plaintext)
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import circuit.auxiliary.LongElement;
import circuit.operations.Gadget;
import circuit.structure.Wire;

import java.util.Arrays;

import static zkay.crypto.DummyBackend.CIPHER_CHUNK_SIZE;

public class ZkayDummyEncryptionGadget extends Gadget {

    private final Wire pk;
    private final Wire plain;
    private final Wire[] cipher;

    public ZkayDummyEncryptionGadget(TypedWire plain, LongElement pk, Wire[] rnd, int keyBits, String... desc) {
        super(desc);
        if (plain == null || pk == null || rnd == null) {
            throw new RuntimeException();
        }
        this.plain = plain.wire;
        Wire[] pkarr = pk.getBits().packBitsIntoWords(256);
        for (int i = 1; i < pkarr.length; ++i) {
            generator.addZeroAssertion(pkarr[i], "Dummy enc pk valid");
        }
        this.pk = pkarr[0];
        this.cipher = new Wire[(int)Math.ceil((1.0*keyBits) / CIPHER_CHUNK_SIZE)];
        buildCircuit();
    }

    protected void buildCircuit() {
        Wire res = plain.add(pk, "plain + pk");
        Arrays.fill(cipher, res);
    }

    @Override
    public Wire[] getOutputWires() {
        return cipher;
    }
}
