/*******************************************************************************
 * Dummy encryption gadget (simply add key to plaintext)
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import circuit.auxiliary.LongElement;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;

import java.util.Arrays;

public class ZkayDummyEncryptionGadget extends Gadget {
    private Wire _pk;
    private Wire[] _plain;
    private Wire[] _cipher;

    public ZkayDummyEncryptionGadget(Wire[] plain, LongElement pk, Wire[] rnd, int key_bits, String... desc) {
        super(desc);
        if (plain == null || pk == null || rnd == null) {
            throw new RuntimeException();
        }
        this._plain = plain;
        Wire[] pkarr = pk.getBits().packBitsIntoWords(256);
        if (pkarr.length != 1) {
            throw new IllegalArgumentException("Pk too large");
        }
        this._pk = pkarr[0];
        this._cipher = new Wire[(int)Math.ceil((1.0*key_bits)/ZkayUtil.ZKAY_DUMMY_CHUNK_SIZE)];
        buildCircuit();
    }

    protected void buildCircuit() {
        Wire res = _plain[0].add(_pk, "plain + pk");
        Arrays.fill(_cipher, res);
    }

    @Override
    public Wire[] getOutputWires() {
        return _cipher;
    }
}
