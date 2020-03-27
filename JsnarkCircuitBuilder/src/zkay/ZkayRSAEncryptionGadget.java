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

import static zkay.ZkayUtil.*;

public class ZkayRSAEncryptionGadget extends Gadget {
    private LongElement _pk;
    private Wire[] _plain;
    private Wire[] _rnd;
    private Wire[] _cipher;
    private int _key_bits;
    private boolean _use_oaep;

    public ZkayRSAEncryptionGadget(Wire[] plain, LongElement pk, Wire[] rnd, int key_bits, boolean use_oaep, String... desc) {
        super(desc);

        if (plain == null || pk == null || rnd == null) {
            throw new RuntimeException();
        }
        this._plain = plain;
        this._pk = pk;
        this._rnd = rnd;
        this._cipher = null;
        this._key_bits = key_bits;
        this._use_oaep = use_oaep;
        buildCircuit();
    }

    protected void buildCircuit() {
        Wire[] plain_bytes = reverseBytes(new WireArray(_plain).getBits(256), 8);

        Gadget enc;
        if (_use_oaep) {
            Wire[] rnd_bytes = reverseBytes(new WireArray(_rnd).getBits(ZKAY_RSA_OAEP_RND_CHUNK_SIZE), 8);
            RSAEncryptionOAEPGadget e = new RSAEncryptionOAEPGadget(_pk, plain_bytes, rnd_bytes, _key_bits, description);
            e.checkSeedCompliance();
            enc = e;
        } else {
            int rnd_len = _key_bits / 8 - 3 - plain_bytes.length;
            Wire[] rnd_bytes = reverseBytes(new WireArray(_rnd).getBits(ZKAY_RSA_PKCS15_RND_CHUNK_SIZE).adjustLength(rnd_len * 8), 8);
            enc = new RSAEncryptionV1_5_Gadget(_pk, plain_bytes, rnd_bytes, _key_bits, description);
        }

        _cipher = new WireArray(enc.getOutputWires()).packWordsIntoLargerWords(8, ZKAY_RSA_CHUNK_SIZE / 8);
    }

    @Override
    public Wire[] getOutputWires() {
        return _cipher;
    }
}
