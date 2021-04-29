package zkay.crypto;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import zkay.TypedWire;
import zkay.ZkayBabyJubJubGadget;
import zkay.ZkayElgamalEncGadget;

public class ElgamalBackend extends CryptoBackend.Asymmetric {

    public static final int EC_COORD_BITS = 256;    // number of bits to store a BabyJubJub affine coordinate

    public ElgamalBackend(int keyBits) {
        super(keyBits);

        // public key is a BabyJubJub point (two coordinates)
        assert(keyBits == 2*EC_COORD_BITS);
    }

    @Override
    public int getKeyChunkSize() {
        return 2*EC_COORD_BITS;
    }

    @Override
    public Gadget createEncryptionGadget(TypedWire plain, String keyName, Wire[] random, String... desc) {
        WireArray pkArray = getKeyArray(keyName);

        // parse as EC curve point
        Wire pkX = pkArray.packAsBits(0, EC_COORD_BITS);
        Wire pkY = pkArray.packAsBits(EC_COORD_BITS, 2*EC_COORD_BITS);
        ZkayBabyJubJubGadget.JubJubPoint pk = new ZkayBabyJubJubGadget.JubJubPoint(pkX, pkY);

        assert(plain.type.bitwidth == 32);  // only supporting 32 bit integers at the moment
        return new ZkayElgamalEncGadget(plain.wire.getBitWires(32).asArray(), pk, random);
    }
}
