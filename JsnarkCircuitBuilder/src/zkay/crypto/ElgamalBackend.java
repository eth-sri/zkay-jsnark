package zkay.crypto;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import zkay.*;

public class ElgamalBackend extends CryptoBackend.Asymmetric implements HomomorphicBackend {

    public static final int EC_COORD_BITS = 253;    // number of bits to store a BabyJubJub affine coordinate

    public ElgamalBackend(int keyBits) {
        super(keyBits);

        // public key must be a BabyJubJub point (two coordinates)
        if (keyBits != 2*EC_COORD_BITS) {
            throw new IllegalArgumentException("public key size mismatch");
        }
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

        if (plain.type.bitwidth > 32) {
            throw new IllegalArgumentException("plaintext must be at most 32 keys for elgamal backend");
        }
        return new ZkayElgamalEncGadget(plain.wire.getBitWires(plain.type.bitwidth).asArray(), pk, random);
    }

    private TypedWire[] toTypedWireArray(Wire[] wires, String name) {
        TypedWire[] typedWires = new TypedWire[wires.length];
        ZkayType uint256 = ZkayType.ZkUint(256);
        for (int i = 0; i < wires.length; ++i) {
            typedWires[i] = new TypedWire(wires[i], uint256, name);
        }
        return typedWires;
    }

    private Wire[] fromTypedWireArray(TypedWire[] typedWires) {
        Wire[] wires = new Wire[typedWires.length];
        ZkayType uint256 = ZkayType.ZkUint(256);
        for (int i = 0; i < typedWires.length; i++) {
            ZkayType.checkType(uint256, typedWires[i].type);
            wires[i] = typedWires[i].wire;
        }
        return wires;
    }

    private ZkayBabyJubJubGadget.JubJubPoint parseJubJubPoint(Wire[] wire, int offset) {
        return new ZkayBabyJubJubGadget.JubJubPoint(wire[offset], wire[offset+1]);
    }

    public TypedWire[] doHomomorphicOp(HomomorphicInput lhs, char op, HomomorphicInput rhs, String keyName) {
        switch (op) {
            case '+': {
                // for (c1, c2) = Enc(m1, r1)
                //     (d1, d2) = Enc(m2, r2)
                //     e1 = c1 + d1
                //     e2 = c2 + d2
                // it is (e1, e2) = Enc(m1 + m2, r1 + r2)
                String outputName = "(" + lhs.getName() + ") + (" + rhs.getName() + ")";

                // TODO: use uninitZeroToOne to convert 0 ciphertext to Enc(0, ...)

                TypedWire[] lhs_twires = lhs.getCipher();
                TypedWire[] rhs_twires = rhs.getCipher();

                // sanity checks
                assert(lhs_twires.length == 4);  // 4 BabyJubJub coordinates
                assert(rhs_twires.length == 4);  // 4 BabyJubJub coordinates
                Wire[] lhs_wires = fromTypedWireArray(lhs_twires);
                Wire[] rhs_wires = fromTypedWireArray(rhs_twires);

                ZkayBabyJubJubGadget.JubJubPoint c1 = parseJubJubPoint(lhs_wires, 0);
                ZkayBabyJubJubGadget.JubJubPoint c2 = parseJubJubPoint(lhs_wires, 2);
                ZkayBabyJubJubGadget.JubJubPoint d1 = parseJubJubPoint(rhs_wires, 0);
                ZkayBabyJubJubGadget.JubJubPoint d2 = parseJubJubPoint(rhs_wires, 2);

                ZkayElgamalAddGadget gadget = new ZkayElgamalAddGadget(c1, c2, d1, d2);
                return toTypedWireArray(gadget.getOutputWires(), outputName);
            }
            default:
                throw new UnsupportedOperationException("Binary operation " + op + " not supported");
        }
    }
}
