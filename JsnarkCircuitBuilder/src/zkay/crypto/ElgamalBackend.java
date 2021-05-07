package zkay.crypto;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import zkay.*;

public class ElgamalBackend extends CryptoBackend.Asymmetric implements HomomorphicBackend {

    public static final int EC_COORD_BITS = 254;    // a BabyJubJub affine coordinate fits into 254 bits

    public static final int KEY_CHUNK_SIZE = 256;   // needs to be a multiple of 8

    public static final int RND_CHUNK_SIZE = 256;

    public ElgamalBackend(int keyBits) {
        super(keyBits);

        // public key must be a BabyJubJub point (two coordinates)
        if (keyBits != 2*EC_COORD_BITS) {
            throw new IllegalArgumentException("public key size mismatch");
        }
    }

    @Override
    public int getKeyChunkSize() {
        return KEY_CHUNK_SIZE;
    }

    @Override
    public boolean usesDecryptionGadget() {
        // randomness is not extractable from an ElGamal ciphertext, so need a separate
        // gadget for decryption
        return true;
    }

    @Override
    public void addKey(String keyName, Wire[] keyWires) {
        // elgamal does not require a bit-representation of the public key, so store it directly
        keys.put(keyName, new WireArray(keyWires));
    }

    @Override
    public Gadget createEncryptionGadget(TypedWire plain, String keyName, Wire[] random, String... desc) {
        WireArray pkArray = getKeyArray(keyName);
        ZkayBabyJubJubGadget.JubJubPoint pk = new ZkayBabyJubJubGadget.JubJubPoint(pkArray.get(0), pkArray.get(1));
        Wire[] randomArray = new WireArray(random).getBits(RND_CHUNK_SIZE).asArray();
        if (plain.type.bitwidth > 32) {
            throw new IllegalArgumentException("plaintext must be at most 32 bits for elgamal backend");
        }
        return new ZkayElgamalEncGadget(plain.wire.getBitWires(plain.type.bitwidth).asArray(), pk, randomArray);
    }

    @Override
    public Gadget createDecryptionGadget(TypedWire plain, Wire[] cipher, String pkName, Wire[] sk, String... desc) {
        WireArray pkArray = getKeyArray(pkName);
        ZkayBabyJubJubGadget.JubJubPoint pk = new ZkayBabyJubJubGadget.JubJubPoint(pkArray.get(0), pkArray.get(1));
        ZkayBabyJubJubGadget.JubJubPoint c1 = new ZkayBabyJubJubGadget.JubJubPoint(cipher[0], cipher[1]);
        ZkayBabyJubJubGadget.JubJubPoint c2 = new ZkayBabyJubJubGadget.JubJubPoint(cipher[2], cipher[3]);
        Wire[] skBits = new WireArray(sk).getBits(RND_CHUNK_SIZE).asArray();
        return new ZkayElgamalDecGadget(pk, skBits, c1, c2, plain.wire);
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

    private static ZkayBabyJubJubGadget.JubJubPoint uninitZeroToIdentity(ZkayBabyJubJubGadget.JubJubPoint p) {
        // Uninitialized values have a ciphertext of all zeroes, which is not a valid ElGamal cipher.
        // Instead, replace those values with the point at infinity (0, 1).
        Wire oneIfBothZero = p.x.checkNonZero().or(p.y.checkNonZero()).invAsBit();
        return new ZkayBabyJubJubGadget.JubJubPoint(p.x, p.y.add(oneIfBothZero));
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

                c1 = uninitZeroToIdentity(c1);
                c2 = uninitZeroToIdentity(c2);
                d1 = uninitZeroToIdentity(d1);
                d2 = uninitZeroToIdentity(d2);

                ZkayElgamalAddGadget gadget = new ZkayElgamalAddGadget(c1, c2, d1, d2);
                return toTypedWireArray(gadget.getOutputWires(), outputName);
            }
            default:
                throw new UnsupportedOperationException("Binary operation " + op + " not supported");
        }
    }
}
