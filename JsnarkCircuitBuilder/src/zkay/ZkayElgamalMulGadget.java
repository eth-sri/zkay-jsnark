package zkay;

import circuit.structure.Wire;

/**
 * Gadget for homomorphically multiplying an ElGamal ciphertext (c1, c2) by a plaintext scalar
 */
public class ZkayElgamalMulGadget extends ZkayBabyJubJubGadget {

    private final JubJubPoint c1;

    private final JubJubPoint c2;

    private Wire[] scalarBits;

    private JubJubPoint e1;

    private JubJubPoint e2;

    public ZkayElgamalMulGadget(JubJubPoint c1, JubJubPoint c2, Wire [] scalarBits) {
        this.c1 = c1;
        this.c2 = c2;
        this.scalarBits = scalarBits;
        buildCircuit();
    }

    protected void buildCircuit() {
        e1 = mulScalar(c1, scalarBits);
        e2 = mulScalar(c2, scalarBits);
    }

    @Override
    public Wire[] getOutputWires() {
        return new Wire[]{ e1.x, e1.y, e2.x, e2.y };
    }
}
