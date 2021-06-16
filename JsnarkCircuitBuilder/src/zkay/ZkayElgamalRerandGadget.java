package zkay;

import circuit.structure.Wire;

/**
 * Gadget homomorphically re-randomizing an ElGamal encrypted ciphertext.
 */
public class ZkayElgamalRerandGadget extends ZkayBabyJubJubGadget {

    private final Wire[] randomnessBits;    // little-endian randomness bits

    private final JubJubPoint pk;   // public key

    private final JubJubPoint c1;   // input ciphertext first point

    private final JubJubPoint c2;   // input ciphertext second point

    private JubJubPoint o1;

    private JubJubPoint o2;

    public ZkayElgamalRerandGadget(JubJubPoint c1, JubJubPoint c2, JubJubPoint pk, Wire[] randomnessBits) {
        this.c1 = c1;
        this.c2 = c2;
        this.randomnessBits = randomnessBits;
        this.pk = pk;
        buildCircuit();
    }

    protected void buildCircuit() {
        // create encryption of zero (z1, z2)
        JubJubPoint sharedSecret = mulScalar(pk, randomnessBits);
        JubJubPoint z1 = mulScalar(getGenerator(), randomnessBits);
        JubJubPoint z2 = sharedSecret;

        // add encryption of zero to re-randomize
        o1 = addPoints(c1, z1);
        o2 = addPoints(c2, z2);
    }

    @Override
    public Wire[] getOutputWires() {
        return new Wire[]{ o1.x, o1.y, o2.x, o2.y };
    }
}
