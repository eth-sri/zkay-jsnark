package zkay;

import circuit.structure.Wire;

/**
 * Gadget for exponential ElGamal encryption, which is additively homomorphic.
 * Because the message is in the exponent it is simply a bit string and
 * does not have to be embedded into the curve.
 */
public class ZkayElgamalEncGadget extends ZkayBabyJubJubGadget {

    private final Wire[] randomnessBits;    // little-endian randomness bits

    private final Wire[] msgBits;   // little-endian message bits

    private final JubJubPoint pk;   // public key

    private JubJubPoint c1;

    private JubJubPoint c2;

    public ZkayElgamalEncGadget(Wire[] msgBits, JubJubPoint pk, Wire[] randomnessBits) {
        this.randomnessBits = randomnessBits;
        this.msgBits = msgBits;
        this.pk = pk;
        buildCircuit();
    }

    protected void buildCircuit() {
        JubJubPoint msgEmbedded = mulScalar(getGenerator(), msgBits);
        JubJubPoint sharedSecret = mulScalar(pk, randomnessBits);
        c1 = mulScalar(getGenerator(), randomnessBits);
        c2 = addPoints(msgEmbedded, sharedSecret);
    }

    @Override
    public Wire[] getOutputWires() {
        return new Wire[]{ c1.x, c1.y, c2.x, c2.y };
    }
}
