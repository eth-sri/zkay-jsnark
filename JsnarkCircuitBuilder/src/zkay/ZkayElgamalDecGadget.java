package zkay;

import circuit.structure.Wire;

/**
 * Gadget for exponential ElGamal decryption.
 * The message is not de-embedded in this gadget.
 */
public class ZkayElgamalDecGadget extends ZkayBabyJubJubGadget {

    private final Wire[] skBits;    // little-endian randomness bits

    private final JubJubPoint c1;

    private final JubJubPoint c2;

    private JubJubPoint msgEmbedded;    // embedded message (generator*msg)

    public ZkayElgamalDecGadget(Wire[] skBits, JubJubPoint c1, JubJubPoint c2) {
        // TODO: Need to make sk a private input and check correspondence to a public key
        this.skBits = skBits;
        this.c1 = c1;
        this.c2 = c2;
        buildCircuit();
    }

    protected void buildCircuit() {
        JubJubPoint sharedSecret = mulScalar(c1, skBits);
        msgEmbedded = addPoints(c2, negatePoint(sharedSecret));
    }

    @Override
    public Wire[] getOutputWires() {
        return new Wire[]{ msgEmbedded.x, msgEmbedded.y };
    }
}
