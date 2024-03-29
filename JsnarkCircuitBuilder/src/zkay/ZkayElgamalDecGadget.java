package zkay;

import circuit.structure.Wire;

/**
 * Gadget for checking correct exponential ElGamal decryption.
 * The expected message is provided as an input.
 */
public class ZkayElgamalDecGadget extends ZkayBabyJubJubGadget {

    private final Wire[] skBits;    // little-endian randomness bits

    private final JubJubPoint pk;

    private final JubJubPoint c1;

    private final JubJubPoint c2;

    private final Wire expectedMsg;

    private Wire msgOk;

    public ZkayElgamalDecGadget(JubJubPoint pk, Wire[] skBits, JubJubPoint c1, JubJubPoint c2, Wire expectedMsg) {
        this.pk = pk;
        this.skBits = skBits;
        this.c1 = c1;
        this.c2 = c2;
        this.expectedMsg = expectedMsg;
        buildCircuit();
    }

    protected void buildCircuit() {
        // ensure pk and skBits form a key pair
        JubJubPoint pkExpected = mulScalar(getGenerator(), skBits);
        Wire keyOk = pkExpected.x.isEqualTo(pk.x).and(pkExpected.y.isEqualTo(pk.y));

        // decrypt ciphertext (without de-embedding)
        JubJubPoint sharedSecret = mulScalar(c1, skBits);
        JubJubPoint msgEmbedded = addPoints(c2, negatePoint(sharedSecret));

        // embed expected message and assert equality
        Wire[] expectedMsgBits = expectedMsg.getBitWires(32).asArray();
        JubJubPoint expectedMsgEmbedded = mulScalar(getGenerator(), expectedMsgBits);
        this.msgOk = expectedMsgEmbedded.x.isEqualTo(msgEmbedded.x)
                .and(expectedMsgEmbedded.y.isEqualTo(msgEmbedded.y))
                .and(keyOk);
    }

    @Override
    public Wire[] getOutputWires() {
        return new Wire[] { this.msgOk };
    }
}
