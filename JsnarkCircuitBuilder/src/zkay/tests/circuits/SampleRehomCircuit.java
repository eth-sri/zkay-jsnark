package zkay.tests.circuits;

import zkay.ZkayCircuitBase;
import zkay.HomomorphicInput;
import static zkay.ZkayType.ZkUint;

public class SampleRehomCircuit extends ZkayCircuitBase {
    public SampleRehomCircuit() {
        super("zk__Verify_Test_foo", 16, 4, 5, true);
        addCryptoBackend("elgamal", "elgamal", 508);
    }

    private void __zk__foo() {
        stepIn("_zk__foo");
        addS("secret0_rnd", 1, ZkUint(256));
        addS("secret1_plain_x1", 1, ZkUint(32));
        addS("zk__in1_cipher_x1_R", 1, ZkUint(256));
        addIn("zk__in0_cipher_b1", 4, ZkUint(256));
        addIn("zk__in1_cipher_x1", 4, ZkUint(256));
        addOut("zk__out0_cipher", 4, ZkUint(256));

        //[ --- b1 * reveal(x1, receiver) ---
        // zk__in0_cipher_b1 = b1
        // secret1_plain_x1 = dec(x1) [zk__in1_cipher_x1]
        checkDec("elgamal", "secret1_plain_x1", "glob_key_Elgamal__me", "zk__in1_cipher_x1_R", "zk__in1_cipher_x1");
        decl("tmp0_cipher", o_rerand(o_hom("elgamal", "glob_key_Elgamal__receiver", HomomorphicInput.of(getCipher("zk__in0_cipher_b1")), '*', HomomorphicInput.of(get("secret1_plain_x1"))), "elgamal", "glob_key_Elgamal__receiver", get("secret0_rnd")));
        checkEq("tmp0_cipher", "zk__out0_cipher");
        //] --- b1 * reveal(x1, receiver) ---

        stepOut();
    }

    @Override
    protected void buildCircuit() {
        super.buildCircuit();
        addS("x1", 1, ZkUint(32));
        addS("x1_R", 1, ZkUint(256));
        addK("elgamal", "glob_key_Elgamal__receiver", 2);
        addK("elgamal", "glob_key_Elgamal__me", 2);
        addIn("zk__in2_cipher_x1", 4, ZkUint(256));

        // zk__in2_cipher_x1 = enc(x1, glob_key_Elgamal__me)
        checkEnc("elgamal", "x1", "glob_key_Elgamal__me", "x1_R", "zk__in2_cipher_x1");
        __zk__foo();
    }

    public static void main(String[] args) {
        SampleRehomCircuit circuit = new SampleRehomCircuit();
        circuit.run(args);
    }
}