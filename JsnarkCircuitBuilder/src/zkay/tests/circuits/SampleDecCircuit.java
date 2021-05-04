package zkay.tests.circuits;

import zkay.ZkayCircuitBase;
import static zkay.ZkayType.ZkUint;

public class SampleDecCircuit extends ZkayCircuitBase {
    public SampleDecCircuit() {
        super("zk__Verify_Test_bar", 6, 1, 2, true);
        addCryptoBackend("elgamal", "elgamal", 508);
    }

    private void __zk__bar() {
        stepIn("_zk__bar");
        addS("secret0_plain_val", 1, ZkUint(32));
        addS("zk__in0_cipher_val_R", 1, ZkUint(256));
        addIn("zk__in0_cipher_val", 4, ZkUint(256));
        addOut("zk__out0_plain_val", 1, ZkUint(32));

        //[ --- val ---
        // secret0_plain_val = dec(val) [zk__in0_cipher_val]
        checkDec("elgamal", "secret0_plain_val", "glob_key_Elgamal__me", "zk__in0_cipher_val_R", "zk__in0_cipher_val");
        decl("tmp0_plain", get("secret0_plain_val"));
        checkEq("tmp0_plain", "zk__out0_plain_val");
        //] --- val ---

        stepOut();
    }

    @Override
    protected void buildCircuit() {
        super.buildCircuit();
        addK("elgamal", "glob_key_Elgamal__me", 2);

        __zk__bar();
    }

    public static void main(String[] args) {
        SampleDecCircuit circuit = new SampleDecCircuit();
        circuit.run(args);
    }
}
