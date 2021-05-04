package zkay.tests.circuits;

import org.junit.Test;

import java.math.BigInteger;


public class SampleCircuitTest {

    @Test
    public void testSampleEncCircuitCompile() {
        SampleEncCircuit.main(new String[] {"compile"});
    }

    @Test
    public void testSampleEncCircuitProve() {
        /*
        zk__out0_cipher = Enc(3, glob_key_Elgamal__owner, zk__out0_cipher_R)
        zk__in0_cipher_val = <42>
        zk__out1_cipher = <42 + 3>

        'glob_key_Elgamal__owner' = in[0:2]
        '_zk__foo.0.zk__in0_cipher_val' = in[2:6]
        '_zk__foo.0.zk__out0_cipher' = out[6:10]
        '_zk__foo.0.zk__out1_cipher' = out[10:14]
        '_zk__foo.0.zk__out0_cipher_R' = priv[0:1]
         */
        String pkx = new BigInteger("10420944247972906704901930255398155539251465080449381763175509401634402210816").toString(16);
        String pky = new BigInteger("676510933272081718087751130659922602804650769442378705766141464386492472495").toString(16);
        String out0_r = new BigInteger("4992017890738015216991440853823451346783754228142718316135811893930821210517").toString(16);
        String out0_c1x = new BigInteger("19192972422083923186464070519964101192898498903392337276087603285275966620124").toString(16);
        String out0_c1y = new BigInteger("6618023754137786203285728996559262879033810391268429127227951976541677679344").toString(16);
        String out0_c2x = new BigInteger("4472608468007309838241775982736001235655709329211813602064761207259504870138").toString(16);
        String out0_c2y = new BigInteger("16187037195592962521053200369750182891030609545782283138466373705116689670351").toString(16);
        String in0_c1x = new BigInteger("17575516153666433400432924447702558477423409923683944849284918792391691139359").toString(16);
        String in0_c1y = new BigInteger("3840342880323340477739333761922907061104957014408322957888704118993497812304").toString(16);
        String in0_c2x = new BigInteger("17476721245305713505111140923926236875142199918756101244927570918300239530767").toString(16);
        String in0_c2y = new BigInteger("7497514342119387331747836801231289445898118249754502859440257057049863178551").toString(16);
        String out1_c1x = new BigInteger("17534253010269307836501878564719704187610598056087396257744800265778849825187").toString(16);
        String out1_c1y = new BigInteger("2765058800862949759217680263413270354463208858275617699935919022287339676211").toString(16);
        String out1_c2x = new BigInteger("13842326506306051973866579828919069925067783979521710428050428985124313955583").toString(16);
        String out1_c2y = new BigInteger("12662606513769434815553780190062001306770521279655614301944124389806792972691").toString(16);

        // argument order: in, out, priv
        String[] args = new String[]{"prove", pkx, pky, in0_c1x, in0_c1y, in0_c2x, in0_c2y,
                out0_c1x, out0_c1y, out0_c2x, out0_c2y, out1_c1x, out1_c1y, out1_c2x, out1_c2y, out0_r};
        SampleEncCircuit.main(args);
    }

    @Test
    public void testSampleDecCircuitCompile() {
        SampleDecCircuit.main(new String[] {"compile"});
    }

    @Test
    public void testSampleDecCircuitProve() {
        /*
        zk__in0_cipher_val = Enc(42, glob_key_Elgamal__me, ...)
        secret0_plain_val = 42
        zk__out0_plain_val = 42
        zk__in0_cipher_val_R = (secret key of me)

        'glob_key_Elgamal__me' = in[0:2]
        '_zk__bar.0.zk__in0_cipher_val' = in[2:6]
        '_zk__bar.0.zk__out0_plain_val' = out[6:7]
        '_zk__bar.0.secret0_plain_val' = priv[0:1]
        '_zk__bar.0.zk__in0_cipher_val_R' = priv[1:2]
         */

        String pkx = new BigInteger("10420944247972906704901930255398155539251465080449381763175509401634402210816").toString(16);
        String pky = new BigInteger("676510933272081718087751130659922602804650769442378705766141464386492472495").toString(16);
        String in0_c1x = new BigInteger("17575516153666433400432924447702558477423409923683944849284918792391691139359").toString(16);
        String in0_c1y = new BigInteger("3840342880323340477739333761922907061104957014408322957888704118993497812304").toString(16);
        String in0_c2x = new BigInteger("17476721245305713505111140923926236875142199918756101244927570918300239530767").toString(16);
        String in0_c2y = new BigInteger("7497514342119387331747836801231289445898118249754502859440257057049863178551").toString(16);
        String out0 = new BigInteger("42").toString(16);
        String secret0 = new BigInteger("42").toString(16);
        String skey = new BigInteger("448344687855328518203304384067387474955750326758815542295083498526674852893").toString(16);

        // argument order: in, out, priv
        String[] args = new String[]{"prove", pkx, pky, in0_c1x, in0_c1y, in0_c2x, in0_c2y, out0, secret0, skey};
        SampleDecCircuit.main(args);
    }
}
