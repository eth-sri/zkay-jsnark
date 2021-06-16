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
        String pkx = new BigInteger("2543111965495064707612623550577403881714453669184859408922451773306175031318").toString(16);
        String pky = new BigInteger("20927827475527585117296730644692999944545060105133073020125343132211068382185").toString(16);
        String out0_r = new BigInteger("4992017890738015216991440853823451346783754228142718316135811893930821210517").toString(16);
        String out0_c1x = new BigInteger("17990166387038654353532224054392704246273066434684370089496246721960255371329").toString(16);
        String out0_c1y = new BigInteger("15866190370882469414665095798958204707796441173247149326160843221134574846694").toString(16);
        String out0_c2x = new BigInteger("20611619168289996179170076826255394452844088446249762902489426332728314449540").toString(16);
        String out0_c2y = new BigInteger("15977019707513990678856869992098745075741339619245698210811867116749537641408").toString(16);
        String in0_c1x = new BigInteger("20000451794290380375914691798920385097103434955980148521154607378788339649411").toString(16);
        String in0_c1y = new BigInteger("3379688933589504078077257631396507733503572474143535438012650064116108361323").toString(16);
        String in0_c2x = new BigInteger("17692342451347357823507390319100928261770955547170665908868317402407559496644").toString(16);
        String in0_c2y = new BigInteger("10685998684618216791975894032544668032271032005273052481243516059128881465545").toString(16);
        String out1_c1x = new BigInteger("18885199402227818148211810144232318738102042906622969713112212912459159846007").toString(16);
        String out1_c1y = new BigInteger("11125071952177567933017599368067887482603292954302203070407920687516147981132").toString(16);
        String out1_c2x = new BigInteger("20036470080915178878390944667725801469044803295396841663384258912114611255016").toString(16);
        String out1_c2y = new BigInteger("18986185709423663075397883577572338596028661172318034324882291197251276265727").toString(16);

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

        String pkx = new BigInteger("2543111965495064707612623550577403881714453669184859408922451773306175031318").toString(16);
        String pky = new BigInteger("20927827475527585117296730644692999944545060105133073020125343132211068382185").toString(16);
        String in0_c1x = new BigInteger("17990166387038654353532224054392704246273066434684370089496246721960255371329").toString(16);
        String in0_c1y = new BigInteger("15866190370882469414665095798958204707796441173247149326160843221134574846694").toString(16);
        String in0_c2x = new BigInteger("13578016172019942326633412365679613147103709674318008979748420035774874659858").toString(16);
        String in0_c2y = new BigInteger("15995926508900361671313404296634773295236345482179714831868518062689263430374").toString(16);
        String out0 = new BigInteger("42").toString(16);
        String secret0 = new BigInteger("42").toString(16);
        String skey = new BigInteger("448344687855328518203304384067387474955750326758815542295083498526674852893").toString(16);

        // argument order: in, out, priv
        String[] args = new String[]{"prove", pkx, pky, in0_c1x, in0_c1y, in0_c2x, in0_c2y, out0, secret0, skey};
        SampleDecCircuit.main(args);
    }

    @Test
    public void testSampleDecCircuitProveUninitialized() {
        String pkx = new BigInteger("2543111965495064707612623550577403881714453669184859408922451773306175031318").toString(16);
        String pky = new BigInteger("20927827475527585117296730644692999944545060105133073020125343132211068382185").toString(16);
        // uninitialized ciphertext
        String in0_c1x = new BigInteger("0").toString(16);
        String in0_c1y = new BigInteger("0").toString(16);
        String in0_c2x = new BigInteger("0").toString(16);
        String in0_c2y = new BigInteger("0").toString(16);
        String out0 = new BigInteger("0").toString(16);
        String secret0 = new BigInteger("0").toString(16);
        String skey = new BigInteger("0").toString(16);

        // argument order: in, out, priv
        String[] args = new String[]{"prove", pkx, pky, in0_c1x, in0_c1y, in0_c2x, in0_c2y, out0, secret0, skey};
        SampleDecCircuit.main(args);
    }

    @Test
    public void testSampleMulCircuitCompile() {
        SampleMulCircuit.main(new String[] {"compile"});
    }

    @Test
    public void testSampleMulCircuitProve() {
        String pkx = new BigInteger("2543111965495064707612623550577403881714453669184859408922451773306175031318").toString(16);
        String pky = new BigInteger("20927827475527585117296730644692999944545060105133073020125343132211068382185").toString(16);
        String in0_c1x = new BigInteger("1345914801503869804221332717328097414792076925078931355300970385489312303055").toString(16);
        String in0_c1y = new BigInteger("3221919363851679888621419552929429977187872757564157365903242129276143826679").toString(16);
        String in0_c2x = new BigInteger("17378197425436069497126136266495011617394395570683447945973025044739809585373").toString(16);
        String in0_c2y = new BigInteger("15789009976977544046062803747743295235439704864191175329350822002296637150904").toString(16);
        String out0_c1x = new BigInteger("1580977511543777394910122699548784426094904736600505129541556064495159060532").toString(16);
        String out0_c1y = new BigInteger("16190941039609473953318528369093289558337201974880158341123285226900681258492").toString(16);
        String out0_c2x = new BigInteger("18928854895111284332170004407067674892341217562252934285209587817233013254394").toString(16);
        String out0_c2y = new BigInteger("8499515539957690392433056598772536511996242730894002020454275332668597388028").toString(16);

        // argument order: in, out, priv
        String[] args = new String[]{"prove", pkx, pky, in0_c1x, in0_c1y, in0_c2x, in0_c2y, out0_c1x, out0_c1y, out0_c2x, out0_c2y};
        SampleMulCircuit.main(args);
    }

    @Test
    public void testSampleRehomCircuitCompile() {
        SampleRehomCircuit.main(new String[] {"compile"});
    }

    @Test
    public void testSampleRehomCircuitProve() {
        // TODO test with actual proof arguments
    }
}
