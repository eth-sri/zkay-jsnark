package zkay.tests;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import org.junit.Assert;
import org.junit.Test;
import zkay.ZkayBabyJubJubGadget;
import zkay.ZkayElgamalDecGadget;
import zkay.ZkayElgamalEncGadget;

import java.math.BigInteger;

public class ElgamalTest {
    protected static class AffinePoint {
        public BigInteger x;
        public BigInteger y;

        public AffinePoint(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        public ZkayBabyJubJubGadget.JubJubPoint asConstJubJub(CircuitGenerator gen) {
            Wire wx = gen.createConstantWire(x);
            Wire wy = gen.createConstantWire(y);
            return new ZkayBabyJubJubGadget.JubJubPoint(wx, wy);
        }
    }

    private static class ElgamalEncCircuitGenerator extends CircuitGenerator {
        private final BigInteger plain;
        private final BigInteger random;
        private final AffinePoint pk;

        private ElgamalEncCircuitGenerator(String name, BigInteger plain, BigInteger random, AffinePoint pk) {
            super(name);
            this.plain = plain;
            this.random = random;
            this.pk = pk;
        }

        @Override
        protected void buildCircuit() {
            Wire randomness = createConstantWire(random);
            WireArray randomnessBits = randomness.getBitWires(random.bitLength());
            Wire message = createConstantWire(plain);
            WireArray messageBits = message.getBitWires(32);

            ZkayElgamalEncGadget gadget = new ZkayElgamalEncGadget(messageBits.asArray(),
                    pk.asConstJubJub(this), randomnessBits.asArray());
            makeOutputArray(gadget.getOutputWires(), "cipher");
        }

        @Override
        public void generateSampleInput(CircuitEvaluator evaluator) { }
    }

    private static class ElgamalDecCircuitGenerator extends CircuitGenerator {
        private final BigInteger sk;
        private final AffinePoint c1;
        private final AffinePoint c2;

        private ElgamalDecCircuitGenerator(String name, BigInteger sk, AffinePoint c1, AffinePoint c2) {
            super(name);
            this.sk = sk;
            this.c1 = c1;
            this.c2 = c2;
        }

        @Override
        protected void buildCircuit() {
            Wire secretKey = createConstantWire(sk);
            WireArray skBits = secretKey.getBitWires(sk.bitLength());

            ZkayElgamalDecGadget gadget = new ZkayElgamalDecGadget(skBits.asArray(), c1.asConstJubJub(this), c2.asConstJubJub(this));
            makeOutputArray(gadget.getOutputWires(), "embedded msg");
        }

        @Override
        public void generateSampleInput(CircuitEvaluator evaluator) { }
    }

    private void oneInputTest(BigInteger plain,
                              AffinePoint plainEmbedded,
                              BigInteger random,
                              BigInteger sk,
                              AffinePoint pk,
                              AffinePoint c1Expected,
                              AffinePoint c2Expected) {
        CircuitGenerator cgen = new ElgamalEncCircuitGenerator("test_enc", plain, random, pk);
        cgen.generateCircuit();
        CircuitEvaluator evaluator = new CircuitEvaluator(cgen);
        evaluator.evaluate();
        BigInteger c1x = evaluator.getWireValue(cgen.getOutWires().get(0));
        BigInteger c1y = evaluator.getWireValue(cgen.getOutWires().get(1));
        BigInteger c2x = evaluator.getWireValue(cgen.getOutWires().get(2));
        BigInteger c2y = evaluator.getWireValue(cgen.getOutWires().get(3));
        Assert.assertEquals(c1Expected.x, c1x);
        Assert.assertEquals(c1Expected.y, c1y);
        Assert.assertEquals(c2Expected.x, c2x);
        Assert.assertEquals(c2Expected.y, c2y);

        cgen = new ElgamalDecCircuitGenerator("test_dec", sk, c1Expected, c2Expected);
        cgen.generateCircuit();
        evaluator = new CircuitEvaluator(cgen);
        evaluator.evaluate();
        BigInteger msgEmbeddedX = evaluator.getWireValue(cgen.getOutWires().get(0));
        BigInteger msgEmbeddedY = evaluator.getWireValue(cgen.getOutWires().get(1));
        Assert.assertEquals(plainEmbedded.x, msgEmbeddedX);
        Assert.assertEquals(plainEmbedded.y, msgEmbeddedY);
    }

    /*
     * SAGE SCRIPT TO GENERATE TEST CASES

            MONT_A = 168698
            p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
            Fp = GF(p)
            E = EllipticCurve(Fp, [0, MONT_A, 0, 1, 0])

            as_edwards = lambda x, y: (x/y, (x-1)/(x+1))

            # Generator in Montgomery form
            Gu = 20362743932050971297570772668378244552617303936952202629186945600444066617704
            Gv = 17607012595805819799103265969342024902528946448890482994254679582103455633482
            G = E(Gu, Gv)

            # Generator in Edwards form
            (Gx, Gy) = as_edwards(G[0], G[1])

            def ElGamalPk(rand):
                return G*rand

            def ElGamalEnc(pk, msg, rand):
                emb = G*msg
                s = pk*rand
                c1 = G*rand
                c2 = emb + s
                return (c1, c2)

            def Run(sk, msg, rand):
                pk = ElGamalPk(sk)
                (c1, c2) = ElGamalEnc(pk, msg, rand)

                (pkx, pky) = as_edwards(pk[0], pk[1])
                (c1x, c1y) = as_edwards(c1[0], c1[1])
                (c2x, c2y) = as_edwards(c2[0], c2[1])
                print('BigInteger plain = new BigInteger("%s");' % msg)
                print('BigInteger random = new BigInteger("%s");' % rand)
                print('BigInteger sk = new BigInteger("%s");' % sk)
                print('BigInteger pkx = new BigInteger("%s");' % pkx)
                print('BigInteger pky = new BigInteger("%s");' % pky)
                print('BigInteger c1x_exp = new BigInteger("%s");' % c1x)
                print('BigInteger c1y_exp = new BigInteger("%s");' % c1y)
                print('BigInteger c2x_exp = new BigInteger("%s");' % c2x)
                print('BigInteger c2y_exp = new BigInteger("%s");' % c2y)
                print('')

            Run(193884008695, 42, 405309899802)
            Run(399850902903, 439864, 450983970634)
            Run(303897902911, 29479828, 11053400909823)
            Run(879404942393, 20503, 40394702098873424340)
            Run(409693890709893623, 9973, 400939876470980734)
            Run(943434980730874900974038, 3092, 304047020868704)
            Run(40909374909834, 11, 9438929848)
            Run(1047249, 309904, 2249)
     */

    @Test
    public void testElgamal1() {
        BigInteger plain = new BigInteger("42");
        BigInteger embx = new BigInteger("10535323380993087886472965362609445287191380307215483857591983963545230395281");
        BigInteger emby = new BigInteger("7231436746873551518227382498558787106156958562991793706165873939508722228633");
        BigInteger random = new BigInteger("405309899802");
        BigInteger sk = new BigInteger("193884008695");
        BigInteger pkx = new BigInteger("978284850177065715845354936399538155744704518287394149249989266721543926341");
        BigInteger pky = new BigInteger("17217898450642819735682116248429187704983468316731137090996994975594781709993");
        BigInteger c1x_exp = new BigInteger("6209753342914507047069393678393777606053129445267245021118724930570165102390");
        BigInteger c1y_exp = new BigInteger("13833111693398634820770094034626796017099662233881307399307205564513324971297");
        BigInteger c2x_exp = new BigInteger("13907350068782852152263605206410886873337365073355078405906573608140578916227");
        BigInteger c2y_exp = new BigInteger("9149307267029351159631788806576363925474058266352419493692535044637375928068");

        oneInputTest(plain, new AffinePoint(embx, emby), random, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp));
    }

    @Test
    public void testElgamal2() {
        BigInteger plain = new BigInteger("439864");
        BigInteger embx = new BigInteger("21595723076599009109058664539084069547870296843240503187093768329425288956219");
        BigInteger emby = new BigInteger("18097202554020896458191497189625993911817072567878859743287269009572194253272");
        BigInteger random = new BigInteger("450983970634");
        BigInteger sk = new BigInteger("399850902903");
        BigInteger pkx = new BigInteger("20154737202903373959008987578119304406284131217874899969944845558277817992999");
        BigInteger pky = new BigInteger("1451500859370872301186647480639399252652178011246579353042483481460967616442");
        BigInteger c1x_exp = new BigInteger("13767851651882786825828238650525311666109243511592091423220892588898327738067");
        BigInteger c1y_exp = new BigInteger("14201113599063576571732266926669867060047540480589574853271674802114565518776");
        BigInteger c2x_exp = new BigInteger("11281513278446502567509454944127307206766814564725516133271053816338428582558");
        BigInteger c2y_exp = new BigInteger("17497269930793571353526793497152430039356164254124504097809662107275794831395");

        oneInputTest(plain, new AffinePoint(embx, emby), random, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp));
    }

    @Test
    public void testElgamal3() {
        BigInteger plain = new BigInteger("29479828");
        BigInteger embx = new BigInteger("5090624408023259778415893099671816951849564978554128197760364260725374272226");
        BigInteger emby = new BigInteger("1694620465452621787587279378257383916417364672629797268890100137801744761116");
        BigInteger random = new BigInteger("11053400909823");
        BigInteger sk = new BigInteger("303897902911");
        BigInteger pkx = new BigInteger("31345435492764945386603444403456735016667614911767016804916505904146913718");
        BigInteger pky = new BigInteger("3472477189523050386935554696512445474228911648292671199409061816223781296741");
        BigInteger c1x_exp = new BigInteger("16661983122097729895470415777197910693188386722836724454130732963455447506482");
        BigInteger c1y_exp = new BigInteger("17007847171524527844810394284722559152301445421702086856010641854000099273132");
        BigInteger c2x_exp = new BigInteger("7139021775344664164940914982660644863540626632912765602986851904647638985983");
        BigInteger c2y_exp = new BigInteger("18209216882420184165131930424230059136829053346622850166005721954516988083586");

        oneInputTest(plain, new AffinePoint(embx, emby), random, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp));
    }

    @Test
    public void testElgamal4() {
        BigInteger plain = new BigInteger("20503");
        BigInteger embx = new BigInteger("12845294958965042102751963863752006883844944956236903541574358473329309925577");
        BigInteger emby = new BigInteger("13852249402230821061072176984977019373927816925932649735225753259434350541217");
        BigInteger random = new BigInteger("40394702098873424340");
        BigInteger sk = new BigInteger("879404942393");
        BigInteger pkx = new BigInteger("10997640620745899545837545119414331968682244195676070584160804376136114640598");
        BigInteger pky = new BigInteger("5251260915484226610043565702139545514957572922763390827968668429092562143428");
        BigInteger c1x_exp = new BigInteger("5130870884668610631015348865906048667180368340203436405890800803173086987861");
        BigInteger c1y_exp = new BigInteger("11258698468331220908750647421439638643393887461688664182953851500137208618816");
        BigInteger c2x_exp = new BigInteger("19901604474199070584712150266469540289963648560125937236459223742458159389116");
        BigInteger c2y_exp = new BigInteger("985969319195464703590470488822285435008689597729109974984302378593296801582");

        oneInputTest(plain, new AffinePoint(embx, emby), random, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp));
    }

    @Test
    public void testElgamal5() {
        BigInteger plain = new BigInteger("9973");
        BigInteger embx = new BigInteger("21249546255012322253651147490468785853734063458424176743427441242223238477066");
        BigInteger emby = new BigInteger("19163313625018099699656147186575486139064606174264885419610412536770071930681");
        BigInteger random = new BigInteger("400939876470980734");
        BigInteger sk = new BigInteger("409693890709893623");
        BigInteger pkx = new BigInteger("13992136274971400894852137371789350766796151296716443626589428788895177216997");
        BigInteger pky = new BigInteger("6324400635805062943160609087934728505578352380273117609861372564441901120793");
        BigInteger c1x_exp = new BigInteger("21075236085951074164922950136768700212716672422556437386709485159488483067618");
        BigInteger c1y_exp = new BigInteger("7037153242953542367141999653212387173304822661057616266271455447124850159904");
        BigInteger c2x_exp = new BigInteger("12722346692527044861221126620569345988799862610226799268676837044749280938913");
        BigInteger c2y_exp = new BigInteger("2199599937649104359053744524481996263472955632317989402668606780155308005390");

        oneInputTest(plain, new AffinePoint(embx, emby), random, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp));
    }

    @Test
    public void testElgamal6() {
        BigInteger plain = new BigInteger("3092");
        BigInteger embx = new BigInteger("21815978496312474512919753918867632909352304846797251404500539251001419890593");
        BigInteger emby = new BigInteger("10998142644080068987975221812204934750780721651950509029099168212917899938871");
        BigInteger random = new BigInteger("304047020868704");
        BigInteger sk = new BigInteger("943434980730874900974038");
        BigInteger pkx = new BigInteger("3846483841619321902862917272107178076874158719796021143240972648161003814796");
        BigInteger pky = new BigInteger("314034466265790003691711233423991034508251038848163284942777325603520307321");
        BigInteger c1x_exp = new BigInteger("8506876051495109885572212505749633871272484187943960928792612927166139812325");
        BigInteger c1y_exp = new BigInteger("9334681069096740443387087533001674933967941778573696906247180111818351369782");
        BigInteger c2x_exp = new BigInteger("8852349727856797217022035283948464963747980292944172667776505369901888813337");
        BigInteger c2y_exp = new BigInteger("12371006555687417080340953455276953005445284356479251781116836631805106046483");

        oneInputTest(plain, new AffinePoint(embx, emby), random, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp));
    }

    @Test
    public void testElgamal7() {
        BigInteger plain = new BigInteger("11");
        BigInteger embx = new BigInteger("3159157295926499193149445380353490579135947520816066200146599058178702160761");
        BigInteger emby = new BigInteger("1993878031115607811290687254767541017673417544700729312366435593051367955543");
        BigInteger random = new BigInteger("9438929848");
        BigInteger sk = new BigInteger("40909374909834");
        BigInteger pkx = new BigInteger("13345168622901191784438750183862538507465816750080851156916198885211569696192");
        BigInteger pky = new BigInteger("21413618423580598928909452978524821615374249788429724978101598924535885092242");
        BigInteger c1x_exp = new BigInteger("15711183884649224904454856382227095355072095970833527508539299423614231427950");
        BigInteger c1y_exp = new BigInteger("16551039642495596563058572364723705999618365983831868573843041620656890776573");
        BigInteger c2x_exp = new BigInteger("125169405077201087432783838668812328494669124013734218228369303721380372323");
        BigInteger c2y_exp = new BigInteger("10612500634152514107223761826458198851886897405592575009866652264045607257975");

        oneInputTest(plain, new AffinePoint(embx, emby), random, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp));
    }

    @Test
    public void testElgamal8() {
        BigInteger plain = new BigInteger("309904");
        BigInteger embx = new BigInteger("2640573642512030532873445190318092415770852369710169159778216117358968643594");
        BigInteger emby = new BigInteger("21280734730554608140681156136077661508322963951311883189549334291605821958283");
        BigInteger random = new BigInteger("2249");
        BigInteger sk = new BigInteger("1047249");
        BigInteger pkx = new BigInteger("14776023925527842556157578633549266512518974259387826572616427867181769340022");
        BigInteger pky = new BigInteger("12827802305038030891197110989803612115941834459979006457395294515328999342825");
        BigInteger c1x_exp = new BigInteger("10740319262742320151494347889930445424587267888618297044348704163374307498206");
        BigInteger c1y_exp = new BigInteger("16108697244032596912619169234395895725270713960640013547810106063624204999138");
        BigInteger c2x_exp = new BigInteger("10199959775847222269886580758148117810980621893786872403186234685052072645184");
        BigInteger c2y_exp = new BigInteger("2743834393457169307568265968374638311944787348697375574904206237236454404544");

        oneInputTest(plain, new AffinePoint(embx, emby), random, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp));
    }
}
