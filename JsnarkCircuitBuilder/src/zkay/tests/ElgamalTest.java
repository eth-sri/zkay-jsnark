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
import zkay.ZkayElgamalRerandGadget;

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

    private static class ElgamalRerandCircuitGenerator extends CircuitGenerator {
        private final AffinePoint c1;
        private final AffinePoint c2;
        private final BigInteger random;
        private final AffinePoint pk;

        private ElgamalRerandCircuitGenerator(String name, AffinePoint c1, AffinePoint c2, AffinePoint pk, BigInteger random) {
            super(name);
            this.c1 = c1;
            this.c2 = c2;
            this.random = random;
            this.pk = pk;
        }

        @Override
        protected void buildCircuit() {
            Wire randomness = createConstantWire(random);
            WireArray randomnessBits = randomness.getBitWires(random.bitLength());

            ZkayElgamalRerandGadget gadget = new ZkayElgamalRerandGadget(
                    c1.asConstJubJub(this),
                    c2.asConstJubJub(this),
                    pk.asConstJubJub(this),
                    randomnessBits.asArray());
            makeOutputArray(gadget.getOutputWires(), "rerand_cipher");
        }

        @Override
        public void generateSampleInput(CircuitEvaluator evaluator) { }
    }

    private static class ElgamalDecCircuitGenerator extends CircuitGenerator {
        private final BigInteger msg;
        private final AffinePoint pk;
        private final BigInteger sk;
        private final AffinePoint c1;
        private final AffinePoint c2;

        private ElgamalDecCircuitGenerator(String name, AffinePoint pk, BigInteger sk, AffinePoint c1, AffinePoint c2, BigInteger msg) {
            super(name);
            this.msg = msg;
            this.pk = pk;
            this.sk = sk;
            this.c1 = c1;
            this.c2 = c2;
        }

        @Override
        protected void buildCircuit() {
            Wire secretKey = createConstantWire(sk);
            WireArray skBits = secretKey.getBitWires(sk.bitLength());
            Wire msgWire = createConstantWire(msg);

            ZkayElgamalDecGadget gadget = new ZkayElgamalDecGadget(pk.asConstJubJub(this),
                    skBits.asArray(), c1.asConstJubJub(this), c2.asConstJubJub(this), msgWire);
            makeOutputArray(gadget.getOutputWires(), "dummy output");
        }

        @Override
        public void generateSampleInput(CircuitEvaluator evaluator) { }
    }

    private void oneInputTest(BigInteger plain,
                              BigInteger random,
                              BigInteger random2,
                              BigInteger sk,
                              AffinePoint pk,
                              AffinePoint c1Expected,
                              AffinePoint c2Expected,
                              AffinePoint r1Expected,
                              AffinePoint r2Expected) {
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

        cgen = new ElgamalDecCircuitGenerator("test_dec", pk, sk, c1Expected, c2Expected, plain);
        cgen.generateCircuit();
        evaluator = new CircuitEvaluator(cgen);
        evaluator.evaluate();
        BigInteger one = evaluator.getWireValue(cgen.getOutWires().get(0));
        Assert.assertEquals(BigInteger.ONE, one);

        CircuitGenerator rgen = new ElgamalRerandCircuitGenerator("test_rerand", c1Expected, c2Expected, pk, random2);
        rgen.generateCircuit();
        evaluator = new CircuitEvaluator(rgen);
        evaluator.evaluate();
        BigInteger r1x = evaluator.getWireValue(rgen.getOutWires().get(0));
        BigInteger r1y = evaluator.getWireValue(rgen.getOutWires().get(1));
        BigInteger r2x = evaluator.getWireValue(rgen.getOutWires().get(2));
        BigInteger r2y = evaluator.getWireValue(rgen.getOutWires().get(3));
        Assert.assertEquals(r1Expected.x, r1x);
        Assert.assertEquals(r1Expected.y, r1y);
        Assert.assertEquals(r2Expected.x, r2x);
        Assert.assertEquals(r2Expected.y, r2y);
    }

    /*
     * SAGE SCRIPT TO GENERATE TEST CASES

            p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
            Fp = GF(p)

            MONT_A = 168698
            MONT_B = 168700

            WEIERSTRASS_A2 = Fp(MONT_A) / Fp(MONT_B)
            WEIERSTRASS_A4 = Fp(1) / (Fp(MONT_B) * Fp(MONT_B))

            E = EllipticCurve(Fp, [0, WEIERSTRASS_A2, 0, WEIERSTRASS_A4, 0])

            as_edwards = lambda x, y: ((Fp(MONT_B)*x)/(Fp(MONT_B)*y), ((Fp(MONT_B)*x)-1)/((Fp(MONT_B)*x)+1))
            as_weierstrass = lambda x, y: ((1+y)/((1-y) * Fp(MONT_B)), (1+y)/((1-y)*x*Fp(MONT_B)))

            # Generator in Edwards form
            Gx = Fp(11904062828411472290643689191857696496057424932476499415469791423656658550213)
            Gy = Fp(9356450144216313082194365820021861619676443907964402770398322487858544118183)

            # Generator in Weierstrass form
            (Gu, Gv) = as_weierstrass(Gx, Gy)
            G = E(Gu, Gv)

            def ElGamalPk(rand):
                return G*rand

            def ElGamalEmbed(msg):
                return G*msg

            def ElGamalEnc(pk, msg, rand):
                s = pk*rand
                c1 = G*rand
                c2 = msg + s
                return (c1, c2)

            def ElGamalRerand(c1, c2, pk, rand):
                z = ElGamalEmbed(0)
                (z1, z2) = ElGamalEnc(pk, z, rand)
                return (z1 + c1, z2 + c2)

            def Run(sk, msg, rand, rand2):
                    pk = ElGamalPk(sk)
                    emb = ElGamalEmbed(msg)
                    (c1, c2) = ElGamalEnc(pk, emb, rand)
                    (d1, d2) = ElGamalRerand(c1, c2, pk, rand2)


                    (pkx, pky) = as_edwards(pk[0], pk[1])
                    (c1x, c1y) = as_edwards(c1[0], c1[1])
                    (c2x, c2y) = as_edwards(c2[0], c2[1])
                    (d1x, d1y) = as_edwards(d1[0], d1[1])
                    (d2x, d2y) = as_edwards(d2[0], d2[1])
                    print('BigInteger plain = new BigInteger("%s");' % msg)
                    print('BigInteger random = new BigInteger("%s");' % rand)
                    print('BigInteger random2 = new BigInteger("%s");' % rand2)
                    print('BigInteger sk = new BigInteger("%s");' % sk)
                    print('BigInteger pkx = new BigInteger("%s");' % pkx)
                    print('BigInteger pky = new BigInteger("%s");' % pky)
                    print('BigInteger c1x_exp = new BigInteger("%s");' % c1x)
                    print('BigInteger c1y_exp = new BigInteger("%s");' % c1y)
                    print('BigInteger c2x_exp = new BigInteger("%s");' % c2x)
                    print('BigInteger c2y_exp = new BigInteger("%s");' % c2y)
                    print('BigInteger r1x_exp = new BigInteger("%s");' % d1x)
                    print('BigInteger r1y_exp = new BigInteger("%s");' % d1y)
                    print('BigInteger r2x_exp = new BigInteger("%s");' % d2x)
                    print('BigInteger r2y_exp = new BigInteger("%s");' % d2y)
                    print('')

            Run(193884008695, 42, 405309899802, 498372940021)
            Run(399850902903, 439864, 450983970634, 1293840028489)
            Run(303897902911, 29479828, 11053400909823, 2818211)
            Run(879404942393, 20503, 40394702098873424340, 1199860398278648324)
            Run(409693890709893623, 9973, 400939876470980734, 980387209578)
            Run(943434980730874900974038, 3092, 304047020868704, 29059219019893)
            Run(40909374909834, 11, 9438929848, 472788712)
            Run(1047249, 309904, 2249, 187498091987891)
            Run(448344687855328518203304384067387474955750326758815542295083498526674852893, 42, 4992017890738015216991440853823451346783754228142718316135811893930821210517, 39278167679809198687982907130870918672986098198762678158021231)

     */

    @Test
    public void testElgamal1() {
        BigInteger plain = new BigInteger("42");
        BigInteger random = new BigInteger("405309899802");
        BigInteger random2 = new BigInteger("498372940021");
        BigInteger sk = new BigInteger("193884008695");
        BigInteger pkx = new BigInteger("16805734088130288896486560435301001274867494983860633470885993193318772284256");
        BigInteger pky = new BigInteger("12162439373882959082081494184542429855888325538638041876957263568830191647503");
        BigInteger c1x_exp = new BigInteger("11968954241083294479582021735246320153591640350554672643229194688283746268751");
        BigInteger c1y_exp = new BigInteger("17725843468231767283529061723550512784133895105007547043315490343601022890819");
        BigInteger c2x_exp = new BigInteger("14203017384855711456240284283576262759333751248327439118405672500504849522290");
        BigInteger c2y_exp = new BigInteger("20209776676192040223587478743432669760403295009110800013515437438556993692901");
        BigInteger r1x_exp = new BigInteger("13591348693066294607093547701467815955182961658265372222056978378224264955118");
        BigInteger r1y_exp = new BigInteger("224496693684666279083264478158697965533005482392940254861497379468968617265");
        BigInteger r2x_exp = new BigInteger("10099626854765102435685973265870013378646709910580992014866316035367552182675");
        BigInteger r2y_exp = new BigInteger("14767943092180306325317567029873935159218010704312689008185444061546749553058");

        oneInputTest(plain, random, random2, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp), new AffinePoint(r1x_exp, r1y_exp), new AffinePoint(r2x_exp, r2y_exp));
    }

    @Test
    public void testElgamal2() {
        BigInteger plain = new BigInteger("439864");
        BigInteger random = new BigInteger("450983970634");
        BigInteger random2 = new BigInteger("1293840028489");
        BigInteger sk = new BigInteger("399850902903");
        BigInteger pkx = new BigInteger("10779867656770035784341593210643876194947544727395589637798068397910380874725");
        BigInteger pky = new BigInteger("10710250165934448718080245412425852632776460303399969324127728070645358476210");
        BigInteger c1x_exp = new BigInteger("21217098875190065545745711937037122650118596372225419155354220102137118082248");
        BigInteger c1y_exp = new BigInteger("8596071183490377685362568529945549465632153223890855646524023565071032562107");
        BigInteger c2x_exp = new BigInteger("12243154004977744181331269362343083310985310016493155403556248989647435379337");
        BigInteger c2y_exp = new BigInteger("5519301039601602428047143906992557429812524647117609489079159221144713724256");
        BigInteger r1x_exp = new BigInteger("12879341210277729652562065130333613991137793795439148105389860506010063832764");
        BigInteger r1y_exp = new BigInteger("12028008901381051327638773292171283584285939209840487219206955741588933923683");
        BigInteger r2x_exp = new BigInteger("21348363880076528954413108099703096613495992044195524899352374409593437815681");
        BigInteger r2y_exp = new BigInteger("448225545923890529546465107524885423214165045321928302012946805889055497548");

        oneInputTest(plain, random, random2, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp), new AffinePoint(r1x_exp, r1y_exp), new AffinePoint(r2x_exp, r2y_exp));
    }

    @Test
    public void testElgamal3() {
        BigInteger plain = new BigInteger("29479828");
        BigInteger random = new BigInteger("11053400909823");
        BigInteger random2 = new BigInteger("2818211");
        BigInteger sk = new BigInteger("303897902911");
        BigInteger pkx = new BigInteger("6414992512248574902260727978938771599371076631007732970498629309935423025541");
        BigInteger pky = new BigInteger("5588797317393153831727440400622613249402810496821055368006297877884731592188");
        BigInteger c1x_exp = new BigInteger("8457880476600111688234391562428843907438067884739990468648711671328170249897");
        BigInteger c1y_exp = new BigInteger("5513193275811000218852876613945594356630692965732869074432709923308086384141");
        BigInteger c2x_exp = new BigInteger("18871471165123797022765192830051533784387329326555711754062027748705980592258");
        BigInteger c2y_exp = new BigInteger("2960859843097508915587155523192075278657656986058747365068999681758189942574");
        BigInteger r1x_exp = new BigInteger("5366029516069172231732392874784911967837619433091056142690918344258949461784");
        BigInteger r1y_exp = new BigInteger("15522512818540701465276714745444492880212853838854710379826233848880406457659");
        BigInteger r2x_exp = new BigInteger("20641775747486861600659362415793944030784330174792501848914914142661365683768");
        BigInteger r2y_exp = new BigInteger("4050578578711337375872799728115034683479047059868613096904707326437389065410");

        oneInputTest(plain, random, random2, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp), new AffinePoint(r1x_exp, r1y_exp), new AffinePoint(r2x_exp, r2y_exp));
    }

    @Test
    public void testElgamal4() {
        BigInteger plain = new BigInteger("20503");
        BigInteger random = new BigInteger("40394702098873424340");
        BigInteger random2 = new BigInteger("1199860398278648324");
        BigInteger sk = new BigInteger("879404942393");
        BigInteger pkx = new BigInteger("12387118419063114351013801589244952825991461324644293362309293502203205557028");
        BigInteger pky = new BigInteger("12115395333617340639899571997042008699641933696177211723946595143553517655022");
        BigInteger c1x_exp = new BigInteger("8470974253563601832011440733676763727170463193150013886940174894973160268113");
        BigInteger c1y_exp = new BigInteger("11451437979815532596520424453163860534423134767934210095904011136004726209298");
        BigInteger c2x_exp = new BigInteger("3755451285204548243386923793338922452126300087029724835994171785286681386647");
        BigInteger c2y_exp = new BigInteger("5647640334301816276800781755737747998337525435601524546545647915251655431126");
        BigInteger r1x_exp = new BigInteger("19189418561911229092629541870381728693454153202408672369439535900592352563832");
        BigInteger r1y_exp = new BigInteger("6190221119147372470564485675966744098041498927494365664238329939235766355806");
        BigInteger r2x_exp = new BigInteger("20606498248708222575429594795830500486712281647481596625185438753439188883374");
        BigInteger r2y_exp = new BigInteger("16572497279801942880250856433861727900257767071582946132942024691743685883868");

        oneInputTest(plain, random, random2, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp), new AffinePoint(r1x_exp, r1y_exp), new AffinePoint(r2x_exp, r2y_exp));
    }

    @Test
    public void testElgamal5() {
        BigInteger plain = new BigInteger("9973");
        BigInteger random = new BigInteger("400939876470980734");
        BigInteger random2 = new BigInteger("980387209578");
        BigInteger sk = new BigInteger("409693890709893623");
        BigInteger pkx = new BigInteger("19038786034365121129737447326845215547071528710647939313908355725905191188995");
        BigInteger pky = new BigInteger("2214248829964940682725033718946556328772607342640796638058055582396213081489");
        BigInteger c1x_exp = new BigInteger("4049645432003817379994226545412987321416789229476686170128957164758871401279");
        BigInteger c1y_exp = new BigInteger("16222213389691959124184899327364928149053913263183689276193684274178358008847");
        BigInteger c2x_exp = new BigInteger("20622976335254791707752271712848997733998271931456734369112350069849260350570");
        BigInteger c2y_exp = new BigInteger("18512314847286550940159097003907528453978422823733935044908448485364066867711");
        BigInteger r1x_exp = new BigInteger("18012047336332553077224720034396440234969675366649853620277921699711776290087");
        BigInteger r1y_exp = new BigInteger("4548928749379657739820459290800365447344909635123275019182600575083243815395");
        BigInteger r2x_exp = new BigInteger("1463706360529125936803497998062819315280830785086437985047610791857684501217");
        BigInteger r2y_exp = new BigInteger("19260145642157386527783785376105740564939772326492185963463823034939637900510");

        oneInputTest(plain, random, random2, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp), new AffinePoint(r1x_exp, r1y_exp), new AffinePoint(r2x_exp, r2y_exp));
    }

    @Test
    public void testElgamal6() {
        BigInteger plain = new BigInteger("3092");
        BigInteger random = new BigInteger("304047020868704");
        BigInteger random2 = new BigInteger("29059219019893");
        BigInteger sk = new BigInteger("943434980730874900974038");
        BigInteger pkx = new BigInteger("11537936820602925819401558832551213707370271036894418664399992536929137441385");
        BigInteger pky = new BigInteger("21341107817615984362450388042180099428636742794610654263474204384582578901535");
        BigInteger c1x_exp = new BigInteger("5759977009078653474075225079238017700911800551924115686420736271126581950794");
        BigInteger c1y_exp = new BigInteger("19803546030374265878743382701240403271716532910167764659132971083286486432920");
        BigInteger c2x_exp = new BigInteger("13163571290961645931573447250398485715074921372484044328064084837570242392677");
        BigInteger c2y_exp = new BigInteger("2561391748738501878805425385302883053224206298569352883147194368919207812616");
        BigInteger r1x_exp = new BigInteger("3395078398739021110672219647886266968195610965478540927835578721265826113829");
        BigInteger r1y_exp = new BigInteger("3226633820835478993953835109420755648719417700859759750351066585603811804967");
        BigInteger r2x_exp = new BigInteger("9019585129196677535142255820209900579037484179808220251923228715078249551317");
        BigInteger r2y_exp = new BigInteger("1217462091073599572419023941043993348899274045225302280909460520543019198569");

        oneInputTest(plain, random, random2, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp), new AffinePoint(r1x_exp, r1y_exp), new AffinePoint(r2x_exp, r2y_exp));
    }

    @Test
    public void testElgamal7() {
        BigInteger plain = new BigInteger("11");
        BigInteger random = new BigInteger("9438929848");
        BigInteger random2 = new BigInteger("472788712");
        BigInteger sk = new BigInteger("40909374909834");
        BigInteger pkx = new BigInteger("18963601429601260488925336533212077133253656490980222624829298073185383062394");
        BigInteger pky = new BigInteger("10955396660032392970784549789530638666297323493863859953055999819584497853280");
        BigInteger c1x_exp = new BigInteger("1585437441439177712931180855793556731169186271301451803103671783184926099707");
        BigInteger c1y_exp = new BigInteger("17238669393035514721193643357894128432464531731096710478456257855369920548914");
        BigInteger c2x_exp = new BigInteger("1905207801382404175680710222856135239447406509352907340030501059581465963296");
        BigInteger c2y_exp = new BigInteger("20283410046728803419736841039385114962006738871621806761375631312392012049538");
        BigInteger r1x_exp = new BigInteger("1172658417426784028905024343050664961751271991789496194901660929685910153502");
        BigInteger r1y_exp = new BigInteger("17841298193398572201135170415806132380874126713992220099435734043652191436231");
        BigInteger r2x_exp = new BigInteger("7665114463165580774659286388392015419508027373404639766757305403638822493955");
        BigInteger r2y_exp = new BigInteger("20283399076363492534661102577978890614478101704954633485201009460012598302984");

        oneInputTest(plain, random, random2, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp), new AffinePoint(r1x_exp, r1y_exp), new AffinePoint(r2x_exp, r2y_exp));
    }

    @Test
    public void testElgamal8() {
        BigInteger plain = new BigInteger("309904");
        BigInteger random = new BigInteger("2249");
        BigInteger random2 = new BigInteger("187498091987891");
        BigInteger sk = new BigInteger("1047249");
        BigInteger pkx = new BigInteger("18796243199533119758484912853892319178237479744292136482258313307214080406845");
        BigInteger pky = new BigInteger("12562816211385016374219058391715927349499041836379377424804413924517388503535");
        BigInteger c1x_exp = new BigInteger("1093180272049918847371658916991447949076205903414878489417833675168297761329");
        BigInteger c1y_exp = new BigInteger("13652001713064310312737185590474813760724236299822572903882767064490757672145");
        BigInteger c2x_exp = new BigInteger("10233072806856007905263356274253594443764592402456777832406280451546479173285");
        BigInteger c2y_exp = new BigInteger("15828131619625847918230665900694350637473057051841970861137734958423235339878");
        BigInteger r1x_exp = new BigInteger("6913306664985054426548553351911704413655199598352597631955117153023351855134");
        BigInteger r1y_exp = new BigInteger("11053589110183477810314966941682935316922509679588844947720220513312942073284");
        BigInteger r2x_exp = new BigInteger("11926108613321274783962330168347934941286508322677303443866831105482343220833");
        BigInteger r2y_exp = new BigInteger("20884432215848566718856711647507988451300507966194327106115486784790475250127");

        oneInputTest(plain, random, random2, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp), new AffinePoint(r1x_exp, r1y_exp), new AffinePoint(r2x_exp, r2y_exp));
    }

    @Test
    public void testElgamal9() {
        BigInteger plain = new BigInteger("42");
        BigInteger random = new BigInteger("4992017890738015216991440853823451346783754228142718316135811893930821210517");
        BigInteger random2 = new BigInteger("39278167679809198687982907130870918672986098198762678158021231");
        BigInteger sk = new BigInteger("448344687855328518203304384067387474955750326758815542295083498526674852893");
        BigInteger pkx = new BigInteger("2543111965495064707612623550577403881714453669184859408922451773306175031318");
        BigInteger pky = new BigInteger("20927827475527585117296730644692999944545060105133073020125343132211068382185");
        BigInteger c1x_exp = new BigInteger("17990166387038654353532224054392704246273066434684370089496246721960255371329");
        BigInteger c1y_exp = new BigInteger("15866190370882469414665095798958204707796441173247149326160843221134574846694");
        BigInteger c2x_exp = new BigInteger("13578016172019942326633412365679613147103709674318008979748420035774874659858");
        BigInteger c2y_exp = new BigInteger("15995926508900361671313404296634773295236345482179714831868518062689263430374");
        BigInteger r1x_exp = new BigInteger("18784552725438955691676194299236851361347814005105892890816896300567057713848");
        BigInteger r1y_exp = new BigInteger("19693165835882985893423572117981608192865028744064689668605666703143190897862");
        BigInteger r2x_exp = new BigInteger("2530344813076577056814169669700763620340945156800181207832024608219434629412");
        BigInteger r2y_exp = new BigInteger("10093888871955407903732269877335284565715256278559408224374937460596986224178");

        oneInputTest(plain, random, random2, sk, new AffinePoint(pkx, pky), new AffinePoint(c1x_exp, c1y_exp), new AffinePoint(c2x_exp, c2y_exp), new AffinePoint(r1x_exp, r1y_exp), new AffinePoint(r2x_exp, r2y_exp));
    }
}
