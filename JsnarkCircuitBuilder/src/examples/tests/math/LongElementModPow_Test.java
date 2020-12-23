package examples.tests.math;

import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.math.LongIntegerModPowGadget;
import org.junit.Test;
import util.Util;

import java.math.BigInteger;

import static java.lang.Math.max;
import static org.junit.Assert.*;

public class LongElementModPow_Test {

	@Test
	public void testZeroBase() {
		BigInteger b = BigInteger.ZERO;
		BigInteger e = new BigInteger("123");
		BigInteger m = new BigInteger("456");
		ModPowCircuitGenerator generator = new ModPowCircuitGenerator("ModPow testZeroBase", b, e, m);
		BigInteger c = generator.computeResult();
		assertEquals(BigInteger.ZERO, c);
	}

	@Test
	public void testZeroExponent() {
		BigInteger b = new BigInteger("123");
		BigInteger e = BigInteger.ZERO;
		BigInteger m = new BigInteger("456");
		ModPowCircuitGenerator generator = new ModPowCircuitGenerator("ModPow testZeroExponent", b, e, m);
		BigInteger c = generator.computeResult();
		assertEquals(BigInteger.ONE, c);
	}

	@Test
	public void testSmallNumbers() {
		BigInteger b = new BigInteger("12");
		BigInteger e = new BigInteger("123");
		BigInteger m = new BigInteger("49");
		ModPowCircuitGenerator generator = new ModPowCircuitGenerator("ModPow testSmallNumbers", b, e, m);
		BigInteger c = generator.computeResult();
		assertEquals(new BigInteger("34"), c);
	}

	@Test
	public void testMediumNumbers() {
		BigInteger b = new BigInteger("1298864277");
		BigInteger e = new BigInteger("1924438110");
		BigInteger m = new BigInteger("1244548309");
		ModPowCircuitGenerator generator = new ModPowCircuitGenerator("ModPow testMediumNumbers", b, e, m);
		BigInteger c = generator.computeResult();
		assertEquals(new BigInteger("1150783129"), c);
	}

	@Test
	public void testBigNumbers() {
		BigInteger b = new BigInteger(
				"11110211273156662410517784086101070676798174233629875592006523851542199589511484624357222380466920698623369709791166395920135403033716226486271823558051887"
		);
		BigInteger e = new BigInteger(
				"2637223903302038027059095366575006140116518851780972335394726622955273020660866979705844488200866214968512356409733151412771035107664426094774364379448460"
		);
		BigInteger m = new BigInteger(
				"9039856562572728185463362753817675352642505391922098683577910062101216793612391112534717706865738103447277202233662317581994672238651788740521423343996904"
		);
		ModPowCircuitGenerator generator = new ModPowCircuitGenerator("ModPow testBigNumbers", b, e, m);
		BigInteger c = generator.computeResult();
		assertEquals(new BigInteger(
				"4080165247529688641168795936577955464635773385849731658617235197161883010753794462149192697334812616262060998583715533488845149182881410994561908785903409"
		), c);
	}

	@Test
	public void testRealisticNumbers() {
		BigInteger b = new BigInteger(
				"15956650897249075294287890909548588691016535757631844000721692781080978790771793003304333326456155339628147547863756759361111941048057919329605678045006387003118845424812414781109119032452838160536965218085832187645818402991051726686365424896376376138463019275030629862387452131124112828449849605774352184624296356040397392067591535898344029401557344157851423331349947726662846801394996336760192765313129692236663369309308131261194136050961594523067920319852599719071121178999921936044923537833234900637857502871107022346800344192648396680047852304207480588611262209580858243709487273995532029254571984523113086051346"
		);
		BigInteger e = new BigInteger(
				"4697746461884575427805002134199734467517334419138562871818872261507520712495625638661477092823743077652510231592069558322039313363971048146239140395156010532227978901007008013621323451325555507699137567249925765138805512041576455873778749392077679938669051571879048201562248353422621821313818468800870731654537156389741506975344180071490682207403506773775575583133428159426542658878821028574999930102135920754684895388203890410618224936810924312768101984632887380846322040192631340387101968258239400577608608121538149743825831047417447407203930304487778296358973753121921726528446659571751257620789683147050819642363"
		);
		BigInteger m = new BigInteger(
				"16341107832445116205501640528523261649363266022751014553926605400693992782728289669386500685967279904769515360460915461397699260232363692028255467589874731199535552036007819650139350306063649544137976119483100038509538628484509854982386732484301157451219210675460186536136186548019152716874977265904275559936393790071667479245132633151965846094409277716712783297072377828830780475770963688044926163259779633640754286181456464469086710235592710358693699582021363258539943667538953498866708030079155181768578680991002618462287324087199367911154799129512810687516524784908002605102740236792183147799768358168657519262340"
		);
		ModPowCircuitGenerator generator = new ModPowCircuitGenerator("ModPow testRealisticNumbers", b, e, m);
		BigInteger c = generator.computeResult();
		assertEquals(new BigInteger(
				"10041145040912246792217185960634142108882886420753112974004655693388733371253235530595367456730729439413713751150336230317387437323376172933840749743237925669646554701289404960263378809774983613579908750440162249938462891358444658196275015202486701830487504498862099547626730682213413245677424282244485936393385592413321214705531388577136462497417228753441282460805240686370595534242850057667908832877962069581872660385376872916767607794259471107512500691855904718103808084312491865904816163148549790852213092902579604085427284017671072032889098384745537545758045971825649926841956464860846563496600900920159805348436"
		), c);
	}

	private static class ModPowCircuitGenerator extends CircuitGenerator {

		private final BigInteger b;
		private final BigInteger e;
		private final BigInteger m;

		private LongElement bWire;
		private LongElement eWire;
		private LongElement mWire;

		private ModPowCircuitGenerator(String name, BigInteger b, BigInteger e, BigInteger m) {
			super(name);
			this.b = b;
			this.e = e;
			this.m = m;
		}

		@Override
		protected void buildCircuit() {
			bWire = createLongElementInput(max(b.bitLength(), 1), "b");
			eWire = createLongElementInput(max(e.bitLength(), 1), "e");
			mWire = createLongElementInput(max(m.bitLength(), 1), "m");
			LongIntegerModPowGadget modPow = new LongIntegerModPowGadget(bWire, eWire, mWire, max(m.bitLength(), 1));
			makeOutputArray(modPow.getOutputWires(), "c");
		}

		@Override
		public void generateSampleInput(CircuitEvaluator evaluator) {
			evaluator.setWireValue(bWire, b, LongElement.CHUNK_BITWIDTH);
			evaluator.setWireValue(eWire, e, LongElement.CHUNK_BITWIDTH);
			evaluator.setWireValue(mWire, m, LongElement.CHUNK_BITWIDTH);
		}

		public BigInteger computeResult() {
			long t1 = System.nanoTime();
			generateCircuit();
			long t2 = System.nanoTime();
			double ms = 1.e-6 * (t2 - t1);
			System.out.format("Building took %.3f ms\n", ms);
			evalCircuit();

			CircuitEvaluator evaluator = getCircuitEvaluator();
			BigInteger[] outValues = evaluator.getWiresValues(getOutWires().toArray(new Wire[0]));
			return Util.group(outValues, LongElement.CHUNK_BITWIDTH);
		}
	}
}
