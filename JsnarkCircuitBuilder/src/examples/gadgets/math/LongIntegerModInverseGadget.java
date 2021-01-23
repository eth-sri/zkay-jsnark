package examples.gadgets.math;

import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.eval.Instruction;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import util.Util;

import java.math.BigInteger;

/**
 * This gadget computes the modular multiplicative inverse a^(-1) mod m,
 * where a and m are LongElements.
 * If restrictRange is set to true, the output will be the sole inverse a^(-1)
 * for which a < m holds. If restrictRange is false, the inverse may be any
 * value x for which ax = 1 mod m holds.
 * It is the responsibility of the caller to ensure that a and m are
 * relatively co-prime, i.e. the modular inverse actually exists.
 */
public class LongIntegerModInverseGadget extends Gadget {

	private final LongElement a; // the value to be inverted
	private final LongElement m; // the modulus
	private final boolean restrictRange; // whether to enforce that a^(-1) < m
	private LongElement inverse;

	public LongIntegerModInverseGadget(LongElement a, LongElement m, boolean restrictRange, String... desc) {
		super(desc);
		this.a = a;
		this.m = m;
		this.restrictRange = restrictRange;
		buildCircuit();
	}

	private void buildCircuit() {
		Wire[] inverseWires = generator.createProverWitnessWireArray(m.getSize());
		inverse = new LongElement(inverseWires, m.getCurrentBitwidth());
		Wire[] quotientWires = generator.createProverWitnessWireArray(m.getSize());
		LongElement quotient = new LongElement(quotientWires, m.getCurrentBitwidth());

		generator.specifyProverWitnessComputation(new Instruction() {
			@Override
			public void evaluate(CircuitEvaluator evaluator) {
				BigInteger aValue = evaluator.getWireValue(a, LongElement.CHUNK_BITWIDTH);
				BigInteger mValue = evaluator.getWireValue(m, LongElement.CHUNK_BITWIDTH);
				BigInteger inverseValue = aValue.modInverse(mValue);
				BigInteger quotientValue = aValue.multiply(inverseValue).divide(mValue);

				evaluator.setWireValue(inverseWires, Util.split(inverseValue, LongElement.CHUNK_BITWIDTH));
				evaluator.setWireValue(quotientWires, Util.split(quotientValue, LongElement.CHUNK_BITWIDTH));
			}
		});

		inverse.restrictBitwidth();
		quotient.restrictBitwidth();

		// a * a^(-1) = 1   (mod m)
		// <=> Exist q:  a * a^(-1) = q * m + 1
		LongElement product = a.mul(inverse);
		LongElement oneModM = quotient.mul(m).add(1);
		product.assertEquality(oneModM);

		if (restrictRange) {
			inverse.assertLessThan(m);
		}
	}

	public LongElement getResult() {
		return inverse;
	}

	@Override
	public Wire[] getOutputWires() {
		return inverse.getArray();
	}
}
