/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.gadgets.math;

import circuit.auxiliary.LongElement;
import circuit.structure.Wire;

/**
 * This gadget provides floor(a / b), when both operands are represented as long
 * elements. You can check the RSA gadgets/circuit generators for an example.
 * Most of the optimizations that reduce the cost of this step are more visible
 * in the LongElement class methods called by this gadget.
 */
public class LongIntegerFloorDivGadget extends LongIntegerDivision {

	public LongIntegerFloorDivGadget(LongElement a, LongElement b, String... desc) {
		super(a, b, true, desc);
	}

	public LongIntegerFloorDivGadget(LongElement a, LongElement b, int bMinBitwidth, String... desc) {
		super(a, b, bMinBitwidth, true, desc);
	}

	@Override
	public Wire[] getOutputWires() {
		return getQuotient().getArray();
	}
}
