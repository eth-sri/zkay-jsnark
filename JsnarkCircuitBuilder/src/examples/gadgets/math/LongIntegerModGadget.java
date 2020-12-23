/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.gadgets.math;

import circuit.auxiliary.LongElement;
import circuit.structure.Wire;

/**
 * This gadget provides a % b, when both operands are represented as long
 * elements. You can check the RSA gadgets/circuit generators for an example.
 * Most of the optimizations that reduce the cost of this step are more visible
 * in the LongElement class methods called by this gadget.
 */
public class LongIntegerModGadget extends LongIntegerDivision {

	/**
	 * @param a
	 * @param b
	 * @param restrictRange
	 * 		if true, the output will be forced to be less than b,
	 * 		otherwise the output remainder will only be guaranteed
	 * 		to have the same bitwidth as b, but not necessarily less
	 * 		than b. The second case is helpful when the purpose is
	 * 		just to reduce the range, while having consistent
	 * 		output. As an example (in a short integer case for
	 * 		simplicity): assume we are interested in this operation
	 * 		3001 % 10. The output should be 1 in normal cases, but
	 * 		to save some operations, we might skip checking that the
	 * 		result is less than the modulus and just check that it
	 * 		has the same bitwidth as the modulus, which we must do
	 * 		anyway since the result is provided as a witness. In
	 * 		that case, the output of this gadget could be 1 or 11,
	 * 		which in some contexts would be ok, e.g. in intermediate
	 * 		operations. See the RSA encryption gadget for an
	 * 		illustration.
	 * @param desc
	 */

	public LongIntegerModGadget(LongElement a, LongElement b, boolean restrictRange, String... desc) {
		super(a, b, restrictRange, desc);
	}

	/**
	 * @param a
	 * @param b
	 * @param bMinBitwidth
	 * 		The minimum bitwidth of the second operand
	 * @param restrictRange
	 * 		if true, the output will be forced to be less than b,
	 * 		otherwise the output remainder will only be guaranteed
	 * 		to have the same bitwidth as b, but not necessarily less
	 * 		than b. The second case is helpful when the purpose is
	 * 		just to reduce the range, while having consistent
	 * 		output. As an example (in a short integer case for
	 * 		simplicity): assume we are interested in this operation
	 * 		3001 % 10. The output should be 1 in normal cases, but
	 * 		to save some operations, we might skip checking that the
	 * 		result is less than the modulus and just check that it
	 * 		has the same bitwidth as the modulus, which we must do
	 * 		anyway since the result is provided as a witness. In
	 * 		that case, the output of this gadget could be 1 or 11,
	 * 		which in some contexts would be ok, e.g. in intermediate
	 * 		operations. See the RSA encryption gadget for an
	 * 		illustration.
	 * @param desc
	 */
	public LongIntegerModGadget(LongElement a, LongElement b, int bMinBitwidth, boolean restrictRange, String... desc) {
		super(a, b, bMinBitwidth, restrictRange, desc);
	}

	@Override
	public Wire[] getOutputWires() {
		return getRemainder().getArray();
	}
}
