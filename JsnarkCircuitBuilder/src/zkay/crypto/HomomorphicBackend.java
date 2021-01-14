package zkay.crypto;

import zkay.TypedWire;

public interface HomomorphicBackend {

	/**
	 * Perform the unary homomorphic operation 'op' on the ciphertext 'cipher'.
	 *
	 * @param op
	 * 		a char identifying the operation; one of {'-', '~', '!'}
	 * @param cipher
	 * 		the ciphertext of the operand
	 * @param keyName
	 * 		the qualified name of the key to be used
	 *
	 * @return the resulting ciphertext
	 *
	 * @throws UnsupportedOperationException
	 * 		if the backend does not support operation 'op'
	 */
	default TypedWire[] doHomomorphicOp(char op, TypedWire[] cipher, String keyName) {
		throw new UnsupportedOperationException("Unary operation " + op + " not supported");
	}

	/**
	 * Perform the binary homomorphic operation 'op' on the ciphertexts 'lhs' and 'rhs'.
	 *
	 * @param lhs
	 * 		the ciphertext of the left-hand side operand
	 * @param op
	 * 		a char identifying the operation; one of {'+', '-', '*', '/', '%', '|', '&', '^', '<', '>'}
	 * @param rhs
	 * 		the ciphertext of the right-hand side operand
	 * @param keyName
	 * 		the qualified name of the key to be used
	 *
	 * @return the resulting ciphertext
	 *
	 * @throws UnsupportedOperationException
	 * 		if the backend does not support operation 'op'
	 */
	default TypedWire[] doHomomorphicOp(TypedWire[] lhs, char op, TypedWire[] rhs, String keyName) {
		throw new UnsupportedOperationException("Binary operation " + op + " not supported");
	}

	/**
	 * Perform the boolean / comparison homomorphic operation 'op' on the ciphertexts 'lhs' and 'rhs'.
	 *
	 * @param lhs
	 * 		the ciphertext of the left-hand side operand
	 * @param op
	 * 		a char identifying the operation; one of {"==", "!=", "<=", ">=", "&&", "||"}
	 * @param rhs
	 * 		the ciphertext of the right-hand side operand
	 * @param keyName
	 * 		the qualified name of the key to be used
	 *
	 * @return the resulting ciphertext
	 *
	 * @throws UnsupportedOperationException
	 * 		if the backend does not support operation 'op'
	 */
	default TypedWire[] doHomomorphicOp(TypedWire[] lhs, String op, TypedWire[] rhs, String keyName) {
		throw new UnsupportedOperationException("Boolean / comparison operation " + op + " not supported");
	}

	/**
	 * Perform the ternary conditional operation on the ciphertexts 'cond', 'trueVal', 'falseVal'.
	 *
	 * @param cond
	 * 		the ciphertext of the condition
	 * @param trueVal
	 * 		the ciphertext of the right-hand side operand
	 * @param falseVal
	 * 		the ciphertext of the right-hand side operand
	 * @param keyName
	 * 		the qualified name of the key to be used
	 *
	 * @return the resulting ciphertext
	 *
	 * @throws UnsupportedOperationException
	 * 		if the backend does not support operation 'op'
	 */
	default TypedWire[] doHomomorphicCond(TypedWire[] cond, TypedWire[] trueVal, TypedWire[] falseVal, String keyName) {
		throw new UnsupportedOperationException("Ternary conditional not supported");
	}
}
