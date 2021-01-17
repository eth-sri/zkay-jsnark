package zkay.crypto;

import zkay.HomomorphicInput;
import zkay.TypedWire;

public interface HomomorphicBackend {

	/**
	 * Perform the unary homomorphic operation 'op' on the ciphertext 'cipher'.
	 *
	 * @param op
	 * 		a char identifying the operation; one of {'-', '~', '!'}
	 * @param arg
	 * 		the operand, either a ciphertext or a plain wire
	 * @param keyName
	 * 		the qualified name of the key to be used
	 *
	 * @return the resulting ciphertext
	 *
	 * @throws UnsupportedOperationException
	 * 		if the backend does not support operation 'op'
	 */
	default TypedWire[] doHomomorphicOp(char op, HomomorphicInput arg, String keyName) {
		throw new UnsupportedOperationException("Unary operation " + op + " not supported");
	}

	/**
	 * Perform the binary homomorphic operation 'op' on the ciphertexts 'lhs' and 'rhs'.
	 *
	 * @param lhs
	 * 		the left-hand side operand, either a ciphertext or a plain wire
	 * @param op
	 * 		a char identifying the operation; one of {'+', '-', '*', '/', '%', '|', '&', '^', '<', '>'}
	 * @param rhs
	 * 		the right-hand side operand, either a ciphertext or a plain wire
	 * @param keyName
	 * 		the qualified name of the key to be used
	 *
	 * @return the resulting ciphertext
	 *
	 * @throws UnsupportedOperationException
	 * 		if the backend does not support operation 'op'
	 */
	default TypedWire[] doHomomorphicOp(HomomorphicInput lhs, char op, HomomorphicInput rhs, String keyName) {
		throw new UnsupportedOperationException("Binary operation " + op + " not supported");
	}

	/**
	 * Perform the boolean / comparison homomorphic operation 'op' on the ciphertexts 'lhs' and 'rhs'.
	 *
	 * @param lhs
	 * 		the left-hand side operand, either a ciphertext or a plain wire
	 * @param op
	 * 		a char identifying the operation; one of {"==", "!=", "<=", ">=", "&&", "||"}
	 * @param rhs
	 * 		the right-hand side operand, either a ciphertext or a plain wire
	 * @param keyName
	 * 		the qualified name of the key to be used
	 *
	 * @return the resulting ciphertext
	 *
	 * @throws UnsupportedOperationException
	 * 		if the backend does not support operation 'op'
	 */
	default TypedWire[] doHomomorphicOp(HomomorphicInput lhs, String op, HomomorphicInput rhs, String keyName) {
		throw new UnsupportedOperationException("Boolean / comparison operation " + op + " not supported");
	}

	/**
	 * Perform the ternary conditional operation on the ciphertexts 'cond', 'trueVal', 'falseVal'.
	 *
	 * @param cond
	 * 		the condition, either a ciphertext or a plain wire
	 * @param trueVal
	 * 		the value if cond is true, either a ciphertext or a plain wire
	 * @param falseVal
	 * 		the value if cond is false, either a ciphertext or a plain wire
	 * @param keyName
	 * 		the qualified name of the key to be used
	 *
	 * @return the resulting ciphertext
	 *
	 * @throws UnsupportedOperationException
	 * 		if the backend does not support operation 'op'
	 */
	default TypedWire[] doHomomorphicCond(HomomorphicInput cond, HomomorphicInput trueVal, HomomorphicInput falseVal, String keyName) {
		throw new UnsupportedOperationException("Ternary conditional not supported");
	}
}
