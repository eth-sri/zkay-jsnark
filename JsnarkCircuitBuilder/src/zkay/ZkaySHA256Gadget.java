/*******************************************************************************
 * SHA256 gadget wrapper, which reorders bytes for zkay compatibility
 * and supports trimming output
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import circuit.structure.Wire;
import circuit.structure.WireArray;

import java.util.Arrays;
import java.util.Collections;

public class ZkaySHA256Gadget extends examples.gadgets.hash.SHA256Gadget {
    private static int bytes_per_word = 32;

    private Wire[] _uint_output;

    private static Wire[] convert_inputs_to_bytes(Wire[] uint256_inputs) {
        Wire[] input_bytes = new WireArray(uint256_inputs).getBits(bytes_per_word * 8).packBitsIntoWords(8);
        // Reverse byte order of each input because jsnark reverses internally when packing
        for (int j = 0; j < uint256_inputs.length; ++j) {
            Collections.reverse(Arrays.asList(input_bytes).subList(j * bytes_per_word, (j+1) * bytes_per_word));
        }
        return input_bytes;
    }

    public ZkaySHA256Gadget(Wire[] uint256_inputs, int truncated_bits, String... desc) {
        super(convert_inputs_to_bytes(uint256_inputs), 8, uint256_inputs.length * bytes_per_word, false, true, desc);
        if (truncated_bits > 253 || truncated_bits < 0) {
            throw new RuntimeException("Unsupported output length " + truncated_bits + " bits");
        }
        assembleOutput(truncated_bits);
    }

    protected void assembleOutput(int truncated_length) {
        Wire[] digest = super.getOutputWires();
        // Invert word order to get correct byte order when packed into one big word below
        Collections.reverse(Arrays.asList(digest));
        if (truncated_length < 256) {
            // Keep truncated_length left-most bits as suggested in FIPS 180-4 to shorten the digest
            if (truncated_length % 32 == 0) {
                Wire[] shortened_digest = new Wire[truncated_length / 32];
                System.arraycopy(digest, digest.length - shortened_digest.length, shortened_digest, 0, shortened_digest.length);
                digest = shortened_digest;
            } else {
                _uint_output = new Wire[]{new WireArray(digest).getBits(32).shiftRight(256, 256 - truncated_length).packAsBits(truncated_length)};
                return;
            }
        }
        _uint_output = new WireArray(digest).packWordsIntoLargerWords(32, 8);
        if (_uint_output.length != 1) throw new RuntimeException("Wrong wire length");
    }

    @Override
    public Wire[] getOutputWires() {
        return _uint_output;
    }
}
