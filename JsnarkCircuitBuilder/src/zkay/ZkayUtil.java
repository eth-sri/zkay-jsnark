/*******************************************************************************
 * Constants and helper functionality
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import circuit.structure.Wire;
import circuit.structure.WireArray;
import util.Util;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;

public class ZkayUtil {
    // These chunk sizes assume a plaintext <= 256 (253) bit.
    // If this should change in the future, the optimal chunk size should be computed on demand based on the plaintext size
    // (optimal: pick such that data has 1. least amount of chunks, 2. for that chunk amount least possible bit amount)
    public static final int ZKAY_SYMM_CIPHER_CHUNK_SIZE = 192;
    public static final int ZKAY_RSA_CHUNK_SIZE = 232;
    public static final int ZKAY_DUMMY_CHUNK_SIZE = 248;

    public static final int ZKAY_RSA_PKCS15_RND_CHUNK_SIZE = 224;
    public static final int ZKAY_RSA_OAEP_RND_CHUNK_SIZE = 128;
    public static final boolean ZKAY_RESTRICT_EVERYTHING = false; // if set to true for debugging, each typed wire constructor restricts bitwidth (rather than just private inputs)

    public static Wire[] reverseBytes(WireArray bit_array, int targetWordBits) {
        return new WireArray(Util.reverseBytes(bit_array.asArray())).packBitsIntoWords(targetWordBits);
    }

    public static BigInteger unsignedBytesToBigInt(byte[] bytes) {
        int signum = 0;
        for (byte b : bytes) {
            if (b != 0) {
                signum = 1;
                break;
            }
        }
        return new BigInteger(signum, bytes);
    }

    public static byte[] unsignedBigintToBytes(BigInteger val) {
        byte[] b = val.toByteArray();
        byte[] ret;
        if (b[0] == 0 && b.length > 1) {
            ret = new byte[b.length - 1];
            System.arraycopy(b, 1, ret, 0, b.length-1);
        } else {
            ret = b;
        }
        return ret;
    }

    public static byte[] unsignedBigintToBytes(BigInteger val, int byte_count) {
        byte[] t = unsignedBigintToBytes(val);
        if (t.length > byte_count) {
            throw new IllegalArgumentException("Value too large to fit into " + byte_count + " bytes");
        }
        byte[] ret = new byte[byte_count];
        System.arraycopy(t, 0, ret, byte_count - t.length, t.length);
        return ret;
    }

    public static void runZkayJsnarkInterface() {
        try {
            Process p;
            p = Runtime.getRuntime()
                    .exec(new String[] { "../libsnark/build/libsnark/zkay_interface/run_snark", "keygen",  ".", ".", "1"});
            p.waitFor();
            System.out.println(
                    "\n-----------------------------------RUNNING LIBSNARK KEYGEN -----------------------------------------");
            String line;
            BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder buf = new StringBuilder();
            while ((line = input.readLine()) != null) {
                buf.append(line).append("\n");
            }
            input.close();
            System.out.println(buf.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            Process p;
            p = Runtime.getRuntime()
                    .exec(new String[] { "../libsnark/build/libsnark/zkay_interface/run_snark", "proofgen",  ".", "proof.out", ".", "1", "1"});
            p.waitFor();
            System.out.println(
                    "\n-----------------------------------RUNNING LIBSNARK PROOFGEN -----------------------------------------");
            String line;
            BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder buf = new StringBuilder();
            while ((line = input.readLine()) != null) {
                buf.append(line).append("\n");
            }
            input.close();
            System.out.println(buf.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
