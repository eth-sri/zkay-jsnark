/*******************************************************************************
 * CBC chaskey LTS using BouncyCastle's CBCBlockCipher + custom cipher engine
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.math.BigInteger;

import static zkay.ZkayUtil.unsignedBigintToBytes;
import static zkay.ZkayUtil.unsignedBytesToBigInt;

public class ChaskeyLtsCbc {

    private static byte[] parse(String val, int len) {
        return unsignedBigintToBytes(new BigInteger(val, 16), len);
    }

    private static final int blocksize = 16;
    private static final int ivlen = blocksize;
    private static final int keylen = blocksize;
    private static final int msglen = 2*blocksize; // Must be multiple of blocksize

    public static byte[] crypt(boolean encrypt, byte[] key, byte[] iv, byte[] input) throws InvalidCipherTextException {
        // Initialize chaskey cipher in cbc mode
        ChaskeyLTSEngine chaskeyEngine = new ChaskeyLTSEngine();
        CBCBlockCipher cbc = new CBCBlockCipher(chaskeyEngine);
        BufferedBlockCipher cipher = new BufferedBlockCipher(cbc); // Don't need padding since size is always statically known in zkay and input is multiple of block size
        CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(encrypt, params);

        // Encrypt / Decrypt
        if (cipher.getOutputSize(input.length) != input.length) {
            throw new RuntimeException("Wrong size");
        }
        byte[] outbuf = new byte[cipher.getOutputSize(input.length)];
        int out_size = cipher.processBytes(input, 0, input.length, outbuf, 0);
        if (cipher.doFinal(outbuf, out_size) != 0) {
            throw new RuntimeException("Input not aligned to block size");
        }

        return outbuf;
    }

    public static void main(String[] args) throws InvalidCipherTextException {
        // Parse inputs
        if (args.length != 4) {
            throw new IllegalArgumentException("expected 4 arguments [enc|dec, key, iv, plain|cipher]");
        }
        boolean enc;
        switch (args[0]) {
            case "enc":
                enc = true;
                break;
            case "dec":
                enc = false;
                break;
            default:
                throw new IllegalArgumentException("First argument must be either 'enc' or 'dec'");
        }
        byte[] key = parse(args[1], keylen);
        byte[] iv = parse(args[2], ivlen);
        byte[] input = parse(args[3], msglen);

        // Perform encryption/decryption
        byte[] output = crypt(enc, key, iv, input);

        // Output result
        System.out.println(unsignedBytesToBigInt(output).toString(16));
    }
}
