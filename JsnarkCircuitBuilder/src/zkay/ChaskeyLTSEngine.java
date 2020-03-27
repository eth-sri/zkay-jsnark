/*******************************************************************************
 * Custom Java Chaskey LTS implementation as a BouncyCastle BlockCipher
 * (follows jsnark's chaskey gadget and the reference implementation it follows)
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ChaskeyLTSEngine implements BlockCipher {
    boolean enc;
    private int[] key;

    @Override
    public void init(boolean encrypt, CipherParameters cipherParameters) throws IllegalArgumentException {
        if (! (cipherParameters instanceof KeyParameter) || ((KeyParameter) cipherParameters).getKey().length != 16) {
            throw new IllegalArgumentException();
        }
        enc = encrypt;
        key = new int[4];
        ByteBuffer.wrap(((KeyParameter) cipherParameters).getKey()).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(key);
    }

    @Override
    public String getAlgorithmName() {
        return "chaskey_lts_128";
    }

    @Override
    public int getBlockSize() {
        return 16;
    }

    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        int[] v = new int[4];
        ByteBuffer.wrap(in, inOff, 16).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(v);

        v[0] ^= key[0];
        v[1] ^= key[1];
        v[2] ^= key[2];
        v[3] ^= key[3];

        if (enc) {
            for (int round = 0; round < 16; ++round)
            {
                v[0] += v[1];
                v[1] = Integer.rotateLeft(v[1], 5) ^ v[0];
                v[0] = Integer.rotateLeft(v[0], 16);

                v[2] += v[3];
                v[3] = Integer.rotateLeft(v[3], 8);
                v[3] ^= v[2];

                v[0] += v[3];
                v[3] = Integer.rotateLeft(v[3], 13);
                v[3] ^= v[0];

                v[2] += v[1];
                v[1] = Integer.rotateLeft(v[1], 7) ^ v[2];
                v[2] = Integer.rotateLeft(v[2], 16);
            }
        }
        else {
            for (int round = 0; round < 16; ++round)
            {
                v[2] = Integer.rotateRight(v[2], 16);
                v[1] = Integer.rotateRight(v[1] ^ v[2], 7);
                v[2] -= v[1];

                v[3] ^= v[0];
                v[3] = Integer.rotateRight(v[3], 13);
                v[0] -= v[3];

                v[3] ^= v[2];
                v[3] = Integer.rotateRight(v[3], 8);
                v[2] -= v[3];

                v[0] = Integer.rotateRight(v[0], 16);
                v[1] = Integer.rotateRight(v[1] ^ v[0], 5);
                v[0] -= v[1];
            }
        }

        v[0] ^= key[0];
        v[1] ^= key[1];
        v[2] ^= key[2];
        v[3] ^= key[3];

        ByteBuffer.wrap(out, outOff, 16).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().put(v);
        return 16;
    }

    @Override
    public void reset() {
        // There are no state modifications -> nothing to do here
    }
}
