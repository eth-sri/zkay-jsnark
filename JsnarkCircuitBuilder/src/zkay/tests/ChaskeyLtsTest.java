package zkay.tests;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.Assert;
import org.junit.Test;
import zkay.*;
import zkay.crypto.CryptoBackend;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class ChaskeyLtsTest {
    // Chaskey lts test vectors from FELICS
    // https://www.cryptolux.org/index.php/FELICS

    final static byte[] key = {
            (byte) 0x56, (byte) 0x09, (byte) 0xe9, (byte) 0x68,
            (byte) 0x5f, (byte) 0x58, (byte) 0xe3, (byte) 0x29,
            (byte) 0x40, (byte) 0xec, (byte) 0xec, (byte) 0x98,
            (byte) 0xc5, (byte) 0x22, (byte) 0x98, (byte) 0x2f
    };
    final static byte[] plain = {
        (byte) 0xb8, (byte) 0x23, (byte) 0x28, (byte) 0x26,
        (byte) 0xfd, (byte) 0x5e, (byte) 0x40, (byte) 0x5e,
        (byte) 0x69, (byte) 0xa3, (byte) 0x01, (byte) 0xa9,
        (byte) 0x78, (byte) 0xea, (byte) 0x7a, (byte) 0xd8
    };
    final static byte[] cipher = {
        (byte) 0xd5, (byte) 0x60, (byte) 0x8d, (byte) 0x4d,
        (byte) 0xa2, (byte) 0xbf, (byte) 0x34, (byte) 0x7b,
        (byte) 0xab, (byte) 0xf8, (byte) 0x77, (byte) 0x2f,
        (byte) 0xdf, (byte) 0xed, (byte) 0xde, (byte) 0x07
    };

    @Test
    public void byteBigintConversionTest() {
        BigInteger b = ZkayUtil.unsignedBytesToBigInt(plain);
        byte[] o = ZkayUtil.unsignedBigintToBytes(b, plain.length);
        Assert.assertArrayEquals("Array bigint conversion does not preserve values", o, plain);

        b = ZkayUtil.unsignedBytesToBigInt(cipher);
        o = ZkayUtil.unsignedBigintToBytes(b, cipher.length);
        Assert.assertArrayEquals("Array bigint conversion does not preserve values", o, cipher);

        byte[] zero_arr = new byte[16];
        b = ZkayUtil.unsignedBytesToBigInt(zero_arr);
        o = ZkayUtil.unsignedBigintToBytes(b, zero_arr.length);
        Assert.assertArrayEquals("Array bigint conversion does not preserve values", o, zero_arr);
    }

    @Test
    public void chaskeyLtsTest() {
        ChaskeyLTSEngine crypto = new ChaskeyLTSEngine();

        // Test encrypt
        crypto.init(true, new KeyParameter(key));
        byte[] out = new byte[16];
        crypto.processBlock(plain, 0, out, 0);
        Assert.assertArrayEquals("Wrong encryption output", cipher, out);

        crypto.reset();

        // Test decrypt
        crypto.init(false, new KeyParameter(key));
        crypto.processBlock(out, 0, out, 0);
        Assert.assertArrayEquals("Wrong decryption output", plain, out);
    }

    @Test
    public void cbcChaskeyOutputSameAsGadgetTest() throws InvalidCipherTextException {
        // Define inputs
        BigInteger key = new BigInteger("b2e21df10a222a69ee1e6a2d60465f4c", 16);
        BigInteger iv = new BigInteger("f2c605c86352cea9fcaf88f12eba6371", 16);
        BigInteger plain = new BigInteger("6d60ad00cd9efa16841c842876fd4dc9f0fba1eb9e1ce623a83f45483a221f9", 16);

        // Compute encryption via jsnark gadget
        CircuitGenerator cgen = new CircuitGenerator("cbcchaskey") {
            @Override
            protected void buildCircuit() {
                TypedWire plainwire = new TypedWire(createConstantWire(plain), ZkayType.ZkUint(256), "plaintext");
                Wire ivwire = createConstantWire(iv);
                Wire keywire = createConstantWire(key);

                makeOutputArray(new ZkayCBCSymmetricEncGadget(plainwire, keywire, ivwire,
                        ZkayCBCSymmetricEncGadget.CipherType.CHASKEY).getOutputWires());
            }

            @Override
            public void generateSampleInput(CircuitEvaluator evaluator) {

            }
        };
        cgen.generateCircuit();
        cgen.evalCircuit();
        CircuitEvaluator evaluator = new CircuitEvaluator(cgen);
        evaluator.evaluate();
        ArrayList<Wire> outwires = cgen.getOutWires();
        BigInteger[] outs = new BigInteger[outwires.size()];
        for (int i = 0; i < outs.length; ++i) {
            outs[i] = evaluator.getWireValue(outwires.get(i));
        }


        // Compute encryption via CbcChaskey implementation
        byte[] iv_bytes = ZkayUtil.unsignedBigintToBytes(iv, 16);
        byte[] result = ChaskeyLtsCbc.crypt(true, ZkayUtil.unsignedBigintToBytes(key, 16),
                                            iv_bytes, ZkayUtil.unsignedBigintToBytes(plain, 32));


        // Convert output to format produced by gadget (iv included, packed 248bit values in reverse order)
        byte[] iv_cipher = new byte[16 + result.length];
        System.arraycopy(iv_bytes, 0, iv_cipher, 0, iv_bytes.length);
        System.arraycopy(result, 0, iv_cipher, iv_bytes.length, result.length);

        int chunk_size = CryptoBackend.Symmetric.CIPHER_CHUNK_SIZE / 8;
        int first_chunk_size = iv_cipher.length % chunk_size;
        List<BigInteger> bigints = new ArrayList<>();
        if (first_chunk_size != 0) {
            byte[] chunk = Arrays.copyOfRange(iv_cipher, 0, first_chunk_size);
            bigints.add(ZkayUtil.unsignedBytesToBigInt(chunk));
        }
        for (int i = first_chunk_size; i < iv_cipher.length - first_chunk_size; i += chunk_size) {
            byte[] chunk = Arrays.copyOfRange(iv_cipher, i, i + chunk_size);
            bigints.add(ZkayUtil.unsignedBytesToBigInt(chunk));
        }
        Collections.reverse(bigints);

        // Check if both are equal
        Assert.assertArrayEquals(outs, bigints.toArray());
    }
}
