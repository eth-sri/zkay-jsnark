/*******************************************************************************
 * Tool for deriving public keys and performing ECDH via jsnark's ECDH gadget
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

import java.math.BigInteger;

import static zkay.ZkayUtil.unsignedBigintToBytes;
import static zkay.ZkayUtil.unsignedBytesToBigInt;

public class ZkayECDHGenerator extends CircuitGenerator {

	private final BigInteger secret;
	private final BigInteger pk;
	private final boolean late_eval;

	private Wire secret_wire;
	private Wire pk_wire;

	private ZkayECDHGenerator(BigInteger pk, BigInteger secret, boolean late_eval) {
		super("circuit");
		this.pk = pk;
		this.secret = secret;
		this.late_eval = late_eval;
	}

	@Override
	protected void buildCircuit() {
		secret_wire = late_eval ? createProverWitnessWire() : createConstantWire(secret);

		if (pk == null) {
			// If no public key specified, compute own public key
			makeOutput(new ZkayEcPkDerivationGadget(secret_wire, true).getOutputWires()[0]);
		} else {
			// Derive shared secret
			pk_wire = late_eval ? createInputWire() : createConstantWire(pk);
			ZkayECDHGadget gadget = new ZkayECDHGadget(pk_wire, secret_wire, true);
			gadget.validateInputs();
			makeOutput(gadget.getOutputWires()[0]);
		}
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		if (late_eval) {
			evaluator.setWireValue(secret_wire, this.secret);
			if (this.pk != null) {
				evaluator.setWireValue(pk_wire, this.pk);
			}
		}
	}

	@Override
	public void runLibsnark() {
		throw new RuntimeException("This circuit is only for evaluation");
	}

	private static BigInteger computeECKey(BigInteger pk, BigInteger sk) {
		ZkayECDHGenerator generator = new ZkayECDHGenerator(pk, sk, false);
		generator.generateCircuit();
		generator.evalCircuit();
		return generator.getCircuitEvaluator().getWireValue(generator.getOutWires().get(0));
	}

	public static String derivePk(BigInteger secret) {
		return computeECKey(null, secret).toString(16);
	}

	public static String getSharedSecret(BigInteger public_key, BigInteger secret) {
		return computeECKey(public_key, secret).toString(16);
	}

	public static BigInteger rnd_to_secret(String rnd_32) {
		BigInteger val = new BigInteger(rnd_32, 16);
		byte[] arr = unsignedBigintToBytes(val, 32);
		arr[0] &= 0x0f;
		arr[0] |= 0x10;
		arr[31] &= 0xf8;
		return unsignedBytesToBigInt(arr);
	}

	public static void main(String[] args) {
		if (args.length == 1) {
			BigInteger secret = rnd_to_secret(args[0]);
			System.out.println("Deriving public key from secret key 0x" + secret.toString(16));
			System.out.println(derivePk(secret));
			System.out.println(secret.toString(16));
		} else if (args.length == 2) {
			BigInteger secret = new BigInteger(args[0], 16);
			BigInteger pk = new BigInteger(args[1], 16);
			System.out.println("Deriving shared key from public key 0x" + pk.toString(16) + " and secret 0x" + secret.toString(16));
			System.out.println(getSharedSecret(pk, secret));
		} else {
			throw new IllegalArgumentException();
		}
	}
}
