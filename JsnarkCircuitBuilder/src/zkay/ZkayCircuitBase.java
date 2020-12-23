/*******************************************************************************
 * core zkay jsnark abstraction layer
 * (in the form of CircuitGenerator subclass)
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import circuit.auxiliary.LongElement;
import circuit.eval.CircuitEvaluator;
import circuit.operations.Gadget;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.*;

import static zkay.ZkayType.*;
import static zkay.ZkayUtil.ZKAY_RSA_CHUNK_SIZE;
import static zkay.ZkayUtil.ZKAY_SYMM_CIPHER_CHUNK_SIZE;

public abstract class ZkayCircuitBase extends CircuitGenerator {
    private enum CryptoBackend {
        DUMMY,
        RSA_OAEP,
        RSA_PKCS15,
        ECDH_AES,
        ECDH_CHASKEY,
    }

    /** Whether to include comments for the more complex operations in the circuit.arith file */
    private static final boolean ADD_OP_LABELS = true;

    protected final String realCircuitName;
    protected final int keyBits;

    private final CryptoBackend cryptoBackend;
    private final boolean isSymmetric;
    private final Wire[] all_pub_io_wires;

    private Wire my_sk = null;
    private Wire my_pk = null;
    private final Map<String, Wire> sharedKeys;

    private int current_pub_in_idx = 0;
    private int current_pub_out_idx;
    private final Wire[] all_priv_in_wires;
    private int current_priv_in_idx = 0;

    private final List<String> pub_in_names = new ArrayList<>();
    private final List<String> pub_out_names = new ArrayList<>();
    private final List<String> priv_in_names = new ArrayList<>();

    private final int pub_in_count;
    private final boolean use_input_hashing;

    private final HashMap<String, TypedWire[]> vars = new HashMap<>();
    private final HashMap<String, LongElement> keys = new HashMap<>();

    private final Stack<TypedWire> current_guard_condition = new Stack<>();
    private BigInteger[] serialized_arguments = null;

    private final Map<String, Integer> name_prefix_indices = new HashMap<>();
    private final Stack<String> name_prefix = new Stack<>();

    private final Stack<Stack<String>> guard_prefixes = new Stack<>();
    private final Stack<HashMap<String, Integer>> guard_prefix_indices = new Stack<>();

    public ZkayCircuitBase(String name, String crypto_backend, int key_bits, int pub_in_size, int pub_out_size, int priv_size, boolean use_input_hashing) {
        super("circuit");
        this.realCircuitName = name;
        switch (crypto_backend) {
            case "dummy":
                this.cryptoBackend = CryptoBackend.DUMMY;
                this.isSymmetric = false;
                break;
            case "ecdh-chaskey":
                this.cryptoBackend = CryptoBackend.ECDH_CHASKEY;
                this.isSymmetric = true;
                break;
            case "ecdh-aes":
                this.cryptoBackend = CryptoBackend.ECDH_AES;
                this.isSymmetric = true;
                break;
            case "rsa-pkcs1.5":
                this.cryptoBackend = CryptoBackend.RSA_PKCS15;
                this.isSymmetric = false;
                break;
            case "rsa-oaep":
                this.cryptoBackend = CryptoBackend.RSA_OAEP;
                this.isSymmetric = false;
                break;
            default:
                throw new RuntimeException("Invalid crypto backend");
        }
        this.keyBits = key_bits;
        this.sharedKeys = isSymmetric ? new HashMap<>() : null;

        this.pub_in_count = pub_in_size;
        this.current_pub_out_idx = pub_in_size;
        this.all_pub_io_wires = new Wire[pub_in_size + pub_out_size];
        this.all_priv_in_wires = new Wire[priv_size];

        this.use_input_hashing = use_input_hashing;

        clear_prefix(this.name_prefix, this.name_prefix_indices);
        clear_prefix(this.guard_prefixes.push(new Stack<>()), this.guard_prefix_indices.push(new HashMap<>()));
    }

    public void run(String[] args) {
        switch (args[0]) {
            case "compile":
                compileCircuit();
                break;
            case "prove":
                compileCircuit();
                parse_inputs(Arrays.asList(args).subList(1, args.length));
                System.out.println("Evaluating circuit '" + realCircuitName + "'");
                evalCircuit();
                break;
            default:
                throw new RuntimeException("invalid command");
        }
        prepFiles();
    }

    private void parse_inputs(List<String> args) {
        int tot_count = all_pub_io_wires.length +  all_priv_in_wires.length;
        if (args.size() != tot_count) {
            throw new IllegalArgumentException("Input count mismatch, expected " + tot_count + ", was " + args.size());
        }
        serialized_arguments = new BigInteger[tot_count];
        for (int i = 0; i < tot_count; ++i) {
            BigInteger v = new BigInteger(args.get(i), 16);
            if (v.signum() == -1) {
                throw new IllegalArgumentException("No signed inputs (signed must be converted to unsigned beforehand)");
            }
            serialized_arguments[i] = v;
        }
    }

    private void compileCircuit() {
        System.out.println("Compiling circuit '" + realCircuitName + "'");
        generateCircuit();
        if (current_pub_in_idx != pub_in_count || current_pub_out_idx != all_pub_io_wires.length) {
            throw new RuntimeException("Not all public inputs assigned");
        }
        if (current_priv_in_idx != all_priv_in_wires.length) {
            throw new RuntimeException("Not all private inputs assigned");
        }
        if (use_input_hashing) {
            makeOutputArray(new ZkaySHA256Gadget(all_pub_io_wires, 253).getOutputWires(), "digest");
        }
        System.out.println("Done with generateCircuit, preparing dummy files...");
    }

    @Override
    protected void buildCircuit() {
        // Create IO wires
        int pub_out_count = all_pub_io_wires.length - pub_in_count;
        final Wire[] in_array, out_array, priv_in_array;
        if (use_input_hashing) {
            in_array = createProverWitnessWireArray(pub_in_count, "in_");
            out_array = createProverWitnessWireArray(pub_out_count, "out_");
        } else {
            in_array = createInputWireArray(pub_in_count, "in_");
            out_array = createInputWireArray(pub_out_count, "out_");
        }
        priv_in_array = createProverWitnessWireArray(all_priv_in_wires.length, "priv_");

        if (isSymmetric) {
            // Ensure that provided sender keys form a key pair
            my_sk = priv_in_array[0];
            my_pk = in_array[0];

            ZkayEcPkDerivationGadget pkDerivationGadget = new ZkayEcPkDerivationGadget(my_sk, true, "getPk(mySk)");
            addEqualityAssertion(my_pk, pkDerivationGadget.getOutputWires()[0]);
        }

        System.arraycopy(in_array, 0, all_pub_io_wires, 0, pub_in_count);
        System.arraycopy(out_array, 0, all_pub_io_wires, pub_in_count, pub_out_count);
        System.arraycopy(priv_in_array, 0, all_priv_in_wires, 0, all_priv_in_wires.length);
    }

    private Wire[] addIO(String typeName, String name, List<String> name_list, Wire[] src, int start_idx, int size, ZkayType t, boolean restrict) {
        name = getQualifiedName(name);
        System.out.println("Adding '" + name + "' = " + typeName + "[" + start_idx +  ":" + (start_idx + size) + "]");
        Wire[] input = Arrays.copyOfRange(src, start_idx, start_idx + size);
        TypedWire[] tinput = new TypedWire[input.length];
        for (int i = 0; i < input.length; ++i) {
            // Enforce size and associate wire with type (technically restrict is only required for private inputs)
            tinput[i] = new TypedWire(input[i], t, name, restrict);
        }
        vars.put(name, tinput);
        name_list.add(name);
        return input;
    }

    /** CIRCUIT IO **/

    protected void addIn(String name, int size, ZkayType t) {
        addIO("in", name, pub_in_names, all_pub_io_wires, current_pub_in_idx, size, t, false);
        current_pub_in_idx += size;
    }

    protected void addK(String name, int size) {
        int csize = isSymmetric ? 256 : ZKAY_RSA_CHUNK_SIZE;
        Wire[] input = addIO("in", name, pub_in_names, all_pub_io_wires, current_pub_in_idx, size, ZkUint(csize), false);
        current_pub_in_idx += size;

        if (isSymmetric) {
            if (size != 1) {
                throw new IllegalArgumentException("Expected key size 1uint for symmetric keys");
            }
            String keystr = String.format("sha256(ecdh(%s, %s))", name, my_sk);

            // Get other public key
            // In the case of decryption with default-initialization, it is possible that the sender pk stored in the
            // cipher struct is 0. In that case -> replace with any valid pk (my_pk for simplicity), to prevent ecdh gadget
            // from crashing (wrong output is not a problem since decryption enforces (pk_zero || cipher_zero) => all_zero
            // and ignores the ecdh result in that case.
            Wire actual_other_pk = input[0];
            actual_other_pk = cond_expr(actual_other_pk.checkNonZero(name + " != 0"), actual_other_pk, my_pk);

            // PreCompute shared key with me
            ZkayECDHGadget sharedKeyGadget = new ZkayECDHGadget(actual_other_pk, my_sk, false, keystr);
            sharedKeyGadget.validateInputs();
            sharedKeys.put(getQualifiedName(name), sharedKeyGadget.getOutputWires()[0]);
        } else {
            WireArray keybits = new WireArray(input).getBits(ZKAY_RSA_CHUNK_SIZE, name + "_bits").adjustLength(keyBits);
            LongElement l = new LongElement(keybits);
            keys.put(getQualifiedName(name), l);
        }
    }

    protected void addOut(String name, int size, ZkayType t) {
        addIO("out", name, pub_out_names, all_pub_io_wires, current_pub_out_idx, size, t, false);
        current_pub_out_idx += size;
    }

    protected void addS(String name, int size, ZkayType t) {
        addIO("priv", name, priv_in_names, all_priv_in_wires, current_priv_in_idx, size, t, true);
        current_priv_in_idx += size;
    }

    /** CONTROL FLOW **/

    protected void stepIn(String fct) {
        push_prefix(name_prefix, name_prefix_indices, guard_prefixes.peek().peek() + fct);
        clear_prefix(guard_prefixes.push(new Stack<>()), guard_prefix_indices.push(new HashMap<>()));
    }

    protected void stepOut() {
        pop_prefix(name_prefix);
        guard_prefixes.pop();
        guard_prefix_indices.pop();
    }

    protected void addGuard(String name, boolean is_true) {
        Wire new_wire = get(name).wire;

        push_prefix(guard_prefixes.peek(), guard_prefix_indices.peek(), name + "_" + is_true);

        if (!is_true) {
            new_wire = new_wire.invAsBit();
        }

        if (!current_guard_condition.empty()) {
            new_wire = current_guard_condition.peek().wire.and(new_wire);
        }
        current_guard_condition.push(new TypedWire(new_wire, ZkBool, "guard_cond_top_" + name + "_" + is_true));
    }

    protected void popGuard() {
        current_guard_condition.pop();
        pop_prefix(guard_prefixes.peek());
    }

    protected TypedWire ite(TypedWire condition, TypedWire trueVal, TypedWire falseVal) {
        checkType(ZkBool, condition.type);
        checkType(trueVal.type, falseVal.type);
        return new TypedWire(cond_expr(condition.wire, trueVal.wire, falseVal.wire), trueVal.type,
                String.format("%s ? %s : %s", condition.name, trueVal.name, falseVal.name));
    }

    /** UNARY OPS **/

    public static TypedWire negate(TypedWire val) {
        int bits = val.type.bitwidth;
        if (bits < 256) {
            // Take two's complement
            TypedWire invbits = new TypedWire(val.wire.invBits(val.type.bitwidth), val.type, "~" + val.name);
            return invbits.plus(((ZkayCircuitBase)getActiveCircuitGenerator()).val(1, val.type));
        } else {
            return new TypedWire(val.wire.mul(-1, "-" + val.name), val.type, "-" + val.name);
        }
    }

    public static TypedWire bitInv(TypedWire val) {
        ZkayType resultType = checkType(val.type, val.type, false);
        Wire res = val.wire.invBits(resultType.bitwidth, "~" + val.name);
        return new TypedWire(res, resultType, "~" + val.name);
    }

    public static TypedWire not(TypedWire val) {
        checkType(ZkBool, val.type);
        return new TypedWire(val.wire.invAsBit("!" + val.name), ZkBool, "!" + val.name);
    }

    /** String op interface **/

    public static TypedWire o_(char op, TypedWire wire) {
        switch (op) {
            case '-': return negate(wire);
            case '~': return bitInv(wire);
            case '!': return not(wire);
            default:
                throw new IllegalArgumentException();
        }
    }
    public static TypedWire o_(TypedWire lhs, char op, TypedWire rhs) {
        switch (op) {
            case '+': return lhs.plus(rhs);
            case '-': return lhs.minus(rhs);
            case '*': return lhs.times(rhs);
            case '|': return lhs.bitOr(rhs);
            case '&': return lhs.bitAnd(rhs);
            case '^': return lhs.bitXor(rhs);
            case '<': return lhs.isLessThan(rhs);
            case '>': return lhs.isGreaterThan(rhs);
            default:
                throw new IllegalArgumentException();
        }
    }
    public TypedWire o_(TypedWire cond, char condChar, TypedWire trueVal, char altChar, TypedWire falseVal) {
        return ite(cond, trueVal, falseVal);
    }
    public static TypedWire o_(TypedWire lhs, String op, int rhs) {
        switch (op) {
            case "<<": return lhs.shiftLeftBy(rhs);
            case ">>": return lhs.shiftRightBy(rhs);
            default:
                throw new IllegalArgumentException();
        }
    }
    public static TypedWire o_(TypedWire lhs, String op, TypedWire rhs) {
        switch (op) {
            case "==": return lhs.isEqualTo(rhs);
            case "!=": return lhs.isNotEqualTo(rhs);
            case "<=": return lhs.isLessThanOrEqual(rhs);
            case ">=": return lhs.isGreaterThanOrEqual(rhs);
            case "&&": return lhs.and(rhs);
            case "||": return lhs.or(rhs);
            default:
                throw new IllegalArgumentException();
        }
    }

    /** TYPE CASTING **/

    protected TypedWire cast(TypedWire w, ZkayType targetType) {
        return convertTo(w, targetType);
    }

    /** SOURCE **/

    protected TypedWire get(String name) {
        name = getQualifiedName(name);
        TypedWire[] w = vars.get(name);
        if (w == null) {
            throw new RuntimeException("Variable " + name + " is not associated with a wire");
        }
        if (w.length != 1) {
            throw new RuntimeException("Tried to treat array as a single wire");
        }
        return w[0];
    }

    public TypedWire val(boolean val) {
        return new TypedWire(val ? getOneWire() : getZeroWire(), ZkBool, "const_" + val);
    }

    public TypedWire val(int val, ZkayType t) {
        Wire w;
        if (val == 0) {
            w = getZeroWire();
        } else if (val == 1) {
            w = getOneWire();
        } else {
            return val(String.valueOf(val), t);
        }
        return new TypedWire(w, t, "const_" + val);
    }

    public TypedWire val(String val, ZkayType t) {
        BigInteger v = new BigInteger(val, 10);
        Wire w;
        if (v.signum() == -1) {
            if (t.signed) {
                BigInteger neg_v = ZkayType.GetNegativeConstant(v.negate(), t.bitwidth);
                if (neg_v.signum() == -1) {
                    throw new RuntimeException("Constant is still negative");
                }
                w = createConstantWire(neg_v, "const_" + v.toString(10));
            } else {
                throw new IllegalArgumentException("Cannot store negative constant in unsigned wire");
            }
        } else {
            w = createConstantWire(v, "const_" + v.toString(10));
        }
        return new TypedWire(w, t, "const_" + v.toString(10));
    }

    /** SINK **/

    protected void decl(String lhs, TypedWire val) {
        if (val.type == null) throw new IllegalArgumentException("Tried to use untyped wires");

        // Get old value and check type
        TypedWire old_val;
        if (vars.containsKey(lhs)) {
            old_val = get(lhs);
            checkType(old_val.type, val.type);
        } else {
            old_val = val(0, val.type);
        }

        // Only assign value if guard condition is met
        if (current_guard_condition.empty()) {
            set(lhs, new TypedWire(val.wire, val.type, lhs));
        } else {
            set(lhs, new TypedWire(cond_expr(current_guard_condition.peek().wire, val.wire, old_val.wire), val.type, lhs));
        }
    }

    private Wire cond_expr(Wire cond, Wire trueVal, Wire falseVal) {
        if (ZkayUtil.ZKAY_RESTRICT_EVERYTHING) {
            addBinaryAssertion(cond);
        }
        return cond.mul(trueVal, "ite_true").add(cond.invAsBit().mul(falseVal, "ite_false"), "ite_res");
    }

    private TypedWire convertTo(TypedWire w, ZkayType targetType) {
        ZkayType fromType = w.type;

        final int fromBitwidth = fromType.bitwidth;
        final boolean wasSigned = fromType.signed;
        final int toBitwidth = targetType.bitwidth;

        Wire new_w;
        if (fromBitwidth < toBitwidth) {
            // Upcast -> sign/zero extend
            if (!wasSigned && w.wire.getBitWiresIfExistAlready() == null) {
                // If this wire was not yet split we can return it without splitting as an optimization
                // -> upcasts from an unsigned type (most common case) are for free this way
                new_w = w.wire;
            } else {
                WireArray bitwires = w.wire.getBitWires(fromBitwidth);
                if (wasSigned && toBitwidth == 256) {
                    // Special case -> sign extension not possible since not enought bits,
                    // want -1 to be field_prime - 1
                    Wire signbit = bitwires.get(fromBitwidth-1);
                    new_w = cond_expr(signbit, negate(w).wire.mul(-1), w.wire);
                } else {
                    Wire extend_bit = wasSigned ? bitwires.get(fromBitwidth-1) : getZeroWire();
                    Wire[] newWs = new Wire[toBitwidth];
                    System.arraycopy(bitwires.asArray(), 0, newWs, 0, fromBitwidth);
                    for (int i = fromBitwidth; i < toBitwidth; i++) {
                        newWs[i] = extend_bit;
                    }
                    new_w = new WireArray(newWs).packAsBits(toBitwidth);
                }
            }
        } else if (fromBitwidth > toBitwidth) {
            // Downcast -> only keep lower bits
            new_w = w.wire.getBitWires(fromBitwidth, "downcast1 " + w.name).packAsBits(toBitwidth, "downcast2 " + w.name);
        } else {
            // Type stays the same -> no expensive bitwise operations necessary
            new_w = w.wire;
        }
        return new TypedWire(new_w, targetType, String.format("(%s) %s", targetType.toString(), w.name));
    }

    private Wire[] cryptoEnc(String plain, String key, String rnd, boolean is_dec) {
        String desc =  ADD_OP_LABELS ? String.format("enc%s(%s, %s, %s)", is_dec ? "[dec]" : "", getQualifiedName(plain), getQualifiedName(key), getQualifiedName(rnd)) : "";
        Gadget enc;
        switch (cryptoBackend) {
            case RSA_OAEP:
                enc = new ZkayRSAEncryptionGadget(getArr(plain), getKey(key), getArr(rnd), keyBits, true, desc);
                break;
            case RSA_PKCS15:
                enc = new ZkayRSAEncryptionGadget(getArr(plain), getKey(key), getArr(rnd), keyBits, false, desc);
                break;
            case DUMMY:
                enc = new ZkayDummyEncryptionGadget(getArr(plain), getKey(key), getArr(rnd), keyBits, desc);
                break;
            default:
                throw new RuntimeException();
        }

        return enc.getOutputWires();
    }

    private Wire extractIv(Wire[] iv_cipher) {
        if (iv_cipher == null || iv_cipher.length == 0) {
            throw new IllegalArgumentException("Iv cipher must not be empty");
        }
        // This assumes as cipher length of 256 bits
        int last_block_cipher_len = (256 - (((iv_cipher.length - 1) * ZKAY_SYMM_CIPHER_CHUNK_SIZE) % 256)) % 256;
        Wire iv = iv_cipher[iv_cipher.length - 1];
        if (last_block_cipher_len > 0) {
            iv = iv.shiftRight(ZKAY_SYMM_CIPHER_CHUNK_SIZE, last_block_cipher_len);
        }
        return iv;
    }

    private Wire[] cryptoSymmEnc(String plain, String other_pk, String iv_cipher, boolean is_dec) {
        // Symmetric encryption
        String cipher_name;
        switch (cryptoBackend) {
            case ECDH_AES:
                cipher_name = "aes128";
                break;
            case ECDH_CHASKEY:
                cipher_name = "chaskey";
                break;
            default:
                throw new RuntimeException();
        }

        Wire k = sharedKeys.get(getQualifiedName(other_pk));
        String desc =  ADD_OP_LABELS ? String.format("enc%s(%s, k, iv)", is_dec ? "[dec]" : "", plain) : "";
        Wire[] m = getArr(plain);
        Wire iv = extractIv(getArr(iv_cipher));
        ZkayCBCSymmetricEncGadget crypto = new ZkayCBCSymmetricEncGadget(m, k, iv, cipher_name, desc);
        return crypto.getOutputWires();
    }

    private void addGuardedEncryptionAssertion(String expected_cipher, Wire[] computed_cipher) {
        Wire[] exp_cipher = getArr(expected_cipher);
        String comp_str = ADD_OP_LABELS ? String.format("%s == cipher", getQualifiedName(expected_cipher)) : "";
        addGuardedOneAssertion(isEqual(exp_cipher, expected_cipher, computed_cipher, "cipher"), comp_str);
    }

    private void addGuardedNonZeroAssertion(Wire[] value, String name) {
        addGuardedOneAssertion(isNonZero(value, name), String.format("assert %s != 0", getQualifiedName(name)));
    }


    /**
     * Asymmetric Encryption
     */
    protected void checkEnc(String plain, String key, String rnd, String expected_cipher) {
        // 1. Check that expected cipher != 0 (since 0 is reserved for default initialization)
        addGuardedNonZeroAssertion(getArr(expected_cipher), expected_cipher);

        // 2. Encrypt
        Wire[] computed_cipher = cryptoEnc(plain, key, rnd, false);

        // 3. Check encryption == expected cipher
        addGuardedEncryptionAssertion(expected_cipher, computed_cipher);
    }

    /**
     * Symmetric Encryption
     */
    protected void checkEnc(String plain, String other_pk, String iv_cipher) {
        // 1. Check that expected cipher != 0 (since 0 is reserved for default initialization)
        addGuardedNonZeroAssertion(getArr(iv_cipher), iv_cipher);

        // 2. Encrypt
        Wire[] computed_cipher = cryptoSymmEnc(plain, other_pk, iv_cipher, false);

        // 3. Check encryption == expected cipher
        addGuardedEncryptionAssertion(iv_cipher, computed_cipher);
    }

    /**
     * Asymmetric Decryption
     */
    protected void checkDec(String plain, String key, String rnd, String expected_cipher) {
        // 1. Decrypt [dec(cipher, rnd, sk) -> enc(plain, rnd, pk)] (compute inverse op)
        Wire[] computed_cipher = cryptoEnc(plain, key, rnd, true);

        Wire[] exp_cipher = getArr(expected_cipher);
        Wire exp_cipher_is_nonzero = isNonZero(exp_cipher, expected_cipher); // "!= 0"
        Wire exp_cipher_is_zero = exp_cipher_is_nonzero.invAsBit(expected_cipher + " == 0");
        Wire plain_zero = isZero(getArr(plain), plain);
        Wire rnd_zero = isZero(getArr(rnd), rnd);

        // 2. Check that: expected_cipher == 0 => plain == 0 && rnd == 0
        addGuardedOneAssertion(exp_cipher_is_nonzero.or(plain_zero.and(rnd_zero)));

        // 3. Check that expected_cipher != 0 => expected_cipher == computed_cipher
        addGuardedOneAssertion(exp_cipher_is_zero.or(isEqual(exp_cipher, expected_cipher, computed_cipher, "cipher")));
    }

    /**
     * Symmetric Decryption
     */
    protected void checkDec(String plain, String other_pk, String iv_cipher) {
        // 1. Decrypt [dec(cipher, rnd, sk) -> encSymm(plain, ecdh(my_sk, other_pk), iv)] (compute inverse op)
        Wire[] computed_cipher = cryptoSymmEnc(plain, other_pk, iv_cipher, true);

        Wire[] exp_iv_cipher = getArr(iv_cipher);
        Wire exp_cipher_non_zero = isNonZero(exp_iv_cipher, iv_cipher);
        Wire exp_cipher_zero = exp_cipher_non_zero.invAsBit(iv_cipher + " == 0");
        Wire other_pk_non_zero = get(other_pk).wire.checkNonZero(other_pk + "!= 0");
        Wire other_pk_zero = other_pk_non_zero.invAsBit(other_pk + " == 0");
        Wire plain_zero = isZero(getArr(plain), plain);

        // Some of these checks are probably not necessary, as zkay should already enforce that
        // other_pk == 0 <=> exp_cipher == 0

        // 2. Check that: iv_cipher == 0 => plain == 0 && other_pk == 0
        addGuardedOneAssertion(exp_cipher_non_zero.or(plain_zero.and(other_pk_zero)),
                ADD_OP_LABELS ? String.format("%s == 0 => %s == 0 && %s == 0", iv_cipher, plain, other_pk) : "");

        // 3. Check that: other_pk == 0 => plain == 0 && iv_cipher == 0
        addGuardedOneAssertion(other_pk_non_zero.or(plain_zero.and(exp_cipher_zero)),
                ADD_OP_LABELS ? String.format("%s == 0 => %s == 0 && %s == 0", other_pk, plain, iv_cipher) : "");

        // 4. Check that: (iv_cipher != 0 && other_pk != 0) => iv_cipher == computed_cipher
        Wire cipher_zero_or_pk_zero = exp_cipher_zero.or(other_pk_zero);
        addGuardedOneAssertion(cipher_zero_or_pk_zero.or(isEqual(exp_iv_cipher, iv_cipher, computed_cipher, "cipher")),
                ADD_OP_LABELS ? String.format("(%s != 0 && %s != 0) => %s == %s", iv_cipher, other_pk, iv_cipher, "cipher") : "");
    }

    protected void checkEq(String lhs, String rhs) {
        Wire[] l = getArr(lhs), r = getArr(rhs);
        int len = l.length;
        if (r.length != len) {
            throw new RuntimeException("Size mismatch for equality check");
        }
        for (int i = 0; i < len; ++i) {
            String comp_str = ADD_OP_LABELS ? String.format("%s[%d] == %s[%d]", getQualifiedName(lhs), i, getQualifiedName(rhs), i) : "";
            addGuardedEqualityAssertion(l[i], r[i], comp_str);
        }
    }

    private Wire isNonZero(Wire[] value, String name) {
        Wire res = value[0].checkNonZero(name + "[0] != 0");
        for (int i = 1; i < value.length; ++i) {
            res = res.add(value[i].checkNonZero(String.format("%s[%d] != 0", name, i)), String.format("or %s[%d] != 0", name, i));
        }
        return res.checkNonZero(name + " != 0");
    }
    private Wire isZero(Wire[] value, String name) {
        return isNonZero(value, name).invAsBit(name + " == 0");
    }
    private Wire isEqual(Wire[] wires1, String name1, Wire[] wires2, String name2) {
        if (wires1.length != wires2.length) {
            throw new IllegalArgumentException("Wire array size mismatch");
        }
        Wire res = getOneWire();
        for (int i = 0; i < wires1.length; ++i) {
            res = res.and(wires1[i].isEqualTo(wires2[i], String.format("%s[%d] == %s[%d]", name1, i, name2, i)));
        }
        return res;
    }

    private void clear_prefix(Stack<String> prefix, Map<String, Integer> indices) {
        prefix.clear();
        prefix.push("");
        indices.clear();
    }

    private void push_prefix(Stack<String> prefix, Map<String, Integer> prefix_indices, String new_str) {
        String new_prefix = prefix.peek() + new_str + ".";
        int count = prefix_indices.getOrDefault(new_prefix, 0);
        prefix_indices.put(new_prefix, count + 1);
        prefix.push(new_prefix + count + ".");
    }

    private void pop_prefix(Stack<String> prefix) {
        prefix.pop();
    }

    private String getQualifiedName(String name) {
        if (name.startsWith("glob_")) {
            return name;
        } else {
            return name_prefix.peek() + name;
        }
    }

    private void addGuardedEqualityAssertion(Wire lhs, Wire rhs, String... desc) {
        if (current_guard_condition.empty()) {
            addEqualityAssertion(lhs, rhs, desc);
        } else {
            Wire eq = lhs.isEqualTo(rhs);
            addOneAssertion(current_guard_condition.peek().wire.invAsBit().or(eq), desc); // guard => lhs == rhs
        }
    }
    private void addGuardedOneAssertion(Wire val, String... desc) {
        if (current_guard_condition.empty()) {
            addOneAssertion(val, desc);
        } else {
            addOneAssertion(current_guard_condition.peek().wire.invAsBit().or(val), desc); // guard => val
        }
    }

    private Wire[] getArr(String name) {
        name = getQualifiedName(name);
        TypedWire[] w = vars.get(name);
        if (w == null) {
            throw new RuntimeException("Variable " + name + " is not associated with a wire");
        }
        Wire[] wa = new Wire[w.length];
        for (int i = 0; i < w.length; ++i) {
            wa[i] = w[i].wire;
        }
        return wa;
    }

    private LongElement getKey(String name) {
        name = getQualifiedName(name);
        LongElement key = keys.get(name);
        if (key == null) {
            throw new RuntimeException("Key variable " + name + " is not associated with a LongElement");
        }
        return key;
    }

    private void set(String name, TypedWire val) {
        set(name, new TypedWire[]{val});
    }
    private void set(String name, TypedWire[] val) {
        name = getQualifiedName(name);
        if (val == null) {
            throw new RuntimeException("Tried to set value " + name + " to null");
        }
        TypedWire[] old_val = vars.get(name);
        if (old_val != null) {
            throw new RuntimeException("SSA violation when trying to write to " + name);
        }
        vars.put(name, val);
    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {
        if (serialized_arguments == null) {
            throw new RuntimeException("No inputs specified, this should not have been called");
        }
        if (serialized_arguments.length != all_pub_io_wires.length + all_priv_in_wires.length) {
            throw new RuntimeException("Invalid serialized argument count, expected " + all_pub_io_wires.length + " was " + serialized_arguments.length);
        }

        int idx = 0;
        for (List<String> io_name_list : Arrays.asList(pub_in_names, pub_out_names, priv_in_names)) {
            for (String name : io_name_list) {
                TypedWire[] wires = vars.get(name);
                StringBuilder sb = new StringBuilder("Setting '" + name + "' to [");
                for (TypedWire w : wires) {
                    BigInteger val = serialized_arguments[idx++];
                    evaluator.setWireValue(w.wire, val);
                    sb.append("wid ").append(w.wire.getWireId()).append("=").append(val).append(", ");
                }
                sb.setLength(sb.length() - 2);
                sb.append("]");
                System.out.println(sb.toString());
            }
        }

        if (idx != all_pub_io_wires.length + all_priv_in_wires.length) {
            throw new RuntimeException("Not all inputs consumed");
        }
    }

    @Override
    public void prepFiles() {
        if (serialized_arguments != null) {
            super.prepFiles();
        } else {
            writeCircuitFile();
            writeDummyInputFile();
        }
    }

    private void writeDummyInputFile() {
        try {
            PrintWriter printWriter = new PrintWriter(new BufferedWriter(new FileWriter(getName() + ".in")));
            printWriter.println("0 1");
            List<Wire> all_io_wires = new ArrayList<>(getInWires().size() + getOutWires().size() + getProverWitnessWires().size());
            all_io_wires.addAll(getInWires().subList(1, getInWires().size()));
            all_io_wires.addAll(getOutWires());
            all_io_wires.addAll(getProverWitnessWires());
            for (Wire w : all_io_wires) {
                printWriter.println(w.getWireId() + " " + "0");
            }
            printWriter.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
