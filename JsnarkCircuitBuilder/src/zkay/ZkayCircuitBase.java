/*******************************************************************************
 * core zkay jsnark abstraction layer
 * (in the form of CircuitGenerator subclass)
 * Author: Nick Baumann
 *******************************************************************************/
package zkay;

import circuit.eval.CircuitEvaluator;
import circuit.operations.Gadget;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import zkay.crypto.CryptoBackend;
import zkay.crypto.HomomorphicBackend;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.*;

import static zkay.ZkayType.ZkBool;
import static zkay.ZkayType.ZkUint;
import static zkay.ZkayType.checkType;

public abstract class ZkayCircuitBase extends CircuitGenerator {

    /**
     * Whether to include comments for the more complex operations in the circuit.arith file
     */
    private static final boolean ADD_OP_LABELS = true;
    private static final Object LEGACY_CRYPTO_BACKEND = new Object();

    protected final String realCircuitName;

    private final Map<Object, CryptoBackend> cryptoBackends = new HashMap<>();

    private int currentPubInIdx = 0;
    private int currentPubOutIdx;
    private final Wire[] allPubIOWires;

    private int currentPrivInIdx = 0;
    private final Wire[] allPrivInWires;

    private final List<String> pubInNames = new ArrayList<>();
    private final List<String> pubOutNames = new ArrayList<>();
    private final List<String> privInNames = new ArrayList<>();

    private final int pubInCount;
    private final boolean useInputHashing;

    private final Map<String, TypedWire[]> vars = new HashMap<>();

    private final Deque<TypedWire> currentGuardCondition = new ArrayDeque<>();
    private BigInteger[] serializedArguments = null;

    private final Map<String, Integer> namePrefixIndices = new HashMap<>();
    private final Deque<String> namePrefix = new ArrayDeque<>();

    private final Deque<Deque<String>> guardPrefixes = new ArrayDeque<>();
    private final Deque<Map<String, Integer>> guardPrefixIndices = new ArrayDeque<>();

    @Deprecated
    public ZkayCircuitBase(String name, String cryptoBackend, int keyBits, int pubInSize, int pubOutSize, int privSize, boolean useInputHashing) {
        this(name, pubInSize, pubOutSize, privSize, useInputHashing);

        // Legacy handling: add default "main" crypto backend
        this.cryptoBackends.put(LEGACY_CRYPTO_BACKEND, CryptoBackend.create(cryptoBackend, keyBits));
    }

    public ZkayCircuitBase(String name, int pubInSize, int pubOutSize, int privSize, boolean useInputHashing) {
        super("circuit");
        this.realCircuitName = name;

        this.pubInCount = pubInSize;
        this.currentPubOutIdx = pubInSize;
        this.allPubIOWires = new Wire[pubInSize + pubOutSize];
        this.allPrivInWires = new Wire[privSize];

        this.useInputHashing = useInputHashing;

        clearPrefix(this.namePrefix, this.namePrefixIndices);
        pushGuardPrefix(this.guardPrefixes, this.guardPrefixIndices);
    }

    public void run(String[] args) {
        switch (args[0]) {
            case "compile":
                compileCircuit();
                break;
            case "prove":
                compileCircuit();
                parseInputs(Arrays.asList(args).subList(1, args.length));
                System.out.println("Evaluating circuit '" + realCircuitName + "'");
                evalCircuit();
                break;
            default:
                throw new RuntimeException("invalid command");
        }
        prepFiles();
    }

    private void parseInputs(List<String> args) {
        int totCount = allPubIOWires.length + allPrivInWires.length;
        if (args.size() != totCount) {
            throw new IllegalArgumentException("Input count mismatch, expected " + totCount + ", was " + args.size());
        }
        serializedArguments = new BigInteger[totCount];
        for (int i = 0; i < totCount; ++i) {
            BigInteger v = new BigInteger(args.get(i), 16);
            if (v.signum() == -1) {
                throw new IllegalArgumentException("No signed inputs (signed must be converted to unsigned beforehand)");
            }
            serializedArguments[i] = v;
        }
    }

    private void compileCircuit() {
        System.out.println("Compiling circuit '" + realCircuitName + "'");
        generateCircuit();
        if (currentPubInIdx != pubInCount || currentPubOutIdx != allPubIOWires.length) {
            throw new RuntimeException("Not all public inputs assigned");
        }
        if (currentPrivInIdx != allPrivInWires.length) {
            throw new RuntimeException("Not all private inputs assigned");
        }
        if (useInputHashing) {
            makeOutputArray(new ZkaySHA256Gadget(allPubIOWires, 253).getOutputWires(), "digest");
        }
        System.out.println("Done with generateCircuit, preparing dummy files...");
    }

    @Override
    protected void buildCircuit() {
        // Create IO wires
        int pubOutCount = allPubIOWires.length - pubInCount;
        final Wire[] inArray, outArray, privInArray;
        if (useInputHashing) {
            inArray = createProverWitnessWireArray(pubInCount, "in_");
            outArray = createProverWitnessWireArray(pubOutCount, "out_");
        } else {
            inArray = createInputWireArray(pubInCount, "in_");
            outArray = createInputWireArray(pubOutCount, "out_");
        }
        privInArray = createProverWitnessWireArray(allPrivInWires.length, "priv_");

        // Legacy handling
        CryptoBackend legacyCryptoBackend = cryptoBackends.get(LEGACY_CRYPTO_BACKEND);
        if (legacyCryptoBackend != null && legacyCryptoBackend.isSymmetric()) {
            Wire myPk = inArray[0];
            Wire mySk = privInArray[0];
            setKeyPair(LEGACY_CRYPTO_BACKEND, myPk, mySk);
        }

        System.arraycopy(inArray, 0, allPubIOWires, 0, pubInCount);
        System.arraycopy(outArray, 0, allPubIOWires, pubInCount, pubOutCount);
        System.arraycopy(privInArray, 0, allPrivInWires, 0, allPrivInWires.length);
    }

    private Wire[] addIO(String typeName, String name, List<String> nameList, Wire[] src, int startIdx, int size, ZkayType t, boolean restrict) {
        name = getQualifiedName(name);
        System.out.println("Adding '" + name + "' = " + typeName + "[" + startIdx + ":" + (startIdx + size) + "]");
        Wire[] input = Arrays.copyOfRange(src, startIdx, startIdx + size);
        TypedWire[] tInput = new TypedWire[input.length];
        for (int i = 0; i < input.length; ++i) {
            // Enforce size and associate wire with type (technically restrict is only required for private inputs)
            tInput[i] = new TypedWire(input[i], t, name, restrict);
        }
        vars.put(name, tInput);
        nameList.add(name);
        return input;
    }

    /* CRYPTO BACKENDS */

    protected void addCryptoBackend(Object cryptoBackendId, String cryptoBackendName, int keyBits) {
        if (this.cryptoBackends.containsKey(cryptoBackendId)) {
            throw new IllegalStateException("Crypto backend " + cryptoBackendId + " already registered");
        }
        this.cryptoBackends.put(cryptoBackendId, CryptoBackend.create(cryptoBackendName, keyBits));
    }

    protected void setKeyPair(Object cryptoBackendId, String pkName, String skName) {
        setKeyPair(cryptoBackendId, get(pkName).wire, get(skName).wire);
    }

    private void setKeyPair(Object cryptoBackendId, Wire myPk, Wire mySk) {
        CryptoBackend cryptoBackend = getCryptoBackend(cryptoBackendId);
        if (!cryptoBackend.isSymmetric()) {
            throw new IllegalArgumentException("Crypto backend is not symmetric");
        }

        CryptoBackend.Symmetric symmetricCrypto = (CryptoBackend.Symmetric) cryptoBackend;
        symmetricCrypto.setKeyPair(myPk, mySk);
    }

    private CryptoBackend getCryptoBackend(Object cryptoBackendId) {
        CryptoBackend backend = cryptoBackends.get(cryptoBackendId);
        if (backend == null) {
            throw new IllegalArgumentException("Unknown crypto backend: " + cryptoBackendId);
        }
        return backend;
    }

    private HomomorphicBackend getHomomorphicCryptoBackend(Object cryptoBackendId) {
        CryptoBackend cryptoBackend = getCryptoBackend(cryptoBackendId);
        if (cryptoBackend instanceof HomomorphicBackend) {
            return (HomomorphicBackend) cryptoBackend;
        } else {
            throw new IllegalArgumentException("Crypto backend " + cryptoBackendId + " is not homomorphic");
        }
    }

    /* CIRCUIT IO */

    protected void addIn(String name, int size, ZkayType t) {
        addIO("in", name, pubInNames, allPubIOWires, currentPubInIdx, size, t, false);
        currentPubInIdx += size;
    }

    protected void addK(Object cryptoBackendId, String name, int size) {
        CryptoBackend cryptoBackend = getCryptoBackend(cryptoBackendId);
        int chunkSize = cryptoBackend.getKeyChunkSize();
        Wire[] input = addIO("in", name, pubInNames, allPubIOWires, currentPubInIdx, size, ZkUint(chunkSize), false);
        currentPubInIdx += size;
        cryptoBackend.addKey(getQualifiedName(name), input);
    }

    @Deprecated
    protected void addK(String name, int size) {
        addK(LEGACY_CRYPTO_BACKEND, name, size);
    }

    protected void addOut(String name, int size, ZkayType t) {
        addIO("out", name, pubOutNames, allPubIOWires, currentPubOutIdx, size, t, false);
        currentPubOutIdx += size;
    }

    protected void addS(String name, int size, ZkayType t) {
        addIO("priv", name, privInNames, allPrivInWires, currentPrivInIdx, size, t, true);
        currentPrivInIdx += size;
    }

    /* CONTROL FLOW */

    protected void stepIn(String fct) {
        pushPrefix(namePrefix, namePrefixIndices, guardPrefixes.element().element() + fct);
        pushGuardPrefix(guardPrefixes, guardPrefixIndices);
    }

    protected void stepOut() {
        popPrefix(namePrefix);
        guardPrefixes.pop();
        guardPrefixIndices.pop();
    }

    protected void addGuard(String name, boolean isTrue) {
        Wire newWire = get(name).wire;

        pushPrefix(guardPrefixes.element(), guardPrefixIndices.element(), name + "_" + isTrue);

        if (!isTrue) {
            newWire = newWire.invAsBit();
        }

        if (!currentGuardCondition.isEmpty()) {
            newWire = currentGuardCondition.element().wire.and(newWire);
        }
        currentGuardCondition.push(new TypedWire(newWire, ZkBool, "guard_cond_top_" + name + "_" + isTrue));
    }

    protected void popGuard() {
        currentGuardCondition.pop();
        popPrefix(guardPrefixes.element());
    }

    protected TypedWire ite(TypedWire condition, TypedWire trueVal, TypedWire falseVal) {
        checkType(ZkBool, condition.type);
        checkType(trueVal.type, falseVal.type);
        return new TypedWire(condExpr(condition.wire, trueVal.wire, falseVal.wire), trueVal.type,
                String.format("%s ? %s : %s", condition.name, trueVal.name, falseVal.name));
    }

    /* UNARY OPS */

    public static TypedWire negate(TypedWire val) {
        int bits = val.type.bitwidth;
        if (bits < 256) {
            // Take two's complement
            TypedWire invBits = new TypedWire(val.wire.invBits(val.type.bitwidth), val.type, "~" + val.name);
            return invBits.plus(((ZkayCircuitBase) getActiveCircuitGenerator()).val(1, val.type));
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

    /* String op interface */

    public static TypedWire o_(char op, TypedWire wire) {
        switch (op) {
            case '-':
                return negate(wire);
            case '~':
                return bitInv(wire);
            case '!':
                return not(wire);
            default:
                throw new IllegalArgumentException();
        }
    }

    public static TypedWire o_(TypedWire lhs, char op, TypedWire rhs) {
        switch (op) {
            case '+':
                return lhs.plus(rhs);
            case '-':
                return lhs.minus(rhs);
            case '*':
                return lhs.times(rhs);
            case '|':
                return lhs.bitOr(rhs);
            case '&':
                return lhs.bitAnd(rhs);
            case '^':
                return lhs.bitXor(rhs);
            case '<':
                return lhs.isLessThan(rhs);
            case '>':
                return lhs.isGreaterThan(rhs);
            default:
                throw new IllegalArgumentException();
        }
    }

    public TypedWire o_(TypedWire cond, char condChar, TypedWire trueVal, char altChar, TypedWire falseVal) {
        if (condChar != '?' || altChar != ':') throw new IllegalArgumentException();
        return ite(cond, trueVal, falseVal);
    }

    public static TypedWire o_(TypedWire lhs, String op, int rhs) {
        switch (op) {
            case "<<":
                return lhs.shiftLeftBy(rhs);
            case ">>":
                return lhs.shiftRightBy(rhs);
            default:
                throw new IllegalArgumentException();
        }
    }

    public static TypedWire o_(TypedWire lhs, String op, TypedWire rhs) {
        switch (op) {
            case "==":
                return lhs.isEqualTo(rhs);
            case "!=":
                return lhs.isNotEqualTo(rhs);
            case "<=":
                return lhs.isLessThanOrEqual(rhs);
            case ">=":
                return lhs.isGreaterThanOrEqual(rhs);
            case "&&":
                return lhs.and(rhs);
            case "||":
                return lhs.or(rhs);
            default:
                throw new IllegalArgumentException();
        }
    }

    /* Homomorphic operations */

    public TypedWire[] o_hom(String cryptoBackendId, String key, char op, HomomorphicInput arg) {
        HomomorphicBackend backend = getHomomorphicCryptoBackend(cryptoBackendId);
        return backend.doHomomorphicOp(op, arg, getQualifiedName(key));
    }

    public TypedWire[] o_hom(String cryptoBackendId, String key, HomomorphicInput lhs, char op, HomomorphicInput rhs) {
        HomomorphicBackend backend = getHomomorphicCryptoBackend(cryptoBackendId);
        return backend.doHomomorphicOp(lhs, op, rhs, getQualifiedName(key));
    }

    public TypedWire[] o_hom(String cryptoBackendId, String key, HomomorphicInput cond, char condChar,
                             HomomorphicInput trueVal, char altChar, HomomorphicInput falseVal) {
        if (condChar != '?' || altChar != ':') throw new IllegalArgumentException();
        HomomorphicBackend backend = getHomomorphicCryptoBackend(cryptoBackendId);
        return backend.doHomomorphicCond(cond, trueVal, falseVal, getQualifiedName(key));
    }

    public TypedWire[] o_hom(String cryptoBackendId, String key, HomomorphicInput lhs, String op, HomomorphicInput rhs) {
        HomomorphicBackend backend = getHomomorphicCryptoBackend(cryptoBackendId);
        return backend.doHomomorphicOp(lhs, op, rhs, getQualifiedName(key));
    }

    /* TYPE CASTING */

    protected TypedWire cast(TypedWire w, ZkayType targetType) {
        return convertTo(w, targetType);
    }

    /* SOURCE */

    protected TypedWire get(String name) {
        TypedWire[] w = getTypedArr(name);
        if (w.length != 1) {
            throw new RuntimeException("Tried to treat array as a single wire");
        }
        return w[0];
    }

    protected TypedWire[] getCipher(String name) {
        return getTypedArr(name);
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
                BigInteger vNeg = ZkayType.GetNegativeConstant(v.negate(), t.bitwidth);
                if (vNeg.signum() == -1) {
                    throw new RuntimeException("Constant is still negative");
                }
                w = createConstantWire(vNeg, "const_" + v.toString(10));
            } else {
                throw new IllegalArgumentException("Cannot store negative constant in unsigned wire");
            }
        } else {
            w = createConstantWire(v, "const_" + v.toString(10));
        }
        return new TypedWire(w, t, "const_" + v.toString(10));
    }

    /* SINK */

    protected void decl(String lhs, TypedWire val) {
        if (val.type == null) throw new IllegalArgumentException("Tried to use untyped wires");

        // Get old value and check type
        TypedWire oldVal;
        if (vars.containsKey(lhs)) {
            oldVal = get(lhs);
            checkType(oldVal.type, val.type);
        } else {
            oldVal = val(0, val.type);
        }

        // Only assign value if guard condition is met
        if (currentGuardCondition.isEmpty()) {
            set(lhs, new TypedWire(val.wire, val.type, lhs));
        } else {
            set(lhs, new TypedWire(condExpr(currentGuardCondition.element().wire, val.wire, oldVal.wire), val.type, lhs));
        }
    }

    protected void decl(String lhs, TypedWire[] val) {
        if (val == null || val.length == 0) throw new IllegalArgumentException("val");
        if (val[0].type == null) throw new IllegalArgumentException("Tried to use untyped wires");
        // Check that all types match; else this gets really strange
        for (int i = 0; i < val.length - 1; ++i) {
            checkType(val[i].type, val[i + 1].type);
        }

        // Get old value and check type and length
        TypedWire[] oldVal;
        if (vars.containsKey(lhs)) {
            oldVal = getTypedArr(lhs);
            checkType(oldVal[0].type, val[0].type);
            if (val.length != oldVal.length) {
                throw new IllegalArgumentException("Wire amounts differ - old = " + oldVal.length + ", new = " + val.length);
            }
        } else {
            oldVal = new TypedWire[val.length];
            Arrays.fill(oldVal, val(0, val[0].type));
        }

        // Only assign value if guard condition is met
        TypedWire[] resVal = new TypedWire[val.length];
        TypedWire guard = currentGuardCondition.peek(); // Null if empty
        for (int i = 0; i < val.length; ++i) {
            if (guard == null) {
                resVal[i] = new TypedWire(val[i].wire, val[i].type, lhs); // No guard, just rename
            } else {
                resVal[i] = new TypedWire(condExpr(guard.wire, val[i].wire, oldVal[i].wire), val[i].type, lhs);
            }
        }
        set(lhs, resVal);
    }

    private Wire condExpr(Wire cond, Wire trueVal, Wire falseVal) {
        if (ZkayUtil.ZKAY_RESTRICT_EVERYTHING) {
            addBinaryAssertion(cond);
        }
        return cond.mul(trueVal, "ite_true").add(cond.invAsBit().mul(falseVal, "ite_false"), "ite_res");
    }

    private TypedWire convertTo(TypedWire w, ZkayType targetType) {
        ZkayType fromType = w.type;

        final int fromBitWidth = fromType.bitwidth;
        final boolean wasSigned = fromType.signed;
        final int toBitWidth = targetType.bitwidth;

        Wire newWire;
        if (fromBitWidth < toBitWidth) {
            // Upcast -> sign/zero extend
            if (!wasSigned && w.wire.getBitWiresIfExistAlready() == null) {
                // If this wire was not yet split we can return it without splitting as an optimization
                // -> upcasts from an unsigned type (most common case) are for free this way
                newWire = w.wire;
            } else {
                WireArray bitWires = w.wire.getBitWires(fromBitWidth);
                if (wasSigned && toBitWidth == 256) {
                    // Special case -> sign extension not possible since not enough bits,
                    // want -1 to be field_prime - 1
                    Wire signBit = bitWires.get(fromBitWidth - 1);
                    newWire = signBit.mux(negate(w).wire.mul(-1), w.wire);
                } else {
                    Wire extendBit = wasSigned ? bitWires.get(fromBitWidth - 1) : getZeroWire();
                    Wire[] newWs = new Wire[toBitWidth];
                    System.arraycopy(bitWires.asArray(), 0, newWs, 0, fromBitWidth);
                    for (int i = fromBitWidth; i < toBitWidth; i++) {
                        newWs[i] = extendBit;
                    }
                    newWire = new WireArray(newWs).packAsBits(toBitWidth);
                }
            }
        } else if (fromBitWidth > toBitWidth) {
            // Downcast -> only keep lower bits
            newWire = w.wire.getBitWires(fromBitWidth, "downcast1 " + w.name).packAsBits(toBitWidth, "downcast2 " + w.name);
        } else {
            // Type stays the same -> no expensive bitwise operations necessary
            newWire = w.wire;
        }
        return new TypedWire(newWire, targetType, String.format("(%s) %s", targetType, w.name));
    }

    private Wire[] cryptoEnc(CryptoBackend cryptoBackend, String plain, String key, String rnd, boolean isDec) {
        if (cryptoBackend.isSymmetric()) {
            throw new IllegalArgumentException("Crypto backend is not asymmetric");
        }

        String desc = ADD_OP_LABELS ? String.format("enc%s(%s, %s, %s)", isDec ? "[dec]" : "",
                getQualifiedName(plain), getQualifiedName(key), getQualifiedName(rnd)) : "";
        Gadget enc = cryptoBackend.createEncryptionGadget(get(plain), getQualifiedName(key), getArr(rnd), desc);
        return enc.getOutputWires();
    }

    private Wire[] cryptoSymmEnc(CryptoBackend cryptoBackend, String plain, String otherPk, String ivCipher, boolean isDec) {
        if (!cryptoBackend.isSymmetric()) {
            throw new IllegalArgumentException("Crypto backend is not symmetric");
        }

        String desc = ADD_OP_LABELS ? String.format("enc%s(%s, k, iv)", isDec ? "[dec]" : "", plain) : "";
        Gadget enc = cryptoBackend.createEncryptionGadget(get(plain), getQualifiedName(otherPk), getArr(ivCipher), desc);
        return enc.getOutputWires();
    }

    private void addGuardedEncryptionAssertion(String expectedCipher, Wire[] computedCipher) {
        Wire[] expCipher = getArr(expectedCipher);
        String compStr = ADD_OP_LABELS ? String.format("%s == cipher", getQualifiedName(expectedCipher)) : "";
        addGuardedOneAssertion(isEqual(expCipher, expectedCipher, computedCipher, "cipher"), compStr);
    }

    private void addGuardedNonZeroAssertion(Wire[] value, String name) {
        addGuardedOneAssertion(isNonZero(value, name), String.format("assert %s != 0", getQualifiedName(name)));
    }

    /**
     * Asymmetric Encryption
     */
    protected void checkEnc(Object cryptoBackendId, String plain, String key, String rnd, String expectedCipher) {
        CryptoBackend cryptoBackend = getCryptoBackend(cryptoBackendId);

        // 1. Check that expected cipher != 0 (since 0 is reserved for default initialization)
        addGuardedNonZeroAssertion(getArr(expectedCipher), expectedCipher);

        // 2. Encrypt
        Wire[] computedCipher = cryptoEnc(cryptoBackend, plain, key, rnd, false);

        // 3. Check encryption == expected cipher
        addGuardedEncryptionAssertion(expectedCipher, computedCipher);
    }

    /**
     * Symmetric Encryption
     */
    protected void checkSymmEnc(Object cryptoBackendId, String plain, String otherPk, String ivCipher) {
        CryptoBackend cryptoBackend = getCryptoBackend(cryptoBackendId);

        // 1. Check that expected cipher != 0 (since 0 is reserved for default initialization)
        addGuardedNonZeroAssertion(getArr(ivCipher), ivCipher);

        // 2. Encrypt
        Wire[] computedCipher = cryptoSymmEnc(cryptoBackend, plain, otherPk, ivCipher, false);

        // 3. Check encryption == expected cipher
        addGuardedEncryptionAssertion(ivCipher, computedCipher);
    }

    /**
     * Asymmetric Decryption
     */
    protected void checkDec(Object cryptoBackendId, String plain, String key, String rnd, String expectedCipher) {
        CryptoBackend cryptoBackend = getCryptoBackend(cryptoBackendId);

        // 1. Decrypt [dec(cipher, rnd, sk) -> enc(plain, rnd, pk)] (compute inverse op)
        Wire[] computedCipher = cryptoEnc(cryptoBackend, plain, key, rnd, true);

        Wire[] expCipher = getArr(expectedCipher);
        Wire expCipherIsNonZero = isNonZero(expCipher, expectedCipher); // "!= 0"
        Wire expCipherIsZero = expCipherIsNonZero.invAsBit(expectedCipher + " == 0");
        Wire plainZero = isZero(getArr(plain), plain);
        Wire rndZero = isZero(getArr(rnd), rnd);

        // 2. Check that: expectedCipher == 0 => plain == 0 && rnd == 0
        addGuardedOneAssertion(expCipherIsNonZero.or(plainZero.and(rndZero)));

        // 3. Check that expectedCipher != 0 => expectedCipher == computedCipher
        addGuardedOneAssertion(expCipherIsZero.or(isEqual(expCipher, expectedCipher, computedCipher, "cipher")));
    }

    /**
     * Symmetric Decryption
     */
    protected void checkSymmDec(Object cryptoBackendId, String plain, String otherPk, String ivCipher) {
        CryptoBackend cryptoBackend = getCryptoBackend(cryptoBackendId);

        // 1. Decrypt [dec(cipher, rnd, sk) -> encSymm(plain, ecdh(mySk, otherPk), iv)] (compute inverse op)
        Wire[] computedCipher = cryptoSymmEnc(cryptoBackend, plain, otherPk, ivCipher, true);

        Wire[] expIvCipher = getArr(ivCipher);
        Wire expCipherNonZero = isNonZero(expIvCipher, ivCipher);
        Wire expCipherZero = expCipherNonZero.invAsBit(ivCipher + " == 0");
        Wire otherPkNonZero = get(otherPk).wire.checkNonZero(otherPk + "!= 0");
        Wire otherPkZero = otherPkNonZero.invAsBit(otherPk + " == 0");
        Wire plainZero = isZero(getArr(plain), plain);

        // Some of these checks are probably not necessary, as zkay should already enforce that
        // otherPk == 0 <=> expCipher == 0

        // 2. Check that: ivCipher == 0 => plain == 0 && otherPk == 0
        addGuardedOneAssertion(expCipherNonZero.or(plainZero.and(otherPkZero)),
                ADD_OP_LABELS ? String.format("%s == 0 => %s == 0 && %s == 0", ivCipher, plain, otherPk) : "");

        // 3. Check that: otherPk == 0 => plain == 0 && ivCipher == 0
        addGuardedOneAssertion(otherPkNonZero.or(plainZero.and(expCipherZero)),
                ADD_OP_LABELS ? String.format("%s == 0 => %s == 0 && %s == 0", otherPk, plain, ivCipher) : "");

        // 4. Check that: (ivCipher != 0 && otherPk != 0) => ivCipher == computedCipher
        Wire cipherZeroOrPkZero = expCipherZero.or(otherPkZero);
        addGuardedOneAssertion(cipherZeroOrPkZero.or(isEqual(expIvCipher, ivCipher, computedCipher, "cipher")),
                ADD_OP_LABELS ? String.format("(%s != 0 && %s != 0) => %s == %s", ivCipher, otherPk, ivCipher, "cipher") : "");
    }

    // Legacy handling

    @Deprecated
    protected void checkEnc(String plain, String key, String rnd, String expectedCipher) {
        checkEnc(LEGACY_CRYPTO_BACKEND, plain, key, rnd, expectedCipher);
    }

    @Deprecated
    protected void checkEnc(String plain, String otherPk, String ivCipher) {
        checkSymmEnc(LEGACY_CRYPTO_BACKEND, plain, otherPk, ivCipher);
    }

    @Deprecated
    protected void checkDec(String plain, String key, String rnd, String expectedCipher) {
        checkDec(LEGACY_CRYPTO_BACKEND, plain, key, rnd, expectedCipher);
    }

    @Deprecated
    protected void checkDec(String plain, String otherPk, String ivCipher) {
        checkSymmDec(LEGACY_CRYPTO_BACKEND, plain, otherPk, ivCipher);
    }

    protected void checkEq(String lhs, String rhs) {
        Wire[] l = getArr(lhs), r = getArr(rhs);
        int len = l.length;
        if (r.length != len) {
            throw new RuntimeException("Size mismatch for equality check");
        }
        for (int i = 0; i < len; ++i) {
            String compStr = ADD_OP_LABELS ? String.format("%s[%d] == %s[%d]", getQualifiedName(lhs), i, getQualifiedName(rhs), i) : "";
            addGuardedEqualityAssertion(l[i], r[i], compStr);
        }
    }

    private static Wire isNonZero(Wire[] value, String name) {
        Wire res = value[0].checkNonZero(name + "[0] != 0");
        for (int i = 1; i < value.length; ++i) {
            res = res.add(value[i].checkNonZero(String.format("%s[%d] != 0", name, i)), String.format("or %s[%d] != 0", name, i));
        }
        return res.checkNonZero(name + " != 0");
    }

    private static Wire isZero(Wire[] value, String name) {
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

    private static void clearPrefix(Deque<String> prefix, Map<String, Integer> indices) {
        prefix.clear();
        prefix.push("");
        indices.clear();
    }

    private static void pushPrefix(Deque<String> prefix, Map<String, Integer> prefixIndices, String newStr) {
        String newPrefix = prefix.peek() + newStr + ".";
        int count = prefixIndices.getOrDefault(newPrefix, 0);
        prefixIndices.put(newPrefix, count + 1);
        prefix.push(newPrefix + count + ".");
    }

    private static void pushGuardPrefix(Deque<Deque<String>> guardPrefixes, Deque<Map<String, Integer>> guardPrefixIndices) {
        Deque<String> newPrefix = new ArrayDeque<>();
        Map<String, Integer> newPrefixIndices = new HashMap<>();
        clearPrefix(newPrefix, newPrefixIndices);
        guardPrefixes.push(newPrefix);
        guardPrefixIndices.push(newPrefixIndices);
    }

    private static void popPrefix(Deque<String> prefix) {
        prefix.pop();
    }

    private String getQualifiedName(String name) {
        if (name.startsWith("glob_")) {
            return name;
        } else {
            return namePrefix.element() + name;
        }
    }

    private void addGuardedEqualityAssertion(Wire lhs, Wire rhs, String... desc) {
        if (currentGuardCondition.isEmpty()) {
            addEqualityAssertion(lhs, rhs, desc);
        } else {
            Wire eq = lhs.isEqualTo(rhs);
            addOneAssertion(currentGuardCondition.element().wire.invAsBit().or(eq), desc); // guard => lhs == rhs
        }
    }

    private void addGuardedOneAssertion(Wire val, String... desc) {
        if (currentGuardCondition.isEmpty()) {
            addOneAssertion(val, desc);
        } else {
            addOneAssertion(currentGuardCondition.element().wire.invAsBit().or(val), desc); // guard => val
        }
    }

    private TypedWire[] getTypedArr(String name) {
        name = getQualifiedName(name);
        TypedWire[] w = vars.get(name);
        if (w == null) {
            throw new RuntimeException("Variable " + name + " is not associated with a wire");
        }
        return w;
    }

    private Wire[] getArr(String name) {
        TypedWire[] w = getTypedArr(name);
        Wire[] wa = new Wire[w.length];
        for (int i = 0; i < w.length; ++i) {
            wa[i] = w[i].wire;
        }
        return wa;
    }

    private void set(String name, TypedWire val) {
        set(name, new TypedWire[] {val});
    }

    private void set(String name, TypedWire[] val) {
        name = getQualifiedName(name);
        if (val == null) {
            throw new RuntimeException("Tried to set value " + name + " to null");
        }
        TypedWire[] oldVal = vars.get(name);
        if (oldVal != null) {
            throw new RuntimeException("SSA violation when trying to write to " + name);
        }
        vars.put(name, val);
    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {
        if (serializedArguments == null) {
            throw new RuntimeException("No inputs specified, this should not have been called");
        }
        if (serializedArguments.length != allPubIOWires.length + allPrivInWires.length) {
            throw new RuntimeException("Invalid serialized argument count, expected " + allPubIOWires.length + " was " + serializedArguments.length);
        }

        int idx = 0;
        for (List<String> ioNameList : Arrays.asList(pubInNames, pubOutNames, privInNames)) {
            for (String name : ioNameList) {
                TypedWire[] wires = vars.get(name);
                StringBuilder sb = new StringBuilder("Setting '" + name + "' to [");
                for (TypedWire w : wires) {
                    BigInteger val = serializedArguments[idx++];
                    evaluator.setWireValue(w.wire, val);
                    sb.append("wid ").append(w.wire.getWireId()).append("=").append(val).append(", ");
                }
                sb.setLength(sb.length() - 2);
                sb.append("]");
                System.out.println(sb);
            }
        }

        if (idx != allPubIOWires.length + allPrivInWires.length) {
            throw new RuntimeException("Not all inputs consumed");
        }
    }

    @Override
    public void prepFiles() {
        if (serializedArguments != null) {
            super.prepFiles();
        } else {
            writeCircuitFile();
            writeDummyInputFile();
        }
    }

    private void writeDummyInputFile() {
        try (PrintWriter printWriter = new PrintWriter(new BufferedWriter(new FileWriter(getName() + ".in")))) {
            printWriter.println("0 1");
            List<Wire> allIOWires = new ArrayList<>(getInWires().size() + getOutWires().size() + getProverWitnessWires().size());
            allIOWires.addAll(getInWires().subList(1, getInWires().size()));
            allIOWires.addAll(getOutWires());
            allIOWires.addAll(getProverWitnessWires());
            for (Wire w : allIOWires) {
                printWriter.println(w.getWireId() + " " + "0");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
