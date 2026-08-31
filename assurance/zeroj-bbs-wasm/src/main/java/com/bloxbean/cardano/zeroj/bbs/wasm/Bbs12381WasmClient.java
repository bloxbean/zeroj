package com.bloxbean.cardano.zeroj.bbs.wasm;

import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.dylibso.chicory.runtime.HostFunction;
import com.dylibso.chicory.runtime.ImportValues;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Memory;
import com.dylibso.chicory.wasm.Parser;
import com.dylibso.chicory.wasm.types.ValueType;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Chicory client for the ZeroJ CFRG BBS Rust WASM module.
 *
 * <p>Exposes the coarse {@code zeroj_bbs_*} ABI: keygen, sk_to_pk, sign, verify,
 * proof_gen, proof_verify. The module imports exactly one host function,
 * {@code env.zeroj_host_getrandom}, which this client wires to
 * {@link SecureRandom}. See ADR-0019 §7.</p>
 */
public final class Bbs12381WasmClient {
    public static final String DEFAULT_RESOURCE = "/zeroj-bbs-wasm/zeroj_bbs.wasm";

    private static final int MAX_RESPONSE_LEN = 16 * 1024 * 1024;
    private static final int MAX_HOST_GETRANDOM_LEN = 16 * 1024;

    /** Maximum number of signed messages or revealed indexes per request (matches the Rust cap). */
    static final int MAX_MESSAGES = 1024;
    /** Maximum bytes per individual message. */
    static final int MAX_MESSAGE_BYTES = 64 * 1024;
    /** Maximum bytes for header / presentation header. */
    static final int MAX_HEADER_BYTES = 64 * 1024;
    /** Maximum bytes for key material / key info. */
    static final int MAX_KEY_INPUT_BYTES = 64 * 1024;
    /** Maximum bytes for an opaque proof. */
    static final int MAX_PROOF_BYTES = 3 * 96 + (4 + MAX_MESSAGES) * 32;
    /** Maximum total serialized request size. */
    static final int MAX_REQUEST_BYTES = 16 * 1024 * 1024;

    static final byte SUITE_SHA256 = 0;
    static final byte SUITE_SHAKE256 = 1;

    private final byte[] wasmBytes;
    private final Instance instance;
    private final Memory memory;
    private final SecureRandom defaultRandom;

    public Bbs12381WasmClient(byte[] wasmBytes, SecureRandom random) {
        Objects.requireNonNull(wasmBytes, "wasmBytes required");
        Objects.requireNonNull(random, "random required");
        if (wasmBytes.length == 0) {
            throw new IllegalArgumentException("wasmBytes must not be empty");
        }
        this.wasmBytes = wasmBytes.clone();
        this.defaultRandom = random;
        try {
            // Persistent instance for ops that consume no entropy (keygen,
            // sk_to_pk, sign, verify, proof_verify) — bound to defaultRandom
            // since they should never reach the host RNG anyway.
            this.instance = buildInstance(this.wasmBytes, this.defaultRandom);
            this.memory = Objects.requireNonNull(instance.memory(), "BBS WASM module must export memory");
            long version = instance.export("zeroj_bbs_version").apply()[0];
            if (version != 1L) {
                throw new Bbs12381WasmException("Unsupported BBS WASM ABI version: " + version);
            }
        } catch (Bbs12381WasmException e) {
            throw e;
        } catch (Exception e) {
            throw new Bbs12381WasmException("Failed to initialize BBS WASM module", e);
        }
    }

    /**
     * Build a fresh Chicory Instance whose {@code env.zeroj_host_getrandom}
     * import draws from the given {@link SecureRandom}. A fresh instance is
     * required for every {@code proof_gen} call because zkryptium's internal
     * {@code rand::thread_rng()} keeps a cached chacha-state per thread that
     * only re-seeds from {@code getrandom} on the first use — so without a
     * fresh instance, calls 2..N silently bypass the per-call SecureRandom and
     * derive bytes from the cached state seeded by call 1.
     */
    private static Instance buildInstance(byte[] wasmBytes, SecureRandom random) {
        HostFunction hostGetrandom = new HostFunction(
                "env",
                "zeroj_host_getrandom",
                List.of(ValueType.I32, ValueType.I32),
                List.of(ValueType.I32),
                (inst, args) -> {
                    int ptr = (int) args[0];
                    int len = (int) args[1];
                    if (len < 0 || len > MAX_HOST_GETRANDOM_LEN) {
                        return new long[]{1L};
                    }
                    if (len == 0) {
                        return new long[]{0L};
                    }
                    byte[] buf = new byte[len];
                    random.nextBytes(buf);
                    inst.memory().write(ptr, buf);
                    return new long[]{0L};
                });
        ImportValues imports = ImportValues.builder().addFunction(hostGetrandom).build();
        return Instance.builder(Parser.parse(wasmBytes)).withImportValues(imports).build();
    }

    public static Bbs12381WasmClient fromPath(Path wasmPath) throws IOException {
        return new Bbs12381WasmClient(Files.readAllBytes(wasmPath), new SecureRandom());
    }

    public static Bbs12381WasmClient createDefault() {
        return createDefault(new SecureRandom());
    }

    public static Bbs12381WasmClient createDefault(SecureRandom random) {
        try (var in = Bbs12381WasmClient.class.getResourceAsStream(DEFAULT_RESOURCE)) {
            if (in == null) {
                throw new Bbs12381WasmException("BBS WASM resource not found: " + DEFAULT_RESOURCE);
            }
            return new Bbs12381WasmClient(in.readAllBytes(), random);
        } catch (IOException e) {
            throw new Bbs12381WasmException("Failed to read BBS WASM resource", e);
        }
    }

    // ----- typed entry points -----

    public byte[] keyGen(BbsCiphersuite ciphersuite, byte[] keyMaterial, byte[] keyInfo) {
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        requireMaxLength(keyMaterial, MAX_KEY_INPUT_BYTES, "keyMaterial");
        requireMaxLength(keyInfo, MAX_KEY_INPUT_BYTES, "keyInfo");
        long size = 1L + 4 + keyMaterial.length + 4 + keyInfo.length;
        ByteBuffer req = allocateRequest(size, "keyGen");
        req.put(suite(ciphersuite));
        putVarBytes(req, keyMaterial);
        putVarBytes(req, keyInfo);
        return invoke("zeroj_bbs_keygen", req.array());
    }

    public byte[] skToPk(BbsCiphersuite ciphersuite, byte[] sk) {
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        Objects.requireNonNull(sk, "sk required");
        if (sk.length != 32) {
            throw new IllegalArgumentException("BBS secret key must be 32 bytes, got " + sk.length);
        }
        ByteBuffer req = ByteBuffer.allocate(1 + 32).order(ByteOrder.LITTLE_ENDIAN);
        req.put(suite(ciphersuite));
        req.put(sk);
        return invoke("zeroj_bbs_sk_to_pk", req.array());
    }

    public byte[] sign(BbsCiphersuite ciphersuite, byte[] sk, byte[] pk, byte[] header, List<byte[]> messages) {
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        Objects.requireNonNull(sk, "sk required");
        if (sk.length != 32) {
            throw new IllegalArgumentException("BBS secret key must be 32 bytes, got " + sk.length);
        }
        requireLength(pk, 96, "BBS public key");
        requireMaxLength(header, MAX_HEADER_BYTES, "header");
        long messagesBytes = validateMessageList(messages, "messages");
        long size = 1L + 32 + 96 + 4 + header.length + 4 + messagesBytes;
        ByteBuffer req = allocateRequest(size, "sign");
        req.put(suite(ciphersuite));
        req.put(sk);
        req.put(pk);
        putVarBytes(req, header);
        putMessageList(req, messages);
        return invoke("zeroj_bbs_sign", req.array());
    }

    public boolean verify(
            BbsCiphersuite ciphersuite, byte[] pk, byte[] signature, byte[] header, List<byte[]> messages) {
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        requireLength(pk, 96, "BBS public key");
        requireLength(signature, 80, "BBS signature");
        requireMaxLength(header, MAX_HEADER_BYTES, "header");
        long messagesBytes = validateMessageList(messages, "messages");
        long size = 1L + 96 + 80 + 4 + header.length + 4 + messagesBytes;
        ByteBuffer req = allocateRequest(size, "verify");
        req.put(suite(ciphersuite));
        req.put(pk);
        req.put(signature);
        putVarBytes(req, header);
        putMessageList(req, messages);
        byte[] response = invoke("zeroj_bbs_verify", req.array());
        return decodeBool(response, "verify");
    }

    public byte[] proofGen(
            BbsCiphersuite ciphersuite,
            byte[] pk,
            byte[] signature,
            byte[] header,
            byte[] presentationHeader,
            List<byte[]> messages,
            int[] disclosedIndexes,
            SecureRandom random) {
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        Objects.requireNonNull(random, "random required");
        requireLength(pk, 96, "BBS public key");
        requireLength(signature, 80, "BBS signature");
        requireMaxLength(header, MAX_HEADER_BYTES, "header");
        requireMaxLength(presentationHeader, MAX_HEADER_BYTES, "presentationHeader");
        long messagesBytes = validateMessageList(messages, "messages");
        validateIndexList(disclosedIndexes, messages.size(), "disclosedIndexes");
        long size = 1L + 96 + 80 + 4 + header.length + 4 + presentationHeader.length
                + 4 + messagesBytes + 4L + 4L * disclosedIndexes.length;
        ByteBuffer req = allocateRequest(size, "proofGen");
        req.put(suite(ciphersuite));
        req.put(pk);
        req.put(signature);
        putVarBytes(req, header);
        putVarBytes(req, presentationHeader);
        putMessageList(req, messages);
        req.putInt(disclosedIndexes.length);
        for (int idx : disclosedIndexes) {
            req.putInt(idx);
        }
        return invokeOnTransientInstance("zeroj_bbs_proof_gen", req.array(), random);
    }

    public boolean proofVerify(
            BbsCiphersuite ciphersuite,
            byte[] pk,
            byte[] proof,
            byte[] header,
            byte[] presentationHeader,
            List<byte[]> disclosedMessages,
            int[] disclosedIndexes) {
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        requireLength(pk, 96, "BBS public key");
        requireMaxLength(proof, MAX_PROOF_BYTES, "proof");
        requireMaxLength(header, MAX_HEADER_BYTES, "header");
        requireMaxLength(presentationHeader, MAX_HEADER_BYTES, "presentationHeader");
        long messagesBytes = validateMessageList(disclosedMessages, "disclosedMessages");
        validateDisclosedIndexesForVerify(disclosedIndexes, "disclosedIndexes");
        if (disclosedIndexes.length != disclosedMessages.size()) {
            throw new IllegalArgumentException(
                    "disclosedIndexes (" + disclosedIndexes.length
                            + ") and disclosedMessages (" + disclosedMessages.size() + ") must have equal length");
        }
        long size = 1L + 96 + 4 + proof.length + 4 + header.length + 4 + presentationHeader.length
                + 4 + messagesBytes + 4L + 4L * disclosedIndexes.length;
        ByteBuffer req = allocateRequest(size, "proofVerify");
        req.put(suite(ciphersuite));
        req.put(pk);
        putVarBytes(req, proof);
        putVarBytes(req, header);
        putVarBytes(req, presentationHeader);
        putMessageList(req, disclosedMessages);
        req.putInt(disclosedIndexes.length);
        for (int idx : disclosedIndexes) {
            req.putInt(idx);
        }
        byte[] response = invoke("zeroj_bbs_proof_verify", req.array());
        return decodeBool(response, "proof_verify");
    }

    // ----- test hooks -----

    byte[] invokeRawForTesting(String exportName, byte[] request) {
        return invoke(exportName, request);
    }

    byte[] invokeNoArgRawForTesting(String exportName) {
        return invokeNoArg(exportName);
    }

    long invokeExportForTesting(String exportName, long... args) {
        return instance.export(exportName).apply(args)[0];
    }

    // ----- internal -----

    /**
     * Run {@code exportName} on a freshly-built Chicory instance whose
     * getrandom import draws from {@code random}. The instance is discarded
     * after the call. See {@link #buildInstance} for the rationale: this is
     * what guarantees the per-call SecureRandom drives every proof generation,
     * not just the first one per shared instance.
     */
    private byte[] invokeOnTransientInstance(String exportName, byte[] request, SecureRandom random) {
        Instance transient_ = buildInstance(wasmBytes, random);
        Memory transientMemory = Objects.requireNonNull(
                transient_.memory(), "BBS WASM module must export memory");
        int requestPtr = 0;
        int responsePtr = 0;
        long responseAllocationLen = 0;
        try {
            requestPtr = (int) transient_.export("alloc").apply(request.length)[0];
            transientMemory.write(requestPtr, request);
            responsePtr = (int) transient_.export(exportName).apply(requestPtr, request.length)[0];
            long responseLen = readResponseLenHeader(transientMemory, responsePtr);
            responseAllocationLen = responseAllocationLen(responseLen);
            requireValidResponseLen(responseLen);
            return readResponsePayload(transientMemory, exportName, responsePtr, (int) responseLen);
        } catch (Bbs12381WasmException e) {
            throw e;
        } catch (Exception e) {
            throw new Bbs12381WasmException("BBS WASM invocation failed: " + exportName, e);
        } finally {
            if (requestPtr != 0) {
                transient_.export("dealloc").apply(requestPtr, request.length);
            }
            if (responsePtr != 0 && responseAllocationLen > 0) {
                transient_.export("dealloc").apply(responsePtr, responseAllocationLen);
            }
        }
    }

    private synchronized byte[] invoke(String exportName, byte[] request) {
        int requestPtr = 0;
        int responsePtr = 0;
        long responseAllocationLen = 0;
        try {
            requestPtr = (int) instance.export("alloc").apply(request.length)[0];
            memory.write(requestPtr, request);
            responsePtr = (int) instance.export(exportName).apply(requestPtr, request.length)[0];
            long responseLen = readResponseLenHeader(memory, responsePtr);
            responseAllocationLen = responseAllocationLen(responseLen);
            requireValidResponseLen(responseLen);
            return readResponsePayload(memory, exportName, responsePtr, (int) responseLen);
        } catch (Bbs12381WasmException e) {
            throw e;
        } catch (Exception e) {
            throw new Bbs12381WasmException("BBS WASM invocation failed: " + exportName, e);
        } finally {
            if (requestPtr != 0) {
                instance.export("dealloc").apply(requestPtr, request.length);
            }
            if (responsePtr != 0 && responseAllocationLen > 0) {
                instance.export("dealloc").apply(responsePtr, responseAllocationLen);
            }
        }
    }

    private synchronized byte[] invokeNoArg(String exportName) {
        int responsePtr = 0;
        long responseAllocationLen = 0;
        try {
            responsePtr = (int) instance.export(exportName).apply()[0];
            long responseLen = readResponseLenHeader(memory, responsePtr);
            responseAllocationLen = responseAllocationLen(responseLen);
            requireValidResponseLen(responseLen);
            return readResponsePayload(memory, exportName, responsePtr, (int) responseLen);
        } catch (Bbs12381WasmException e) {
            throw e;
        } catch (Exception e) {
            throw new Bbs12381WasmException("BBS WASM invocation failed: " + exportName, e);
        } finally {
            if (responsePtr != 0 && responseAllocationLen > 0) {
                instance.export("dealloc").apply(responsePtr, responseAllocationLen);
            }
        }
    }

    private long readResponseLenHeader(Memory mem, int responsePtr) {
        byte[] lenBytes = mem.readBytes(responsePtr, 4);
        return Integer.toUnsignedLong(ByteBuffer.wrap(lenBytes).order(ByteOrder.LITTLE_ENDIAN).getInt());
    }

    private void requireValidResponseLen(long responseLen) {
        if (responseLen == 0 || responseLen > MAX_RESPONSE_LEN) {
            throw new Bbs12381WasmException("Invalid BBS WASM response length: " + responseLen);
        }
    }

    private long responseAllocationLen(long responseLen) {
        long maxWasmAllocationLen = Integer.toUnsignedLong(-1);
        return responseLen <= maxWasmAllocationLen - 4 ? responseLen + 4 : 0;
    }

    private byte[] readResponsePayload(Memory mem, String exportName, int responsePtr, int responseLen) {
        byte[] response = mem.readBytes(responsePtr + 4, responseLen);
        if (response[0] != 0) {
            String message = new String(response, 1, response.length - 1, StandardCharsets.UTF_8);
            throw new Bbs12381WasmException("BBS WASM error from " + exportName + ": " + message);
        }
        return Arrays.copyOfRange(response, 1, response.length);
    }

    private static byte suite(BbsCiphersuite ciphersuite) {
        return switch (ciphersuite) {
            case BLS12381_SHA256 -> SUITE_SHA256;
            case BLS12381_SHAKE256 -> SUITE_SHAKE256;
        };
    }

    private static void putVarBytes(ByteBuffer buf, byte[] bytes) {
        buf.putInt(bytes.length);
        buf.put(bytes);
    }

    private static void putMessageList(ByteBuffer buf, List<byte[]> messages) {
        buf.putInt(messages.size());
        for (byte[] msg : messages) {
            putVarBytes(buf, msg);
        }
    }

    private static long validateMessageList(List<byte[]> messages, String label) {
        Objects.requireNonNull(messages, label + " required");
        if (messages.size() > MAX_MESSAGES) {
            throw new IllegalArgumentException(
                    label + " count " + messages.size() + " exceeds " + MAX_MESSAGES);
        }
        long total = 0L;
        for (int i = 0; i < messages.size(); i++) {
            byte[] m = messages.get(i);
            if (m == null) {
                throw new IllegalArgumentException(label + "[" + i + "] must not be null");
            }
            if (m.length > MAX_MESSAGE_BYTES) {
                throw new IllegalArgumentException(
                        label + "[" + i + "] length " + m.length + " exceeds " + MAX_MESSAGE_BYTES);
            }
            total = Math.addExact(total, 4L + m.length);
        }
        return total;
    }

    private static void validateIndexList(int[] indexes, int messageCount, String label) {
        Objects.requireNonNull(indexes, label + " required");
        if (indexes.length > MAX_MESSAGES) {
            throw new IllegalArgumentException(
                    label + " count " + indexes.length + " exceeds " + MAX_MESSAGES);
        }
        int previous = -1;
        for (int i = 0; i < indexes.length; i++) {
            int idx = indexes[i];
            if (idx < 0 || idx >= messageCount) {
                throw new IllegalArgumentException(
                        label + "[" + i + "] = " + idx + " out of range [0, " + messageCount + ")");
            }
            if (idx <= previous) {
                throw new IllegalArgumentException(
                        label + " must be strictly ascending; "
                                + label + "[" + i + "] = " + idx + " is not greater than previous " + previous);
            }
            previous = idx;
        }
    }

    /**
     * Like {@link #validateIndexList} but for the proof_verify path where the
     * total message count is not known to the caller (only the disclosed
     * subset is). Validates strict-ascending, no-duplicate, non-negative.
     */
    private static void validateDisclosedIndexesForVerify(int[] indexes, String label) {
        Objects.requireNonNull(indexes, label + " required");
        if (indexes.length > MAX_MESSAGES) {
            throw new IllegalArgumentException(
                    label + " count " + indexes.length + " exceeds " + MAX_MESSAGES);
        }
        int previous = -1;
        for (int i = 0; i < indexes.length; i++) {
            int idx = indexes[i];
            if (idx < 0) {
                throw new IllegalArgumentException(
                        label + "[" + i + "] = " + idx + " must be non-negative");
            }
            if (idx <= previous) {
                throw new IllegalArgumentException(
                        label + " must be strictly ascending; "
                                + label + "[" + i + "] = " + idx + " is not greater than previous " + previous);
            }
            previous = idx;
        }
    }

    private static void requireLength(byte[] arr, int length, String label) {
        Objects.requireNonNull(arr, label + " required");
        if (arr.length != length) {
            throw new IllegalArgumentException(label + " must be " + length + " bytes, got " + arr.length);
        }
    }

    private static void requireMaxLength(byte[] arr, int max, String label) {
        Objects.requireNonNull(arr, label + " required");
        if (arr.length > max) {
            throw new IllegalArgumentException(
                    label + " length " + arr.length + " exceeds " + max);
        }
    }

    private static ByteBuffer allocateRequest(long size, String op) {
        if (size > MAX_REQUEST_BYTES) {
            throw new IllegalArgumentException(
                    "BBS WASM " + op + " request size " + size + " exceeds " + MAX_REQUEST_BYTES);
        }
        return ByteBuffer.allocate(Math.toIntExact(size)).order(ByteOrder.LITTLE_ENDIAN);
    }

    private static boolean decodeBool(byte[] response, String exportName) {
        if (response.length != 1) {
            throw new Bbs12381WasmException(
                    "Invalid BBS WASM " + exportName + " response length: " + response.length);
        }
        byte b = response[0];
        if (b == 0) {
            return false;
        }
        if (b == 1) {
            return true;
        }
        throw new Bbs12381WasmException(
                "Invalid BBS WASM " + exportName + " boolean response byte: 0x"
                        + String.format("%02x", b & 0xff));
    }
}
