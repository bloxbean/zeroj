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

    static final byte SUITE_SHA256 = 0;
    static final byte SUITE_SHAKE256 = 1;

    private final Instance instance;
    private final Memory memory;
    private final SecureRandom random;

    public Bbs12381WasmClient(byte[] wasmBytes, SecureRandom random) {
        Objects.requireNonNull(wasmBytes, "wasmBytes required");
        Objects.requireNonNull(random, "random required");
        if (wasmBytes.length == 0) {
            throw new IllegalArgumentException("wasmBytes must not be empty");
        }
        this.random = random;
        try {
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
                        this.random.nextBytes(buf);
                        inst.memory().write(ptr, buf);
                        return new long[]{0L};
                    });
            ImportValues imports = ImportValues.builder().addFunction(hostGetrandom).build();
            this.instance = Instance.builder(Parser.parse(wasmBytes))
                    .withImportValues(imports)
                    .build();
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
        Objects.requireNonNull(keyMaterial, "keyMaterial required");
        Objects.requireNonNull(keyInfo, "keyInfo required");
        ByteBuffer req = ByteBuffer.allocate(1 + 4 + keyMaterial.length + 4 + keyInfo.length)
                .order(ByteOrder.LITTLE_ENDIAN);
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
        Objects.requireNonNull(pk, "pk required");
        Objects.requireNonNull(header, "header required");
        Objects.requireNonNull(messages, "messages required");
        if (sk.length != 32) {
            throw new IllegalArgumentException("BBS secret key must be 32 bytes, got " + sk.length);
        }
        if (pk.length != 96) {
            throw new IllegalArgumentException("BBS public key must be 96 bytes, got " + pk.length);
        }
        ByteBuffer req = ByteBuffer.allocate(signRequestLen(header, messages)).order(ByteOrder.LITTLE_ENDIAN);
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
        Objects.requireNonNull(pk, "pk required");
        Objects.requireNonNull(signature, "signature required");
        Objects.requireNonNull(header, "header required");
        Objects.requireNonNull(messages, "messages required");
        if (pk.length != 96) {
            throw new IllegalArgumentException("BBS public key must be 96 bytes, got " + pk.length);
        }
        if (signature.length != 80) {
            throw new IllegalArgumentException("BBS signature must be 80 bytes, got " + signature.length);
        }
        ByteBuffer req = ByteBuffer.allocate(1 + 96 + 80 + 4 + header.length + 4 + messagesPayload(messages))
                .order(ByteOrder.LITTLE_ENDIAN);
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
            int[] disclosedIndexes) {
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        Objects.requireNonNull(pk, "pk required");
        Objects.requireNonNull(signature, "signature required");
        Objects.requireNonNull(header, "header required");
        Objects.requireNonNull(presentationHeader, "presentationHeader required");
        Objects.requireNonNull(messages, "messages required");
        Objects.requireNonNull(disclosedIndexes, "disclosedIndexes required");
        if (pk.length != 96) {
            throw new IllegalArgumentException("BBS public key must be 96 bytes, got " + pk.length);
        }
        if (signature.length != 80) {
            throw new IllegalArgumentException("BBS signature must be 80 bytes, got " + signature.length);
        }
        int size = 1 + 96 + 80 + 4 + header.length + 4 + presentationHeader.length
                + 4 + messagesPayload(messages) + 4 + 4 * disclosedIndexes.length;
        ByteBuffer req = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
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
        return invoke("zeroj_bbs_proof_gen", req.array());
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
        Objects.requireNonNull(pk, "pk required");
        Objects.requireNonNull(proof, "proof required");
        Objects.requireNonNull(header, "header required");
        Objects.requireNonNull(presentationHeader, "presentationHeader required");
        Objects.requireNonNull(disclosedMessages, "disclosedMessages required");
        Objects.requireNonNull(disclosedIndexes, "disclosedIndexes required");
        if (pk.length != 96) {
            throw new IllegalArgumentException("BBS public key must be 96 bytes, got " + pk.length);
        }
        int size = 1 + 96 + 4 + proof.length + 4 + header.length + 4 + presentationHeader.length
                + 4 + messagesPayload(disclosedMessages) + 4 + 4 * disclosedIndexes.length;
        ByteBuffer req = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
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

    private synchronized byte[] invoke(String exportName, byte[] request) {
        int requestPtr = 0;
        int responsePtr = 0;
        long responseAllocationLen = 0;
        try {
            requestPtr = (int) instance.export("alloc").apply(request.length)[0];
            memory.write(requestPtr, request);
            responsePtr = (int) instance.export(exportName).apply(requestPtr, request.length)[0];
            long responseLen = readResponseLenHeader(responsePtr);
            responseAllocationLen = responseAllocationLen(responseLen);
            requireValidResponseLen(responseLen);
            return readResponsePayload(exportName, responsePtr, (int) responseLen);
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
            long responseLen = readResponseLenHeader(responsePtr);
            responseAllocationLen = responseAllocationLen(responseLen);
            requireValidResponseLen(responseLen);
            return readResponsePayload(exportName, responsePtr, (int) responseLen);
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

    private long readResponseLenHeader(int responsePtr) {
        byte[] lenBytes = memory.readBytes(responsePtr, 4);
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

    private byte[] readResponsePayload(String exportName, int responsePtr, int responseLen) {
        byte[] response = memory.readBytes(responsePtr + 4, responseLen);
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

    private static int messagesPayload(List<byte[]> messages) {
        int total = 0;
        for (byte[] m : messages) {
            total += 4 + m.length;
        }
        return total;
    }

    private static int signRequestLen(byte[] header, List<byte[]> messages) {
        return 1 + 32 + 96 + 4 + header.length + 4 + messagesPayload(messages);
    }

    private static boolean decodeBool(byte[] response, String exportName) {
        if (response.length != 1) {
            throw new Bbs12381WasmException(
                    "Invalid BBS WASM " + exportName + " response length: " + response.length);
        }
        return response[0] != 0;
    }
}
