package com.bloxbean.cardano.zeroj.bls12381.wasm;

import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Memory;
import com.dylibso.chicory.wasm.Parser;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

/**
 * Chicory client for the ZeroJ BLS12-381 Rust WASM module.
 */
public final class Bls12381WasmClient {
    public static final String DEFAULT_RESOURCE = "/zeroj-bls12381/zeroj_bls12381.wasm";

    private static final int MAX_RESPONSE_LEN = 16 * 1024 * 1024;

    private final Instance instance;
    private final Memory memory;

    public Bls12381WasmClient(byte[] wasmBytes) {
        Objects.requireNonNull(wasmBytes, "wasmBytes required");
        if (wasmBytes.length == 0) {
            throw new IllegalArgumentException("wasmBytes must not be empty");
        }
        try {
            this.instance = Instance.builder(Parser.parse(wasmBytes)).build();
            this.memory = Objects.requireNonNull(instance.memory(), "BLS12-381 WASM module must export memory");
            long version = instance.export("zeroj_bls12381_version").apply()[0];
            if (version != 1L) {
                throw new Bls12381WasmException("Unsupported BLS12-381 WASM ABI version: " + version);
            }
        } catch (Bls12381WasmException e) {
            throw e;
        } catch (Exception e) {
            throw new Bls12381WasmException("Failed to initialize BLS12-381 WASM module", e);
        }
    }

    public static Bls12381WasmClient fromPath(Path wasmPath) throws IOException {
        return new Bls12381WasmClient(Files.readAllBytes(wasmPath));
    }

    public static Bls12381WasmClient createDefault() {
        try (var in = Bls12381WasmClient.class.getResourceAsStream(DEFAULT_RESOURCE)) {
            if (in == null) {
                throw new Bls12381WasmException("BLS12-381 WASM resource not found: " + DEFAULT_RESOURCE);
            }
            return new Bls12381WasmClient(in.readAllBytes());
        } catch (IOException e) {
            throw new Bls12381WasmException("Failed to read BLS12-381 WASM resource", e);
        }
    }

    public G1Point g1Generator() {
        return Bls12381Codecs.g1FromUncompressed(invokeNoArg("zeroj_bls12381_g1_generator"));
    }

    public G2Point g2Generator() {
        return Bls12381Codecs.g2FromUncompressed(invokeNoArg("zeroj_bls12381_g2_generator"));
    }

    public G1Point g1ScalarMul(G1Point point, BigInteger scalar) {
        byte[] request = concat(
                Bls12381Codecs.g1ToUncompressed(Bls12381Codecs.requireValid(point)),
                Bls12381Codecs.scalarToLittleEndian32Reduced(Objects.requireNonNull(scalar, "scalar required")));
        return Bls12381Codecs.g1FromUncompressed(invoke("zeroj_bls12381_g1_scalar_mul", request));
    }

    public G2Point g2ScalarMul(G2Point point, BigInteger scalar) {
        byte[] request = concat(
                Bls12381Codecs.g2ToUncompressed(Bls12381Codecs.requireValid(point)),
                Bls12381Codecs.scalarToLittleEndian32Reduced(Objects.requireNonNull(scalar, "scalar required")));
        return Bls12381Codecs.g2FromUncompressed(invoke("zeroj_bls12381_g2_scalar_mul", request));
    }

    public boolean pairingProductIsIdentity(G1Point[] g1Points, G2Point[] g2Points) {
        Objects.requireNonNull(g1Points, "g1Points required");
        Objects.requireNonNull(g2Points, "g2Points required");
        if (g1Points.length != g2Points.length) {
            throw new IllegalArgumentException("Arrays must have equal length");
        }
        ByteBuffer request = ByteBuffer
                .allocate(4 + g1Points.length * (Bls12381Codecs.G1_UNCOMPRESSED_BYTES + Bls12381Codecs.G2_UNCOMPRESSED_BYTES))
                .order(ByteOrder.LITTLE_ENDIAN);
        request.putInt(g1Points.length);
        for (int i = 0; i < g1Points.length; i++) {
            request.put(Bls12381Codecs.g1ToUncompressed(Bls12381Codecs.requireValid(g1Points[i])));
            request.put(Bls12381Codecs.g2ToUncompressed(Bls12381Codecs.requireValid(g2Points[i])));
        }
        byte[] response = invoke("zeroj_bls12381_pairing_check", request.array());
        if (response.length != 1) {
            throw new Bls12381WasmException("Invalid BLS12-381 pairing response length: " + response.length);
        }
        return response[0] != 0;
    }

    byte[] invokeRawForTesting(String exportName, byte[] request) {
        return invoke(exportName, request);
    }

    byte[] invokeNoArgRawForTesting(String exportName) {
        return invokeNoArg(exportName);
    }

    long invokeExportForTesting(String exportName, long... args) {
        return instance.export(exportName).apply(args)[0];
    }

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
        } catch (Bls12381WasmException e) {
            throw e;
        } catch (Exception e) {
            throw new Bls12381WasmException("BLS12-381 WASM invocation failed: " + exportName, e);
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
        } catch (Bls12381WasmException e) {
            throw e;
        } catch (Exception e) {
            throw new Bls12381WasmException("BLS12-381 WASM invocation failed: " + exportName, e);
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
            throw new Bls12381WasmException("Invalid BLS12-381 WASM response length: " + responseLen);
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
            throw new Bls12381WasmException("BLS12-381 WASM error from " + exportName + ": " + message);
        }
        return Arrays.copyOfRange(response, 1, response.length);
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] out = Arrays.copyOf(left, left.length + right.length);
        System.arraycopy(right, 0, out, left.length, right.length);
        return out;
    }

}
