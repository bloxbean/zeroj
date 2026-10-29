package org.zeroj.assurance.sha2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.lib.hash.Sha256;
import org.zeroj.circuit.lib.hash.Sha512;
import org.zeroj.circuit.r1cs.R1CSSerializer;
import org.zeroj.examples.dsl.common.WitnessExporter;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Optional test-only export. All witnesses are deliberately public fixtures. */
public final class Sha2InteropExport {
    private static final ObjectMapper JSON = new ObjectMapper();

    private Sha2InteropExport() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("Expected cases.json and output directory");
        Path output = Path.of(args[1]);
        Files.createDirectories(output);
        JSON.writerWithDefaultPrettyPrinter().writeValue(output.resolve("environment.json").toFile(), Map.of(
                "java_runtime_version", System.getProperty("java.runtime.version"),
                "java_vm", System.getProperty("java.vm.name"),
                "os_arch", System.getProperty("os.arch"),
                "available_processors", Runtime.getRuntime().availableProcessors(),
                "max_heap_bytes", Runtime.getRuntime().maxMemory()));
        Map<String, List<JsonNode>> groups = new TreeMap<>();
        for (JsonNode fixture : JSON.readTree(Path.of(args[0]).toFile())) {
            String algorithm = fixture.path("algorithm").asText();
            if (!List.of("sha256", "sha512").contains(algorithm)) throw new IllegalArgumentException(algorithm);
            byte[] message = HexFormat.of().parseHex(fixture.path("message_hex").asText());
            byte[] expected = HexFormat.of().parseHex(fixture.path("digest_hex").asText());
            byte[] oracle = MessageDigest.getInstance(algorithm.equals("sha256") ? "SHA-256" : "SHA-512").digest(message);
            if (!Arrays.equals(expected, oracle)) throw new IllegalStateException("JCA disagrees with fixture " + fixture);
            groups.computeIfAbsent(algorithm + "-" + message.length, ignored -> new ArrayList<>()).add(fixture);
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        for (var group : groups.entrySet()) {
            JsonNode first = group.getValue().getFirst();
            String algorithm = first.path("algorithm").asText();
            int byteLength = first.path("message_hex").asText().length() / 2;
            int limbCount = algorithm.equals("sha256") ? 2 : 4;
            for (boolean bits : new boolean[]{false, true}) {
                String api = bits ? "bits" : "bytes";
                String profile = group.getKey() + "-" + api;
                long started = System.nanoTime();
                CircuitBuilder circuit = circuit(algorithm, byteLength, bits);
                var relation = circuit.compileR1CS(CurveId.BLS12_381);
                double compileMs = elapsed(started);
                Path folder = Files.createDirectories(output.resolve(profile));
                byte[] encoded = R1CSSerializer.serialize(relation);
                Files.write(folder.resolve("circuit.r1cs"), encoded);
                for (JsonNode fixture : group.getValue()) {
                    byte[] message = HexFormat.of().parseHex(fixture.path("message_hex").asText());
                    byte[] digest = HexFormat.of().parseHex(fixture.path("digest_hex").asText());
                    Map<String, List<BigInteger>> inputs = inputs(message, digest, bits);
                    started = System.nanoTime();
                    BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);
                    double witnessMs = elapsed(started);
                    for (int i = 0; i < limbCount; i++) {
                        if (!witness[i + 1].equals(inputs.get("digest" + i).getFirst()))
                            throw new IllegalStateException("Public digest ordering differs");
                    }
                    String id = fixture.path("id").asText();
                    Files.write(folder.resolve(id + ".wtns"), WitnessExporter.toWtns(witness, relation.prime(), relation.fieldConfig().n8() / 4));
                    var row = new LinkedHashMap<String, Object>();
                    row.put("id", id); row.put("algorithm", algorithm); row.put("api", api);
                    row.put("message_bytes", byteLength); row.put("public_limbs", limbCount);
                    row.put("constraints", relation.numConstraints()); row.put("wires", relation.numWires());
                    row.put("compile_ms", compileMs); row.put("witness_ms", witnessMs);
                    row.put("r1cs", profile + "/circuit.r1cs"); row.put("witness", profile + "/" + id + ".wtns");
                    row.put("r1cs_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(encoded)));
                    row.put("digest_hex", fixture.path("digest_hex").asText());
                    row.put("first_private_wire", byteLength == 0 ? null : limbCount + 1);
                    rows.add(row);
                    System.out.println(id + " " + api + " constraints=" + relation.numConstraints());
                }
            }
        }
        JSON.writerWithDefaultPrettyPrinter().writeValue(output.resolve("export.json").toFile(), rows);
    }

    private static CircuitBuilder circuit(String algorithm, int byteLength, boolean bits) {
        int limbCount = algorithm.equals("sha256") ? 2 : 4;
        int length = bits ? Math.multiplyExact(byteLength, 8) : byteLength;
        var builder = CircuitBuilder.create(algorithm + "-" + byteLength + "-" + bits);
        for (int i = 0; i < limbCount; i++) builder.publicVar("digest" + i);
        for (int i = 0; i < length; i++) builder.secretVar("message" + i);
        return builder.define(api -> {
            Variable[] message = new Variable[length];
            for (int i = 0; i < length; i++) message[i] = api.var("message" + i);
            Variable[] digest;
            if (bits) digest = algorithm.equals("sha256") ? Sha256.hashBits(api, message) : Sha512.hashBits(api, message);
            else digest = algorithm.equals("sha256") ? Sha256.hashBytes(api, message) : Sha512.hashBytes(api, message);
            int units = bits ? 128 : 16;
            int radix = bits ? 2 : 256;
            for (int limb = 0; limb < limbCount; limb++) {
                Variable packed = api.constant(0);
                for (int i = 0; i < units; i++) packed = api.add(api.mul(packed, api.constant(radix)), digest[limb * units + i]);
                api.assertEqual(packed, api.var("digest" + limb));
            }
        });
    }

    private static Map<String, List<BigInteger>> inputs(byte[] message, byte[] digest, boolean bits) {
        Map<String, List<BigInteger>> inputs = new LinkedHashMap<>();
        for (int i = 0; i < digest.length / 16; i++)
            inputs.put("digest" + i, List.of(new BigInteger(1, Arrays.copyOfRange(digest, i * 16, (i + 1) * 16))));
        for (int i = 0; i < message.length; i++) {
            if (bits) for (int j = 0; j < 8; j++)
                inputs.put("message" + (i * 8 + j), List.of(BigInteger.valueOf((message[i] >>> (7 - j)) & 1)));
            else inputs.put("message" + i, List.of(BigInteger.valueOf(message[i] & 255)));
        }
        return inputs;
    }

    private static double elapsed(long start) { return (System.nanoTime() - start) / 1_000_000.0; }
}
