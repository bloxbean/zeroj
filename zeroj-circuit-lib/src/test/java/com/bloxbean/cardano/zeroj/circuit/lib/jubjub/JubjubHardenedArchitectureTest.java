package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.HardenedBytecodePolicy.MemberRef;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.HardenedBytecodePolicy.read;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Compiled-artifact allow-list for the hardened secret-processing region.
 *
 * <p>The policy classifies exact external dependencies and exact calls across the public-data
 * boundary. A class-level boundary exemption is insufficient: it would allow hardened code
 * to add a new adapter method that converts secret limbs to {@code BigInteger}. Nested
 * hardened classes are traversed and checked rather than attributed to an unscanned outer
 * class.
 */
class JubjubHardenedArchitectureTest {

    private static final List<Class<?>> HARDENED_SECRET_CLASSES = List.of(
            CtMontgomery256Ops.class,
            CtJubjubFqOps.class,
            CtJubjubFrOps.class,
            CtJubjubPointOps.class,
            CtPoseidonT3.class,
            CtPoseidonT3Constants.class,
            CtJubjubNonce.class,
            SigningScratch.class,
            HardenedJubjubKey.class,
            FixedLimbJubjubSigner.class,
            PedersenScratch.class,
            HardenedPedersenOpening.class,
            HardenedPedersen.class
    );

    private static final Set<String> ALLOWED_EXTERNAL_CLASSES = Set.of(
            "java/lang/AutoCloseable",
            "java/lang/Class",
            "java/lang/Enum",
            "java/lang/Error",
            "java/lang/FunctionalInterface",
            "java/lang/IllegalArgumentException",
            "java/lang/IllegalStateException",
            "java/lang/InterruptedException",
            "java/lang/Math",
            "java/lang/Object",
            "java/lang/RuntimeException",
            "java/lang/String",
            "java/lang/System",
            "java/lang/Thread",
            "java/lang/Throwable",
            "java/lang/invoke/CallSite",
            "java/lang/invoke/LambdaMetafactory",
            "java/lang/invoke/MethodHandle",
            "java/lang/invoke/MethodHandles",
            "java/lang/invoke/MethodHandles$Lookup",
            "java/lang/invoke/MethodType",
            "java/lang/invoke/StringConcatFactory",
            "java/lang/invoke/VarHandle",
            "java/security/SecureRandom",
            "java/util/Arrays",
            "java/util/Objects",
            "java/util/concurrent/CountDownLatch",
            "java/util/concurrent/atomic/AtomicBoolean"
    );

    private static final Set<MemberRef> ALLOWED_EXTERNAL_METHODS = Set.of(
            method("java/lang/Enum", "<init>", "(Ljava/lang/String;I)V"),
            method("java/lang/Enum", "valueOf",
                    "(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;"),
            method("java/lang/IllegalArgumentException", "<init>",
                    "(Ljava/lang/String;)V"),
            method("java/lang/IllegalStateException", "<init>",
                    "(Ljava/lang/String;)V"),
            method("java/lang/Math", "unsignedMultiplyHigh", "(JJ)J"),
            method("java/lang/Object", "<init>", "()V"),
            method("java/lang/Object", "notifyAll", "()V"),
            method("java/lang/Object", "wait", "()V"),
            method("java/lang/String", "valueOf",
                    "(Ljava/lang/Object;)Ljava/lang/String;"),
            method("java/lang/System", "arraycopy",
                    "(Ljava/lang/Object;ILjava/lang/Object;II)V"),
            method("java/lang/Thread", "currentThread", "()Ljava/lang/Thread;"),
            method("java/lang/Thread", "interrupt", "()V"),
            method("java/lang/Throwable", "addSuppressed",
                    "(Ljava/lang/Throwable;)V"),
            method("java/lang/invoke/LambdaMetafactory", "metafactory",
                    "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                            + "Ljava/lang/invoke/MethodType;"
                            + "Ljava/lang/invoke/MethodType;"
                            + "Ljava/lang/invoke/MethodHandle;"
                            + "Ljava/lang/invoke/MethodType;)"
                            + "Ljava/lang/invoke/CallSite;"),
            method("java/lang/invoke/MethodHandles", "arrayElementVarHandle",
                    "(Ljava/lang/Class;)Ljava/lang/invoke/VarHandle;"),
            method("java/lang/invoke/StringConcatFactory", "makeConcatWithConstants",
                    "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                            + "Ljava/lang/invoke/MethodType;Ljava/lang/String;"
                            + "[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;"),
            method("java/lang/invoke/VarHandle", "fullFence", "()V"),
            method("java/lang/invoke/VarHandle", "setVolatile", "([BIB)V"),
            method("java/lang/invoke/VarHandle", "setVolatile", "([JIJ)V"),
            method("java/security/SecureRandom", "nextBytes", "([B)V"),
            method("java/util/Arrays", "fill", "([JJ)V"),
            method("java/util/Objects", "requireNonNull",
                    "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;"),
            method("java/util/concurrent/CountDownLatch", "<init>", "(I)V"),
            method("java/util/concurrent/CountDownLatch", "await", "()V"),
            method("java/util/concurrent/CountDownLatch", "countDown", "()V"),
            method("java/util/concurrent/atomic/AtomicBoolean", "<init>", "()V"),
            method("java/util/concurrent/atomic/AtomicBoolean", "compareAndSet",
                    "(ZZ)Z"),
            method("java/util/concurrent/atomic/AtomicBoolean", "get", "()Z")
    );

    private static final Set<String> APPROVED_BOUNDARY_CLASSES = Set.of(
            internalName(JubjubPublicAdapter.class),
            internalName(JubjubMessage.class),
            internalName(JubjubSigner.class),
            internalName(JubjubSigningProfile.class),
            internalName(JubjubAuxiliaryRandomSource.class),
            internalName(JubjubPoint.class),
            internalName(JubjubCurve.class),
            internalName(EdDSAJubjub.class),
            internalName(EdDSAJubjub.Signature.class)
    );

    private static final Set<MemberRef> APPROVED_BOUNDARY_METHODS = Set.of(
            method(JubjubAuxiliaryRandomSource.class, "fill", "([B)V"),
            method(JubjubAuxiliaryRandomSource.class, "close", "()V"),
            method(JubjubMessage.class, "copyCanonicalTo", "([BI)V"),
            method(JubjubPublicAdapter.class, "normalizedPoint",
                    "([JI[BII[JI)Lcom/bloxbean/cardano/zeroj/circuit/lib/jubjub/"
                            + "JubjubPoint;"),
            method(JubjubPublicAdapter.class, "challengeToScalar",
                    "([JILcom/bloxbean/cardano/zeroj/circuit/lib/jubjub/JubjubPoint;"
                            + "Lcom/bloxbean/cardano/zeroj/circuit/lib/jubjub/JubjubPoint;"
                            + "Lcom/bloxbean/cardano/zeroj/circuit/lib/jubjub/JubjubMessage;"
                            + "[BI[JI)J"),
            method(JubjubPublicAdapter.class, "signature",
                    "(Lcom/bloxbean/cardano/zeroj/circuit/lib/jubjub/JubjubPoint;"
                            + "[JI[BI[JI)Lcom/bloxbean/cardano/zeroj/circuit/lib/jubjub/"
                            + "EdDSAJubjub$Signature;"),
            method(JubjubPublicAdapter.class, "verifyBeforeRelease",
                    "(Lcom/bloxbean/cardano/zeroj/circuit/lib/jubjub/JubjubPoint;"
                            + "Lcom/bloxbean/cardano/zeroj/circuit/lib/jubjub/JubjubMessage;"
                            + "Lcom/bloxbean/cardano/zeroj/circuit/lib/jubjub/"
                            + "EdDSAJubjub$Signature;)"
                            + "Lcom/bloxbean/cardano/zeroj/circuit/lib/jubjub/"
                            + "EdDSAJubjub$Signature;")
    );

    private static final Set<MemberRef> APPROVED_BOUNDARY_FIELDS = Set.of(
            field(JubjubSigningProfile.class,
                    "FIXED_LIMB_DETERMINISTIC_V1_COMPATIBILITY",
                    "Lcom/bloxbean/cardano/zeroj/circuit/lib/jubjub/"
                            + "JubjubSigningProfile;"),
            field(JubjubSigningProfile.class,
                    "HEDGED_DEDICATED_HOST_CANDIDATE",
                    "Lcom/bloxbean/cardano/zeroj/circuit/lib/jubjub/"
                            + "JubjubSigningProfile;")
    );

    @Test
    @DisplayName("the complete hardened call graph matches the explicit allow-list")
    void hardenedCallGraphIsAllowListed() throws Exception {
        List<String> violations = architectureViolations(HARDENED_SECRET_CLASSES);
        assertTrue(violations.isEmpty(), () -> String.join("\n", violations));
    }

    @Test
    @DisplayName("the policy rejects boxing and data-dependent collection dependencies")
    void rejectsBoxingAndCollections() throws Exception {
        List<String> violations =
                architectureViolations(List.of(ForbiddenBoxingArchitectureFixture.class));
        assertTrue(violations.stream().anyMatch(
                        violation -> violation.contains("java/lang/Long")),
                () -> String.join("\n", violations));
        assertTrue(violations.stream().anyMatch(
                        violation -> violation.contains("java/util/LinkedHashMap")),
                () -> String.join("\n", violations));
    }

    @Test
    @DisplayName("the policy rejects a new call across an approved boundary")
    void rejectsUnapprovedBoundaryMethod() throws Exception {
        List<String> violations = architectureViolations(
                List.of(ForbiddenBoundaryEdgeArchitectureFixture.class));
        assertTrue(violations.stream().anyMatch(
                        violation -> violation.contains("JubjubPublicAdapter.scalar")),
                () -> String.join("\n", violations));
    }

    private static List<String> architectureViolations(
            List<Class<?>> rootTypes) throws Exception {
        Set<String> hardenedRoots = new HashSet<>();
        for (Class<?> type : rootTypes) {
            hardenedRoots.add(internalName(type));
        }

        ArrayDeque<String> pending = new ArrayDeque<>(hardenedRoots);
        Set<String> visited = new HashSet<>();
        List<String> violations = new ArrayList<>();
        while (!pending.isEmpty()) {
            String current = pending.removeFirst();
            if (!visited.add(current)) {
                continue;
            }
            HardenedBytecodePolicy.ClassFile bytecode = read(current);
            for (String dependency : bytecode.classes()) {
                if (dependency.startsWith("[")) {
                    continue;
                }
                if (isHardened(dependency, hardenedRoots)) {
                    pending.addLast(dependency);
                } else if (APPROVED_BOUNDARY_CLASSES.contains(dependency)) {
                    // Exact calls and field reads are checked below.
                } else if (!ALLOWED_EXTERNAL_CLASSES.contains(dependency)) {
                    violations.add(current + " reaches unclassified class " + dependency);
                }
            }

            for (MemberRef method : bytecode.methods()) {
                if (isHardened(method.owner(), hardenedRoots)
                        || isAllowedArrayMethod(method)) {
                    continue;
                }
                if (APPROVED_BOUNDARY_CLASSES.contains(method.owner())) {
                    if (!APPROVED_BOUNDARY_METHODS.contains(method)) {
                        violations.add(current + " calls unapproved boundary method "
                                + method);
                    }
                } else if (!ALLOWED_EXTERNAL_METHODS.contains(method)) {
                    violations.add(current + " calls unapproved external method " + method);
                }
            }

            for (MemberRef field : bytecode.fields()) {
                if (isHardened(field.owner(), hardenedRoots)) {
                    continue;
                }
                if (APPROVED_BOUNDARY_CLASSES.contains(field.owner())) {
                    if (!APPROVED_BOUNDARY_FIELDS.contains(field)) {
                        violations.add(current + " reads unapproved boundary field " + field);
                    }
                } else {
                    violations.add(current + " reads unapproved external field " + field);
                }
            }
        }
        return violations;
    }

    private static boolean isHardened(String dependency, Set<String> roots) {
        return roots.stream().anyMatch(
                root -> dependency.equals(root) || dependency.startsWith(root + "$"));
    }

    private static boolean isAllowedArrayMethod(MemberRef method) {
        return method.owner().startsWith("[")
                && method.name().equals("clone")
                && method.descriptor().equals("()Ljava/lang/Object;");
    }

    private static MemberRef method(
            Class<?> owner, String name, String descriptor) {
        return method(internalName(owner), name, descriptor);
    }

    private static MemberRef method(
            String owner, String name, String descriptor) {
        return new MemberRef(owner, name, descriptor);
    }

    private static MemberRef field(
            Class<?> owner, String name, String descriptor) {
        return new MemberRef(internalName(owner), name, descriptor);
    }

    private static String internalName(Class<?> type) {
        return type.getName().replace('.', '/');
    }
}

final class ForbiddenBoxingArchitectureFixture {
    private ForbiddenBoxingArchitectureFixture() {
    }

    static long remember(long secret) {
        Map<Long, Long> values = new LinkedHashMap<>();
        values.put(secret, secret);
        return values.get(secret);
    }
}

final class ForbiddenBoundaryEdgeArchitectureFixture {
    private ForbiddenBoundaryEdgeArchitectureFixture() {
    }

    static void convertSecret(long[] secret, byte[] bytes, long[] work) {
        JubjubPublicAdapter.scalar(secret, 0, bytes, 0, work, 0);
    }
}
