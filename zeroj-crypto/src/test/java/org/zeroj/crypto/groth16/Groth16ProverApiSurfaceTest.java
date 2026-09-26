package org.zeroj.crypto.groth16;

import org.zeroj.api.R1CSConstraint;
import org.zeroj.api.R1CSFlat;
import org.zeroj.api.TrustedSetupPolicy;
import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.crypto.msm.FlatScalars;
import org.zeroj.crypto.plonk.PlonKProof;
import org.zeroj.crypto.plonk.PlonKProofBLS381;
import org.zeroj.crypto.plonk.PlonKProverBLS381;
import org.zeroj.crypto.setup.Groth16Setup;
import org.zeroj.crypto.setup.Groth16SetupBLS381;
import org.zeroj.crypto.setup.PowersOfTau;
import org.zeroj.crypto.setup.PowersOfTauBLS381;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0046 (issue #50): the normal public Groth16 proving facade cannot produce an unblinded
 * proof, and the deterministic prover that the byte-equality differential tests use is not
 * product code.
 *
 * <p>Three layers of evidence, each with a stated limit:</p>
 * <ol>
 *   <li><b>Frozen surface.</b> The exact public method set of the four Groth16 facade classes is
 *       pinned, and so is the set of every public or protected method in the {@code groth16} and
 *       {@code plonk} packages (nested types included) that returns a proof type. A new
 *       proof-producing public method anywhere in those packages fails this test until it is
 *       added to the allowlist deliberately, after checking that it draws its blinders from
 *       {@code Groth16ProverBLS381.secureRandomBlinders()} (or a caller-supplied CSPRNG for
 *       PlonK). A public method that returns something other than a proof type is not caught
 *       by the second list; the name and {@code BlinderSource} scans below are the net for that.</li>
 *   <li><b>Seam visibility.</b> {@code BlinderSource} and {@code proveBlinded} — the only way to
 *       fix the blinders — are non-public, and the main artifact has no method that fixes them
 *       itself. The fixture is loaded from a different code source than the prover.</li>
 *   <li><b>Behaviour.</b> With the explicit-randomness setup and an independent Lagrange
 *       evaluation, the unblinded {@code A = [alpha + sum a_i u_i(tau)]_1} and
 *       {@code B = [beta + sum a_i v_i(tau)]_2} are computed in the test. Every public BLS12-381
 *       prove entry point (six on {@code Groth16ProverBLS381}, three on {@code Groth16Keys}, two
 *       on {@code Groth16Pipeline}) must produce {@code A}/{@code B} different from those values
 *       and two calls must differ from each other; the fixture must reproduce exactly those
 *       values, be deterministic, and still pairing-verify. The legacy BN254 prover is checked
 *       for distinct proofs across calls only (no independent unblinded reference is computed for
 *       it). PlonK blinding is out of scope here (triage C-04).</li>
 * </ol>
 */
class Groth16ProverApiSurfaceTest {

    // ---- 1. frozen public surface -------------------------------------------------------------

    private static final Set<String> PROVER_SURFACE = Set.of(
            "prove(Groth16ProvingKeyBLS381,BigInteger[],List,int)",
            "prove(Groth16ProvingKeyBLS381,BigInteger[],List,int,int)",
            "heapReaders(Groth16ProvingKeyBLS381)",
            "proveWithReaders(Groth16ProvingKeyBLS381,G1Readers,BigInteger[],List,int,int)",
            "proveWithReaders(Groth16ProvingKeyBLS381,G1Readers,ProverBackend,BigInteger[],List,int,int)",
            "proveWithHCoeffs(Groth16ProvingKeyBLS381,G1Readers,ProverBackend,BigInteger[],BigInteger[])",
            "proveWithHCoeffs(Groth16ProvingKeyBLS381,G1Readers,ProverBackend,FlatScalars,FlatScalars)",
            "computeH(List,BigInteger[],int,int)",
            "computeH(R1CSFlat,BigInteger[],int,int)",
            "computeHFlat(R1CSFlat,FlatScalars,int,int)");

    private static final Set<String> KEYS_SURFACE = Set.of(
            "setupInMemory(List,int,int,BigInteger)",
            "setupToStore(R1CSFlat,int,int,BigInteger,Path,boolean)",
            "load(Path)",
            "of(Loaded)",
            "of(SetupResult)",
            "prove(BigInteger[],List)",
            "prove(ProverBackend,BigInteger[],List)",
            "prove(ProverBackend,FlatScalars,R1CSFlat,int)",
            "pk()", "readers()", "gammaG2()", "ic()", "domain()", "numWires()", "circuitFingerprint()",
            "close()");

    private static final Set<String> PIPELINE_SURFACE = Set.of(
            "fingerprint(int,int,int)",
            "isExactFingerprint(String)",
            "parseFingerprint(String)",
            "setup(Compiled,BigInteger,Path,boolean)",
            "setup(Compiled,BigInteger,Path,boolean,Progress)",
            "cacheMatches(Path,String)",
            "prove(Groth16Keys,Path,String,Supplier,Supplier,int,ProverBackend)",
            "prove(Groth16Keys,Path,String,Supplier,Supplier,int,ProverBackend,Progress)",
            "estimateProvePhaseHeapBytes(int,int)");

    /** Legacy BN254 prover (opt-in only, ADR-0025); its unused unblinded method was removed too. */
    private static final Set<String> LEGACY_PROVER_SURFACE = Set.of(
            "prove(Groth16ProvingKey,BigInteger[],List,int)",
            "prove(Groth16ProvingKey,BigInteger[],List,int,int)",
            "validateWitness(List,BigInteger[],int)");

    /**
     * Every public/protected method of the {@code groth16} and {@code plonk} packages that returns
     * a proof type. Each entry is a blinded (Groth16: {@code secureRandomBlinders}; PlonK: fresh
     * or caller-supplied {@code SecureRandom}) or delegating path; add to this list only after
     * checking that.
     */
    private static final Set<String> PROOF_PRODUCERS = Set.of(
            "Groth16ProverBLS381#prove(Groth16ProvingKeyBLS381,BigInteger[],List,int)",
            "Groth16ProverBLS381#prove(Groth16ProvingKeyBLS381,BigInteger[],List,int,int)",
            "Groth16ProverBLS381#proveWithReaders(Groth16ProvingKeyBLS381,G1Readers,BigInteger[],List,int,int)",
            "Groth16ProverBLS381#proveWithReaders(Groth16ProvingKeyBLS381,G1Readers,ProverBackend,BigInteger[],List,int,int)",
            "Groth16ProverBLS381#proveWithHCoeffs(Groth16ProvingKeyBLS381,G1Readers,ProverBackend,BigInteger[],BigInteger[])",
            "Groth16ProverBLS381#proveWithHCoeffs(Groth16ProvingKeyBLS381,G1Readers,ProverBackend,FlatScalars,FlatScalars)",
            "Groth16Keys#prove(BigInteger[],List)",
            "Groth16Keys#prove(ProverBackend,BigInteger[],List)",
            "Groth16Keys#prove(ProverBackend,FlatScalars,R1CSFlat,int)",
            "Groth16Pipeline#prove(Groth16Keys,Path,String,Supplier,Supplier,int,ProverBackend)",
            "Groth16Pipeline#prove(Groth16Keys,Path,String,Supplier,Supplier,int,ProverBackend,Progress)",
            "Groth16Prover#prove(Groth16ProvingKey,BigInteger[],List,int)",
            "Groth16Prover#prove(Groth16ProvingKey,BigInteger[],List,int,int)",
            "PlonKProver#prove(PlonKProvingKey,MontFr254[],MontFr254[],MontFr254[],BigInteger[])",
            "PlonKProverBLS381#prove(PlonKProvingKeyBLS381,MontFr381[],MontFr381[],MontFr381[],BigInteger[])",
            "PlonKProverBLS381#prove(PlonKProvingKeyBLS381,MontFr381[],MontFr381[],MontFr381[],BigInteger[],SecureRandom)",
            "PlonKProverBLS381#proveCardano(PlonKProvingKeyBLS381,MontFr381[],MontFr381[],MontFr381[],BigInteger[])",
            "PlonKProverBLS381#proveCardano(PlonKProvingKeyBLS381,MontFr381[],MontFr381[],MontFr381[],BigInteger[],SecureRandom)",
            "PlonKProverBLS381#proveCardanoMpi(PlonKProvingKeyBLS381,MontFr381[],MontFr381[],MontFr381[],BigInteger[])",
            "PlonKProverBLS381#proveCardanoMpi(PlonKProvingKeyBLS381,MontFr381[],MontFr381[],MontFr381[],BigInteger[],SecureRandom)");

    private static final Set<Class<?>> PROOF_TYPES =
            Set.of(Groth16ProofBLS381.class, Groth16Proof.class, PlonKProofBLS381.class, PlonKProof.class);

    @Test
    void publicProverFacadeIsExactlyTheAllowlistedSurface() {
        assertEquals(new TreeSet<>(PROVER_SURFACE), publicMethods(Groth16ProverBLS381.class),
                "Groth16ProverBLS381 public methods changed: review the blinder policy before updating");
        assertEquals(new TreeSet<>(KEYS_SURFACE), publicMethods(Groth16Keys.class),
                "Groth16Keys public methods changed: review the blinder policy before updating");
        assertEquals(new TreeSet<>(PIPELINE_SURFACE), publicMethods(Groth16Pipeline.class),
                "Groth16Pipeline public methods changed: review the blinder policy before updating");
        assertEquals(new TreeSet<>(LEGACY_PROVER_SURFACE), publicMethods(Groth16Prover.class),
                "Groth16Prover (BN254) public methods changed: review the blinder policy before updating");
    }

    @Test
    void proofProducingPublicMethodsAreExactlyTheAllowlist() throws Exception {
        TreeSet<String> found = new TreeSet<>();
        for (Class<?> c : mainProverClasses()) {
            for (Method m : c.getDeclaredMethods()) {
                int mods = m.getModifiers();
                if (m.isSynthetic() || !(Modifier.isPublic(mods) || Modifier.isProtected(mods))) continue;
                if (PROOF_TYPES.contains(m.getReturnType())) found.add(c.getSimpleName() + "#" + signature(m));
            }
        }
        assertEquals(new TreeSet<>(PROOF_PRODUCERS), found,
                "a public proof-producing method appeared or vanished in the groth16/plonk packages: "
                        + "review its blinder policy before updating the allowlist");
    }

    private static TreeSet<String> publicMethods(Class<?> c) {
        return Arrays.stream(c.getDeclaredMethods())
                .filter(m -> Modifier.isPublic(m.getModifiers()) && !m.isSynthetic())
                .map(Groth16ProverApiSurfaceTest::signature)
                .collect(Collectors.toCollection(TreeSet::new));
    }

    private static String signature(Method m) {
        return m.getName() + Arrays.stream(m.getParameterTypes())
                .map(Class::getSimpleName)
                .collect(Collectors.joining(",", "(", ")"));
    }

    // ---- 2. seams and package scan ------------------------------------------------------------

    private static final String GROTH16_PKG = "org/zeroj/crypto/groth16/";
    private static final String PLONK_PKG = "org/zeroj/crypto/plonk/";
    private static final List<String> FORBIDDEN_NAME_FRAGMENTS =
            List.of("unblinded", "deterministic", "fixedblinder", "withblinders", "noblind", "zeroblind");

    @Test
    void noPublicMemberOfTheProverPackagesNamesOrAcceptsFixedBlinders() throws Exception {
        List<Class<?>> classes = mainProverClasses();
        assertTrue(classes.size() >= 40, "scan must cover the groth16 + plonk packages; found " + classes.size());
        assertTrue(classes.contains(Groth16ProverBLS381.class));
        assertTrue(classes.contains(Groth16Keys.class));
        assertTrue(classes.contains(PlonKProverBLS381.class));
        assertFalse(classes.contains(Groth16UnblindedTestProver.class),
                "the unblinded test prover must not be part of the main artifact");

        List<String> offenders = new ArrayList<>();
        for (Class<?> c : classes) {
            List<Executable> members = new ArrayList<>();
            members.addAll(Arrays.asList(c.getDeclaredMethods()));
            members.addAll(Arrays.asList(c.getDeclaredConstructors()));
            for (Executable e : members) {
                int mods = e.getModifiers();
                if (!Modifier.isPublic(mods) && !Modifier.isProtected(mods)) continue;
                String name = e.getName().toLowerCase(Locale.ROOT);
                boolean badName = FORBIDDEN_NAME_FRAGMENTS.stream().anyMatch(name::contains);
                boolean badParam = Arrays.stream(e.getParameterTypes())
                        .anyMatch(t -> t == Groth16ProverBLS381.BlinderSource.class);
                if (badName || badParam) offenders.add(c.getName() + "#" + e);
            }
        }
        assertEquals(List.of(), offenders, "public/protected fixed-blinder members in the main artifact");
    }

    @Test
    void blinderSeamsAreNotPublicAndMainHasNoFixedBlinderPath() throws Exception {
        assertFalse(Modifier.isPublic(Groth16ProverBLS381.BlinderSource.class.getModifiers()),
                "BlinderSource must stay package-private (ADR-0045/ADR-0046 test seam)");
        Method blinded = Groth16ProverBLS381.class.getDeclaredMethod("proveBlinded",
                Groth16ProvingKeyBLS381.class, Groth16ProverBLS381.G1Readers.class, ProverBackend.class,
                FlatScalars.class, FlatScalars.class, Groth16ProverBLS381.BlinderSource.class);
        assertFalse(Modifier.isPublic(blinded.getModifiers()) || Modifier.isProtected(blinded.getModifiers()),
                "proveBlinded (caller-supplied BlinderSource) must stay package-private");
        // The r = s = 0 choice lives in the fixture only: the prover has no method of any visibility
        // that fixes the blinders (ADR-0046 Z3).
        List<String> fixed = Arrays.stream(Groth16ProverBLS381.class.getDeclaredMethods())
                .map(Method::getName)
                .filter(n -> FORBIDDEN_NAME_FRAGMENTS.stream().anyMatch(n.toLowerCase(Locale.ROOT)::contains))
                .toList();
        assertEquals(List.of(), fixed, "Groth16ProverBLS381 must not regain a fixed-blinder prove");
    }

    @Test
    void unblindedTestProverIsNotShippedWithTheProver() {
        URL prover = Groth16ProverBLS381.class.getProtectionDomain().getCodeSource().getLocation();
        URL fixture = Groth16UnblindedTestProver.class.getProtectionDomain().getCodeSource().getLocation();
        // The inequality is the guarantee; the path check is a sanity net for Gradle-driven runs.
        assertNotEquals(prover, fixture,
                "Groth16UnblindedTestProver must come from the test-fixtures output, not the main artifact");
        assertTrue(fixture.toString().contains("testFixtures") || fixture.toString().contains("test-fixtures"),
                "unexpected fixture location: " + fixture);
    }

    /** Every class of the main artifact (classes directory or jar) in the two prover packages. */
    private static List<Class<?>> mainProverClasses() throws Exception {
        URL location = Groth16ProverBLS381.class.getProtectionDomain().getCodeSource().getLocation();
        Path root = Path.of(location.toURI());
        List<String> entries = new ArrayList<>();
        if (Files.isDirectory(root)) {
            try (Stream<Path> files = Files.walk(root)) {
                files.filter(p -> p.toString().endsWith(".class"))
                        .map(p -> root.relativize(p).toString().replace('\\', '/'))
                        .forEach(entries::add);
            }
        } else {
            try (JarFile jar = new JarFile(root.toFile())) {
                jar.stream().map(ZipEntry::getName).filter(n -> n.endsWith(".class")).forEach(entries::add);
            }
        }
        List<Class<?>> classes = new ArrayList<>();
        for (String entry : entries) {
            if (!entry.startsWith(GROTH16_PKG) && !entry.startsWith(PLONK_PKG)) continue;
            String className = entry.substring(0, entry.length() - ".class".length()).replace('/', '.');
            classes.add(Class.forName(className, false, Groth16ProverBLS381.class.getClassLoader()));
        }
        return classes;
    }

    // ---- 3. behaviour: public paths are blinded, the fixture is exactly unblinded ---------------

    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger FR = MontFr381.modulus();
    private static final int NUM_WIRES = 4;
    private static final int NUM_PUBLIC = 1;
    /** {@code a * b = c} and {@code 1 * 1 = 1} over wires {@code [1, c, a, b]}. */
    private static final List<R1CSConstraint> RELATION = List.of(
            new R1CSConstraint(Map.of(2, ONE), Map.of(3, ONE), Map.of(1, ONE)),
            new R1CSConstraint(Map.of(0, ONE), Map.of(0, ONE), Map.of(0, ONE)));
    private static final BigInteger[] WITNESS =
            {ONE, BigInteger.valueOf(33), BigInteger.valueOf(3), BigInteger.valueOf(11)};

    private static Groth16SetupBLS381.SetupResult setup;
    private static JacobianG1BLS381.AffineG1 expectedUnblindedA;
    private static JacobianG2BLS381.AffineG2 expectedUnblindedB;

    @BeforeAll
    static void setUp() {
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
        BigInteger tau = PowersOfTauBLS381.generate(4).tauScalar();
        var rng = new SecureRandom();
        BigInteger alpha = Groth16InfinityIcProfileTest.nonzeroScalar(rng);
        BigInteger beta = Groth16InfinityIcProfileTest.nonzeroScalar(rng);
        BigInteger gamma = Groth16InfinityIcProfileTest.nonzeroScalar(rng);
        BigInteger delta = Groth16InfinityIcProfileTest.nonzeroScalar(rng);
        setup = Groth16SetupBLS381.setup(RELATION, NUM_WIRES, NUM_PUBLIC, tau, alpha, beta, gamma, delta);

        // Independent of the prover: A = [alpha + sum_i a_i u_i(tau)]_1 with u_0 = L_1, u_2 = L_0;
        // B = [beta + sum_i a_i v_i(tau)]_2 with v_0 = L_1, v_3 = L_0 (Groth16 §3.1 with r = s = 0).
        BigInteger[] l = Groth16InfinityIcProfileTest.lagrangeAt(tau, 4);
        BigInteger aScalar = alpha.add(l[1]).add(l[0].multiply(WITNESS[2])).mod(FR);
        BigInteger bScalar = beta.add(l[1]).add(l[0].multiply(WITNESS[3])).mod(FR);
        expectedUnblindedA = JacobianG1BLS381.GENERATOR.scalarMul(aScalar).toAffine();
        expectedUnblindedB = JacobianG2BLS381.GENERATOR.scalarMul(bScalar).toAffine();
    }

    private static R1CSFlat flatRelation() {
        var b = R1CSFlat.builder();
        for (var c : RELATION) b.add(c.a(), c.b(), c.c());
        return b.build();
    }

    /** One proof from each public BLS12-381 prove entry point (11 of them). */
    private static List<Groth16ProofBLS381> oneProofPerPublicPath() throws Exception {
        var pk = setup.provingKey();
        int domain = Groth16ProvingKeyBLS381.count(pk.pointsH());
        var readers = Groth16ProverBLS381.heapReaders(pk);
        BigInteger[] h = Groth16ProverBLS381.computeH(RELATION, WITNESS, RELATION.size(), domain);
        FlatScalars packedWitness = FlatScalars.pack(WITNESS, WITNESS.length);
        R1CSFlat flat = flatRelation();

        List<Groth16ProofBLS381> proofs = new ArrayList<>();
        proofs.add(Groth16ProverBLS381.prove(pk, WITNESS, RELATION, NUM_WIRES));
        proofs.add(Groth16ProverBLS381.prove(pk, WITNESS, RELATION, NUM_WIRES, domain));
        proofs.add(Groth16ProverBLS381.proveWithReaders(pk, readers, WITNESS, RELATION, NUM_WIRES, domain));
        proofs.add(Groth16ProverBLS381.proveWithReaders(pk, readers, ProverBackend.PURE_JAVA,
                WITNESS, RELATION, NUM_WIRES, domain));
        proofs.add(Groth16ProverBLS381.proveWithHCoeffs(pk, readers, ProverBackend.PURE_JAVA, WITNESS, h));
        proofs.add(Groth16ProverBLS381.proveWithHCoeffs(pk, readers, ProverBackend.PURE_JAVA,
                packedWitness, FlatScalars.pack(h, h.length)));
        try (var keys = Groth16Keys.of(setup)) {
            proofs.add(keys.prove(WITNESS, RELATION));
            proofs.add(keys.prove(ProverBackend.PURE_JAVA, WITNESS, RELATION));
            proofs.add(keys.prove(ProverBackend.PURE_JAVA, packedWitness, flat, 0));
            // Pipeline: no constraint cache and an unknown (null) fingerprint — an in-heap key is
            // unbound, and the pipeline rightly refuses an exact fingerprint against an unbound bundle.
            var compiled = new Groth16Pipeline.Compiled(flat, RELATION.size(), NUM_WIRES, NUM_PUBLIC);
            proofs.add(Groth16Pipeline.prove(keys, null, null, () -> compiled,
                    () -> FlatScalars.pack(WITNESS, WITNESS.length), 0, ProverBackend.PURE_JAVA));
            proofs.add(Groth16Pipeline.prove(keys, null, null, () -> compiled,
                    () -> FlatScalars.pack(WITNESS, WITNESS.length), 0, ProverBackend.PURE_JAVA,
                    new Groth16Pipeline.Progress() {}));
        }
        assertEquals(11, proofs.size());
        return proofs;
    }

    @Test
    void everyPublicProvePathIsBlindedAndRandomized() throws Exception {
        List<Groth16ProofBLS381> proofs = new ArrayList<>(oneProofPerPublicPath());
        proofs.addAll(oneProofPerPublicPath());
        assertEquals(22, proofs.size());
        // Distinct blinders on every call: no proof is the unblinded one and no two proofs share
        // A, B, or C (collision probability on the order of 1/r per pair).
        for (int i = 0; i < proofs.size(); i++) {
            assertFalse(sameG1(proofs.get(i).a(), expectedUnblindedA), "proof " + i + ": A is unblinded (r = 0)");
            assertFalse(sameG2(proofs.get(i).b(), expectedUnblindedB), "proof " + i + ": B is unblinded (s = 0)");
            for (int j = i + 1; j < proofs.size(); j++) {
                assertFalse(sameG1(proofs.get(i).a(), proofs.get(j).a()), "proofs " + i + "/" + j + " share A");
                assertFalse(sameG2(proofs.get(i).b(), proofs.get(j).b()), "proofs " + i + "/" + j + " share B");
                assertFalse(sameG1(proofs.get(i).c(), proofs.get(j).c()), "proofs " + i + "/" + j + " share C");
            }
            assertTrue(Groth16ProofPointResamplingTest.pairingVerify(setup, proofs.get(i), WITNESS[1]),
                    "proof " + i + " must verify");
        }
    }

    @Test
    void unblindedTestProverIsDeterministicNotZeroKnowledgeAndStillVerifies() {
        var pk = setup.provingKey();
        int domain = Groth16ProvingKeyBLS381.count(pk.pointsH());
        var readers = Groth16ProverBLS381.heapReaders(pk);

        var first = Groth16UnblindedTestProver.proveUnblinded(pk, readers, ProverBackend.PURE_JAVA,
                WITNESS, RELATION, domain);
        var second = Groth16UnblindedTestProver.proveUnblinded(pk, readers, ProverBackend.PURE_JAVA,
                WITNESS, RELATION, domain);

        assertTrue(sameG1(first.a(), expectedUnblindedA), "unblinded A must equal [alpha + sum a_i u_i(tau)]_1");
        assertTrue(sameG2(first.b(), expectedUnblindedB), "unblinded B must equal [beta + sum a_i v_i(tau)]_2");
        assertTrue(sameG1(first.a(), second.a()) && sameG2(first.b(), second.b()) && sameG1(first.c(), second.c()),
                "the fixture must be a deterministic function of (key, witness)");
        assertTrue(Groth16ProofPointResamplingTest.pairingVerify(setup, first, WITNESS[1]),
                "the unblinded proof must still verify (differential oracle)");

        // Same witness, different blinders: the public path must not reproduce the fixture's proof.
        var blinded = Groth16ProverBLS381.prove(pk, WITNESS, RELATION, NUM_WIRES);
        assertFalse(sameG1(blinded.a(), first.a()));
        assertFalse(sameG1(blinded.c(), first.c()));
    }

    /** The opt-in BN254 prover keeps fresh blinders too: four proofs of one witness are all distinct. */
    @Test
    void legacyBn254ProveIsRandomized() {
        BigInteger tau = PowersOfTau.generate(4).tauScalar();
        var pk = Groth16Setup.setup(RELATION, NUM_WIRES, NUM_PUBLIC, tau);
        int domain = pk.pointsH().length;
        List<Groth16Proof> proofs = List.of(
                Groth16Prover.prove(pk, WITNESS, RELATION, NUM_WIRES),
                Groth16Prover.prove(pk, WITNESS, RELATION, NUM_WIRES),
                Groth16Prover.prove(pk, WITNESS, RELATION, NUM_WIRES, domain),
                Groth16Prover.prove(pk, WITNESS, RELATION, NUM_WIRES, domain));
        for (int i = 0; i < proofs.size(); i++) {
            for (int j = i + 1; j < proofs.size(); j++) {
                assertFalse(proofs.get(i).a().xBigInt().equals(proofs.get(j).a().xBigInt()),
                        "BN254 proofs " + i + "/" + j + " share A");
                assertFalse(proofs.get(i).c().xBigInt().equals(proofs.get(j).c().xBigInt()),
                        "BN254 proofs " + i + "/" + j + " share C");
            }
        }
    }

    // ---- helpers ------------------------------------------------------------------------------

    private static boolean sameG1(JacobianG1BLS381.AffineG1 p, JacobianG1BLS381.AffineG1 q) {
        return p.xBigInt().equals(q.xBigInt()) && p.yBigInt().equals(q.yBigInt());
    }

    private static boolean sameG2(JacobianG2BLS381.AffineG2 p, JacobianG2BLS381.AffineG2 q) {
        return p.x().reBigInt().equals(q.x().reBigInt()) && p.x().imBigInt().equals(q.x().imBigInt())
                && p.y().reBigInt().equals(q.y().reBigInt()) && p.y().imBigInt().equals(q.y().imBigInt());
    }
}
