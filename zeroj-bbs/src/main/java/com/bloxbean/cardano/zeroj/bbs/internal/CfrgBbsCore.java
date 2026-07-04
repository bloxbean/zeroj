package com.bloxbean.cardano.zeroj.bbs.internal;

import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Hash;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Provider;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * CFRG BBS draft-10 algorithms for supported BLS12-381 ciphersuites.
 */
public final class CfrgBbsCore {
    private static final BigInteger R = BbsCodec.R;

    private CfrgBbsCore() {}

    public record Generators(G1Point q1, List<G1Point> h) {
        public Generators {
            BbsCodec.requireNonIdentity(q1, "Q_1");
            h = List.copyOf(Objects.requireNonNull(h, "H generators required"));
            for (G1Point point : h) {
                BbsCodec.requireNonIdentity(point, "H generator");
            }
        }

        public int count() {
            return h.size() + 1;
        }
    }

    record ProofInitResult(
            G1Point aBar,
            G1Point bBar,
            G1Point d,
            G1Point t1,
            G1Point t2,
            BigInteger domain
    ) {}

    public static BigInteger keyGen(BbsCiphersuite ciphersuite, byte[] keyMaterial, byte[] keyInfo) {
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        Objects.requireNonNull(keyMaterial, "key material required");
        keyInfo = BbsCodec.copy(keyInfo);
        if (keyMaterial.length < 32) {
            throw new IllegalArgumentException("BBS key material must be at least 32 bytes");
        }
        if (keyInfo.length > 65535) {
            throw new IllegalArgumentException("BBS key info must be at most 65535 bytes");
        }

        byte[] deriveInput = BbsCodec.concat(keyMaterial, BbsCodec.i2osp(keyInfo.length, 2), keyInfo);
        // Draft-10 interface vectors bind KeyGen to the BBS API identifier, not only the ciphersuite id.
        BigInteger sk = hashToScalar(deriveInput, dst(ciphersuite.apiId(), "KEYGEN_DST_"), ciphersuite);
        return BbsCodec.requireNonZeroScalar(sk, "BBS secret key");
    }

    public static byte[] skToPk(BigInteger secretKey, Bls12381Provider bls) {
        BbsCodec.requireNonZeroScalar(secretKey, "BBS secret key");
        G2Point publicKey = Objects.requireNonNull(bls, "BLS provider required")
                .g2SecretScalarMul(bls.g2Generator(), secretKey);
        return BbsCodec.publicKeyToOctets(publicKey);
    }

    public static List<BigInteger> messagesToScalars(List<byte[]> messages, BbsCiphersuite ciphersuite) {
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        List<byte[]> copiedMessages = BbsCodec.copyMessages(messages);
        byte[] mapDst = dst(ciphersuite.apiId(), "MAP_MSG_TO_SCALAR_AS_HASH_");
        List<BigInteger> scalars = new ArrayList<>(copiedMessages.size());
        for (byte[] message : copiedMessages) {
            scalars.add(hashToScalar(message, mapDst, ciphersuite));
        }
        return List.copyOf(scalars);
    }

    public static Generators createGenerators(int count, BbsCiphersuite ciphersuite, Bls12381Provider bls) {
        if (count < 1) {
            throw new IllegalArgumentException("BBS generator count must be at least 1");
        }
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        Objects.requireNonNull(bls, "BLS provider required");

        byte[] apiId = ciphersuite.apiId();
        byte[] seedDst = dst(apiId, "SIG_GENERATOR_SEED_");
        byte[] generatorDst = dst(apiId, "SIG_GENERATOR_DST_");
        byte[] generatorSeed = dst(apiId, "MESSAGE_GENERATOR_SEED");

        byte[] v = expandMessage(generatorSeed, seedDst, ciphersuite.expandLen(), ciphersuite);
        List<G1Point> points = new ArrayList<>(count);
        for (int i = 1; i <= count; i++) {
            v = expandMessage(BbsCodec.concat(v, BbsCodec.i2osp(i, 8)), seedDst, ciphersuite.expandLen(), ciphersuite);
            points.add(BbsCodec.requireNonIdentity(hashToG1(v, generatorDst, ciphersuite, bls), "BBS generator"));
        }
        return new Generators(points.getFirst(), points.subList(1, points.size()));
    }

    public static BigInteger calculateDomain(
            byte[] publicKey,
            Generators generators,
            byte[] header,
            BbsCiphersuite ciphersuite
    ) {
        Objects.requireNonNull(publicKey, "public key required");
        Objects.requireNonNull(generators, "generators required");
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        header = BbsCodec.copy(header);

        List<Object> domArray = new ArrayList<>(generators.count() + 1);
        domArray.add((long) generators.h().size());
        domArray.add(generators.q1());
        domArray.addAll(generators.h());
        byte[] domOcts = BbsCodec.concat(BbsCodec.serialize(domArray.toArray()), ciphersuite.apiId());
        byte[] domInput = BbsCodec.concat(publicKey, domOcts, BbsCodec.i2osp(header.length, 8), header);
        return hashToScalar(domInput, dst(ciphersuite.apiId(), "H2S_"), ciphersuite);
    }

    public static G1Point calculateB(
            Generators generators,
            BigInteger domain,
            List<BigInteger> messages,
            BbsCiphersuite ciphersuite
    ) {
        return computeB(generators, domain, messages, ciphersuite);
    }

    public static byte[] sign(
            BigInteger secretKey,
            byte[] publicKey,
            List<byte[]> messages,
            byte[] header,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls
    ) {
        BbsCodec.requireNonZeroScalar(secretKey, "BBS secret key");
        BbsCodec.octetsToPublicKey(publicKey);
        List<BigInteger> messageScalars = messagesToScalars(messages, ciphersuite);
        Generators generators = createGenerators(messageScalars.size() + 1, ciphersuite, bls);
        BbsCodec.SignatureParts signature = coreSign(
                secretKey, publicKey, generators, BbsCodec.copy(header), messageScalars, ciphersuite, bls);
        return BbsCodec.signatureToOctets(signature);
    }

    public static boolean verify(
            byte[] publicKey,
            byte[] signature,
            List<byte[]> messages,
            byte[] header,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls
    ) {
        try {
            List<BigInteger> messageScalars = messagesToScalars(messages, ciphersuite);
            Generators generators = createGenerators(messageScalars.size() + 1, ciphersuite, bls);
            return coreVerify(publicKey, signature, generators, BbsCodec.copy(header), messageScalars, ciphersuite, bls);
        } catch (RuntimeException e) {
            return false;
        }
    }

    public static byte[] proofGen(
            byte[] publicKey,
            byte[] signature,
            List<byte[]> messages,
            byte[] header,
            byte[] presentationHeader,
            int[] disclosedIndexes,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls,
            SecureRandom random
    ) {
        Objects.requireNonNull(random, "secure random required");
        int messageCount = Objects.requireNonNull(messages, "messages required").size();
        int[] indexes = validateDisclosedIndexes(disclosedIndexes, messageCount);
        int undisclosedCount = messageCount - indexes.length;
        return proofGenWithRandomScalars(
                publicKey,
                signature,
                messages,
                header,
                presentationHeader,
                indexes,
                ciphersuite,
                bls,
                randomScalars(5 + undisclosedCount, ciphersuite, random));
    }

    public static byte[] proofGenWithRandomScalars(
            byte[] publicKey,
            byte[] signature,
            List<byte[]> messages,
            byte[] header,
            byte[] presentationHeader,
            int[] disclosedIndexes,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls,
            List<BigInteger> randomScalars
    ) {
        List<BigInteger> messageScalars = messagesToScalars(messages, ciphersuite);
        int[] indexes = validateDisclosedIndexes(disclosedIndexes, messageScalars.size());
        Generators generators = createGenerators(messageScalars.size() + 1, ciphersuite, bls);
        if (!coreVerify(publicKey, signature, generators, BbsCodec.copy(header), messageScalars, ciphersuite, bls, true)) {
            throw new IllegalArgumentException("Cannot generate BBS proof for an invalid signature");
        }

        BbsCodec.SignatureParts signatureParts = BbsCodec.octetsToSignature(signature, ciphersuite);
        int[] undisclosedIndexes = undisclosedIndexes(messageScalars.size(), indexes);
        List<BigInteger> disclosedMessages = select(messageScalars, indexes);
        List<BigInteger> undisclosedMessages = select(messageScalars, undisclosedIndexes);
        List<BigInteger> proofRandomScalars = validateRandomScalars(randomScalars, 5 + undisclosedIndexes.length);

        ProofInitResult initResult = proofInit(
                publicKey,
                signatureParts,
                generators,
                proofRandomScalars,
                BbsCodec.copy(header),
                messageScalars,
                undisclosedIndexes,
                ciphersuite,
                bls);
        BigInteger challenge = proofChallengeCalculate(
                initResult,
                disclosedMessages,
                indexes,
                BbsCodec.copy(presentationHeader),
                ciphersuite);
        return proofFinalize(initResult, challenge, signatureParts.e(), proofRandomScalars, undisclosedMessages);
    }

    public static boolean proofVerify(
            byte[] publicKey,
            byte[] proof,
            byte[] header,
            byte[] presentationHeader,
            List<byte[]> disclosedMessages,
            int[] disclosedIndexes,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls
    ) {
        try {
            BbsCodec.ProofParts proofParts = BbsCodec.octetsToProof(proof, ciphersuite);
            int undisclosedCount = proofParts.mHats().size();
            int revealedCount = Objects.requireNonNull(disclosedMessages, "disclosed messages required").size();
            int messageCount = undisclosedCount + revealedCount;
            if (messageCount > BbsCodec.MAX_MESSAGES) {
                return false;
            }
            int[] indexes = validateDisclosedIndexes(disclosedIndexes, messageCount);
            if (indexes.length != revealedCount) {
                return false;
            }
            List<BigInteger> disclosedScalars = messagesToScalars(disclosedMessages, ciphersuite);
            Generators generators = createGenerators(messageCount + 1, ciphersuite, bls);
            return coreProofVerify(
                    publicKey,
                    proofParts,
                    generators,
                    BbsCodec.copy(header),
                    BbsCodec.copy(presentationHeader),
                    disclosedScalars,
                    indexes,
                    ciphersuite,
                    bls);
        } catch (RuntimeException e) {
            return false;
        }
    }

    public static List<BigInteger> seededRandomScalars(
            byte[] seed,
            byte[] dst,
            int count,
            BbsCiphersuite ciphersuite
    ) {
        Objects.requireNonNull(seed, "seed required");
        Objects.requireNonNull(dst, "dst required");
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        if (count < 0) {
            throw new IllegalArgumentException("random scalar count must be non-negative");
        }
        int outLen = ciphersuite.expandLen() * count;
        if (outLen > 65535) {
            throw new IllegalArgumentException("mocked random scalar output exceeds 65535 bytes");
        }
        byte[] uniform = expandMessage(seed, dst, outLen, ciphersuite);
        List<BigInteger> scalars = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            scalars.add(new BigInteger(1, Arrays.copyOfRange(
                    uniform, i * ciphersuite.expandLen(), (i + 1) * ciphersuite.expandLen())).mod(R));
        }
        return List.copyOf(scalars);
    }

    public static BigInteger hashToScalar(byte[] message, byte[] dst, BbsCiphersuite ciphersuite) {
        Objects.requireNonNull(message, "message required");
        Objects.requireNonNull(dst, "dst required");
        byte[] uniform = expandMessage(message, dst, ciphersuite.expandLen(), ciphersuite);
        return new BigInteger(1, uniform).mod(R);
    }

    public static List<BigInteger> randomScalars(int count, BbsCiphersuite ciphersuite, SecureRandom random) {
        if (count < 0) {
            throw new IllegalArgumentException("random scalar count must be non-negative");
        }
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        Objects.requireNonNull(random, "secure random required");
        byte[] buffer = new byte[ciphersuite.expandLen()];
        List<BigInteger> scalars = new ArrayList<>(count);
        while (scalars.size() < count) {
            random.nextBytes(buffer);
            BigInteger scalar = new BigInteger(1, buffer).mod(R);
            if (scalar.signum() != 0) {
                scalars.add(scalar);
            }
        }
        return List.copyOf(scalars);
    }

    private static BbsCodec.SignatureParts coreSign(
            BigInteger secretKey,
            byte[] publicKey,
            Generators generators,
            byte[] header,
            List<BigInteger> messageScalars,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls
    ) {
        BigInteger domain = calculateDomain(publicKey, generators, header, ciphersuite);
        List<Object> eInput = new ArrayList<>(messageScalars.size() + 2);
        eInput.add(secretKey);
        eInput.addAll(messageScalars);
        eInput.add(domain);
        BigInteger e = hashToScalar(BbsCodec.serialize(eInput.toArray()), dst(ciphersuite.apiId(), "H2S_"), ciphersuite);
        BbsCodec.requireNonZeroScalar(e, "signature e");

        BigInteger denominator = mod(secretKey.add(e));
        if (denominator.signum() == 0) {
            throw new IllegalArgumentException("BBS signature denominator is zero");
        }
        G1Point b = computeBSecretMessages(generators, domain, messageScalars, ciphersuite, bls);
        G1Point a = bls.g1SecretScalarMul(b, secretScalarInverse(denominator));
        return new BbsCodec.SignatureParts(a, e);
    }

    private static boolean coreVerify(
            byte[] publicKey,
            byte[] signature,
            Generators generators,
            byte[] header,
            List<BigInteger> messageScalars,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls
    ) {
        return coreVerify(publicKey, signature, generators, header, messageScalars, ciphersuite, bls, false);
    }

    private static boolean coreVerify(
            byte[] publicKey,
            byte[] signature,
            Generators generators,
            byte[] header,
            List<BigInteger> messageScalars,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls,
            boolean secretMessages
    ) {
        try {
            BbsCodec.SignatureParts signatureParts = BbsCodec.octetsToSignature(signature, ciphersuite);
            G2Point w = BbsCodec.octetsToPublicKey(publicKey);
            BigInteger domain = calculateDomain(publicKey, generators, header, ciphersuite);
            G1Point b = secretMessages
                    ? computeBSecretMessages(generators, domain, messageScalars, ciphersuite, bls)
                    : computeBPublicMessages(generators, domain, messageScalars, ciphersuite, bls);
            G1Point left2 = bls.g1Add(bls.g1ScalarMul(signatureParts.a(), signatureParts.e()), bls.g1Negate(b));
            return bls.pairingProductIsIdentity(
                    new G1Point[]{signatureParts.a(), left2},
                    new G2Point[]{w, bls.g2Generator()});
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static ProofInitResult proofInit(
            byte[] publicKey,
            BbsCodec.SignatureParts signature,
            Generators generators,
            List<BigInteger> randomScalars,
            byte[] header,
            List<BigInteger> messages,
            int[] undisclosedIndexes,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls
    ) {
        BigInteger r1 = randomScalars.get(0);
        BigInteger r2 = randomScalars.get(1);
        BigInteger eTilde = randomScalars.get(2);
        BigInteger r1Tilde = randomScalars.get(3);
        BigInteger r3Tilde = randomScalars.get(4);

        BigInteger domain = calculateDomain(publicKey, generators, header, ciphersuite);
        G1Point b = computeBSecretMessages(generators, domain, messages, ciphersuite, bls);
        G1Point d = bls.g1SecretScalarMul(b, r2);
        G1Point aBar = bls.g1SecretScalarMul(signature.a(), mod(r1.multiply(r2)));
        G1Point bBar = bls.g1Add(
                bls.g1SecretScalarMul(d, r1),
                bls.g1Negate(bls.g1SecretScalarMul(aBar, signature.e())));
        G1Point t1 = bls.g1Add(bls.g1SecretScalarMul(aBar, eTilde), bls.g1SecretScalarMul(d, r1Tilde));
        G1Point t2 = bls.g1SecretScalarMul(d, r3Tilde);
        for (int u = 0; u < undisclosedIndexes.length; u++) {
            t2 = bls.g1Add(
                    t2,
                    bls.g1SecretScalarMul(generators.h().get(undisclosedIndexes[u]), randomScalars.get(5 + u)));
        }
        return new ProofInitResult(aBar, bBar, d, t1, t2, domain);
    }

    private static byte[] proofFinalize(
            ProofInitResult initResult,
            BigInteger challenge,
            BigInteger e,
            List<BigInteger> randomScalars,
            List<BigInteger> undisclosedMessages
    ) {
        BigInteger r1 = randomScalars.get(0);
        BigInteger r2 = randomScalars.get(1);
        BigInteger eTilde = randomScalars.get(2);
        BigInteger r1Tilde = randomScalars.get(3);
        BigInteger r3Tilde = randomScalars.get(4);
        BigInteger r3 = secretScalarInverse(r2);

        BigInteger eHat = mod(eTilde.add(e.multiply(challenge)));
        BigInteger r1Hat = mod(r1Tilde.subtract(r1.multiply(challenge)));
        BigInteger r3Hat = mod(r3Tilde.subtract(r3.multiply(challenge)));
        List<BigInteger> mHats = new ArrayList<>(undisclosedMessages.size());
        for (int i = 0; i < undisclosedMessages.size(); i++) {
            mHats.add(mod(randomScalars.get(5 + i).add(undisclosedMessages.get(i).multiply(challenge))));
        }

        return BbsCodec.proofToOctets(new BbsCodec.ProofParts(
                initResult.aBar(),
                initResult.bBar(),
                initResult.d(),
                eHat,
                r1Hat,
                r3Hat,
                mHats,
                challenge));
    }

    private static boolean coreProofVerify(
            byte[] publicKey,
            BbsCodec.ProofParts proof,
            Generators generators,
            byte[] header,
            byte[] presentationHeader,
            List<BigInteger> disclosedMessages,
            int[] disclosedIndexes,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls
    ) {
        G2Point w = BbsCodec.octetsToPublicKey(publicKey);
        ProofInitResult initResult = proofVerifyInit(
                publicKey, proof, generators, header, disclosedMessages, disclosedIndexes, ciphersuite, bls);
        BigInteger challenge = proofChallengeCalculate(
                initResult, disclosedMessages, disclosedIndexes, presentationHeader, ciphersuite);
        if (!proof.challenge().equals(challenge)) {
            return false;
        }
        return bls.pairingProductIsIdentity(
                new G1Point[]{proof.aBar(), proof.bBar()},
                new G2Point[]{w, bls.g2Generator().negate()});
    }

    private static ProofInitResult proofVerifyInit(
            byte[] publicKey,
            BbsCodec.ProofParts proof,
            Generators generators,
            byte[] header,
            List<BigInteger> disclosedMessages,
            int[] disclosedIndexes,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls
    ) {
        int hiddenCount = proof.mHats().size();
        int messageCount = hiddenCount + disclosedIndexes.length;
        int[] undisclosedIndexes = undisclosedIndexes(messageCount, disclosedIndexes);
        BigInteger domain = calculateDomain(publicKey, generators, header, ciphersuite);

        G1Point t1 = bls.g1Add(
                bls.g1Add(
                        bls.g1ScalarMul(proof.bBar(), proof.challenge()),
                        bls.g1ScalarMul(proof.aBar(), proof.eHat())),
                bls.g1ScalarMul(proof.d(), proof.r1Hat()));

        G1Point bv = bls.g1Add(ciphersuite.p1(), bls.g1ScalarMul(generators.q1(), domain));
        for (int i = 0; i < disclosedIndexes.length; i++) {
            bv = bls.g1Add(bv, bls.g1ScalarMul(generators.h().get(disclosedIndexes[i]), disclosedMessages.get(i)));
        }

        G1Point t2 = bls.g1Add(bls.g1ScalarMul(bv, proof.challenge()), bls.g1ScalarMul(proof.d(), proof.r3Hat()));
        for (int u = 0; u < undisclosedIndexes.length; u++) {
            t2 = bls.g1Add(t2, bls.g1ScalarMul(generators.h().get(undisclosedIndexes[u]), proof.mHats().get(u)));
        }
        return new ProofInitResult(proof.aBar(), proof.bBar(), proof.d(), t1, t2, domain);
    }

    private static BigInteger proofChallengeCalculate(
            ProofInitResult initResult,
            List<BigInteger> disclosedMessages,
            int[] disclosedIndexes,
            byte[] presentationHeader,
            BbsCiphersuite ciphersuite
    ) {
        if (disclosedMessages.size() != disclosedIndexes.length) {
            throw new IllegalArgumentException("Disclosed message count must match disclosed index count");
        }
        List<Object> values = new ArrayList<>(1 + disclosedIndexes.length * 2 + 6);
        values.add((long) disclosedIndexes.length);
        for (int i = 0; i < disclosedIndexes.length; i++) {
            values.add((long) disclosedIndexes[i]);
            values.add(disclosedMessages.get(i));
        }
        values.add(initResult.aBar());
        values.add(initResult.bBar());
        values.add(initResult.d());
        values.add(initResult.t1());
        values.add(initResult.t2());
        values.add(initResult.domain());

        byte[] cOctets = BbsCodec.concat(
                BbsCodec.serialize(values.toArray()),
                BbsCodec.i2osp(presentationHeader.length, 8),
                presentationHeader);
        return hashToScalar(cOctets, dst(ciphersuite.apiId(), "H2S_"), ciphersuite);
    }

    private static G1Point computeB(
            Generators generators,
            BigInteger domain,
            List<BigInteger> messages,
            BbsCiphersuite ciphersuite
    ) {
        return computeB(generators, domain, messages, ciphersuite, null, false);
    }

    private static G1Point computeBPublicMessages(
            Generators generators,
            BigInteger domain,
            List<BigInteger> messages,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls
    ) {
        return computeB(generators, domain, messages, ciphersuite, bls, false);
    }

    private static G1Point computeBSecretMessages(
            Generators generators,
            BigInteger domain,
            List<BigInteger> messages,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls
    ) {
        return computeB(generators, domain, messages, ciphersuite, bls, true);
    }

    private static G1Point computeB(
            Generators generators,
            BigInteger domain,
            List<BigInteger> messages,
            BbsCiphersuite ciphersuite,
            Bls12381Provider bls,
            boolean secretMessages
    ) {
        if (messages.size() != generators.h().size()) {
            throw new IllegalArgumentException("Message count must match BBS message generator count");
        }
        G1Point b = bls == null
                ? ciphersuite.p1().add(generators.q1().scalarMul(domain))
                : bls.g1Add(ciphersuite.p1(), bls.g1ScalarMul(generators.q1(), domain));
        for (int i = 0; i < messages.size(); i++) {
            G1Point term = bls == null
                    ? generators.h().get(i).scalarMul(messages.get(i))
                    : secretMessages
                            ? bls.g1SecretScalarMul(generators.h().get(i), messages.get(i))
                            : bls.g1ScalarMul(generators.h().get(i), messages.get(i));
            b = bls == null ? b.add(term) : bls.g1Add(b, term);
        }
        return b;
    }

    private static List<BigInteger> validateRandomScalars(List<BigInteger> randomScalars, int expected) {
        Objects.requireNonNull(randomScalars, "random scalars required");
        if (randomScalars.size() != expected) {
            throw new IllegalArgumentException("Expected " + expected + " random scalars, got " + randomScalars.size());
        }
        List<BigInteger> scalars = new ArrayList<>(expected);
        for (BigInteger scalar : randomScalars) {
            scalars.add(BbsCodec.requireNonZeroScalar(scalar, "proof random scalar"));
        }
        return List.copyOf(scalars);
    }

    public static int[] validateDisclosedIndexes(int[] disclosedIndexes, int messageCount) {
        Objects.requireNonNull(disclosedIndexes, "disclosed indexes required");
        if (messageCount < 0) {
            throw new IllegalArgumentException("message count must be non-negative");
        }
        int[] copy = disclosedIndexes.clone();
        int previous = -1;
        for (int index : copy) {
            if (index < 0 || index >= messageCount) {
                throw new IllegalArgumentException("BBS disclosed index out of range: " + index);
            }
            if (index <= previous) {
                throw new IllegalArgumentException("BBS disclosed indexes must be strictly ascending");
            }
            previous = index;
        }
        return copy;
    }

    private static int[] undisclosedIndexes(int messageCount, int[] disclosedIndexes) {
        int[] out = new int[messageCount - disclosedIndexes.length];
        int disclosedOffset = 0;
        int outOffset = 0;
        for (int i = 0; i < messageCount; i++) {
            if (disclosedOffset < disclosedIndexes.length && disclosedIndexes[disclosedOffset] == i) {
                disclosedOffset++;
            } else {
                out[outOffset++] = i;
            }
        }
        return out;
    }

    private static List<BigInteger> select(List<BigInteger> values, int[] indexes) {
        List<BigInteger> selected = new ArrayList<>(indexes.length);
        for (int index : indexes) {
            selected.add(values.get(index));
        }
        return List.copyOf(selected);
    }

    private static BigInteger mod(BigInteger value) {
        BigInteger out = value.mod(R);
        return out.signum() >= 0 ? out : out.add(R);
    }

    private static BigInteger secretScalarInverse(BigInteger scalar) {
        BbsCodec.requireNonZeroScalar(scalar, "secret scalar");
        return MontFr381.fromBigInteger(scalar).inverse().toBigInteger();
    }

    private static byte[] expandMessage(byte[] message, byte[] dst, int len, BbsCiphersuite ciphersuite) {
        if (dst.length > 255) {
            throw new IllegalArgumentException("BBS DST must be at most 255 bytes");
        }
        return switch (ciphersuite) {
            case BLS12381_SHA256 -> Bls12381Hash.expandMessageXmdSha256(message, dst, len);
            case BLS12381_SHAKE256 -> Bls12381Hash.expandMessageXofShake256(message, dst, len);
        };
    }

    private static G1Point hashToG1(byte[] message, byte[] dst, BbsCiphersuite ciphersuite, Bls12381Provider bls) {
        return switch (ciphersuite) {
            case BLS12381_SHA256 -> bls.g1HashToCurve(message, dst);
            case BLS12381_SHAKE256 -> bls.g1HashToCurveXofShake256(message, dst);
        };
    }

    private static byte[] dst(byte[] prefix, String suffix) {
        return BbsCodec.concat(prefix, suffix.getBytes(StandardCharsets.US_ASCII));
    }
}
