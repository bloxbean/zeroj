package org.zeroj.api.commitment;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Test-only profiles and codecs. Each identifier is defined exactly once per JVM, because
 * {@link CommitmentProfile#define} rejects duplicates for the life of the class loader.
 *
 * <p>The fake point encoding is 4 octets: a first octet {@code 0xFF} is malformed and
 * {@code 0xEE} is "outside the subgroup"; anything else decodes. The fake context is one octet.
 */
final class FakeProfiles {

    static final int POINT_LENGTH = 4;

    static final CommitmentProfile FAKE = CommitmentProfile.define(
            CommitmentProfileId.of("zeroj-test-fake-v1"), CommitmentKind.SCALAR, CommitmentGroup.JUBJUB, POINT_LENGTH);
    static final CommitmentProfile OTHER = CommitmentProfile.define(
            CommitmentProfileId.of("zeroj-test-other-v1"), CommitmentKind.BYTES, CommitmentGroup.JUBJUB, POINT_LENGTH);

    private FakeProfiles() {
    }

    /** A commitment of a fake profile with a one-octet context. */
    static final class FakeCommitment implements Commitment {
        final CommitmentProfile profile;
        final byte[] point;
        final byte context;

        FakeCommitment(CommitmentProfile profile, byte[] point, byte context) {
            this.profile = profile;
            this.point = point.clone();
            this.context = context;
        }

        @Override
        public CommitmentProfile profile() {
            return profile;
        }

        @Override
        public byte[] toPointBytes() {
            return point.clone();
        }
    }

    /** A different concrete class claiming the same profile: must never pass the class check. */
    static final class ForeignCommitment implements Commitment {
        final AtomicInteger calls = new AtomicInteger();

        @Override
        public CommitmentProfile profile() {
            calls.incrementAndGet();
            return FAKE;
        }

        @Override
        public byte[] toPointBytes() {
            calls.incrementAndGet();
            return new byte[POINT_LENGTH];
        }
    }

    /** The codec of a fake profile, bound to one context octet. Counts decodePoint calls. */
    static class FakeCodec implements CommitmentCodec<FakeCommitment> {
        final CommitmentProfile profile;
        final byte context;
        final AtomicInteger decodes = new AtomicInteger();

        FakeCodec(CommitmentProfile profile, byte context) {
            this.profile = profile;
            this.context = context;
        }

        @Override
        public CommitmentProfile profile() {
            return profile;
        }

        @Override
        public Class<FakeCommitment> commitmentType() {
            return FakeCommitment.class;
        }

        @Override
        public FakeCommitment decodePoint(byte[] pointBytes) {
            decodes.incrementAndGet();
            if (pointBytes.length != POINT_LENGTH || pointBytes[0] == (byte) 0xFF) {
                throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING, "fake malformed");
            }
            if (pointBytes[0] == (byte) 0xEE) {
                throw new CommitmentFormatException(CommitmentError.NOT_IN_SUBGROUP, "fake small order");
            }
            return new FakeCommitment(profile, pointBytes, context);
        }

        @Override
        public byte[] keyContext() {
            return new byte[]{context};
        }

        @Override
        public void requireContext(FakeCommitment commitment) {
            if (commitment.context != context) {
                throw new CommitmentFormatException(CommitmentError.PROFILE_MISMATCH, "fake context");
            }
        }
    }

    static FakeCommitment commitment(int a, int b, int c, int d) {
        return new FakeCommitment(FAKE, new byte[]{(byte) a, (byte) b, (byte) c, (byte) d}, (byte) 0);
    }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    static byte[] bytes(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) out[i] = (byte) values[i];
        return out;
    }

    static byte[] withByte(byte[] in, int index, int value) {
        byte[] out = Arrays.copyOf(in, in.length);
        out[index] = (byte) value;
        return out;
    }
}
