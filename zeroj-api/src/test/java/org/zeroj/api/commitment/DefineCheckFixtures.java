package org.zeroj.api.commitment;

import static org.zeroj.api.commitment.CommitmentProfile . define ;

/**
 * Compiled fixtures for the self-check of the build's {@code verifyNoBuiltinProfileDefine} task
 * (ADR-0060 D8). The task must detect a reference to {@code CommitmentProfile.define} in each of the
 * first three nested classes and must not flag {@link MentionOnly}. Nothing here is ever executed.
 */
final class DefineCheckFixtures {

    private DefineCheckFixtures() {
    }

    interface Definer {
        CommitmentProfile define(CommitmentProfileId id, CommitmentKind kind, CommitmentGroup group, int length);
    }

    /** A method reference. */
    static final class MethodReference {
        static final Definer DEFINER = CommitmentProfile::define;
    }

    /** A call through a static import written with spaces. */
    static final class StaticImport {
        static CommitmentProfile call() {
            return define(CommitmentProfileId.of("zeroj-test-check-import-v1"), CommitmentKind.SCALAR,
                    CommitmentGroup.JUBJUB, 32);
        }
    }

    /** A fully qualified call split by a comment. */
    static final class Qualified {
        static CommitmentProfile call() {
            return org.zeroj.api.commitment.CommitmentProfile./* split */define(
                    CommitmentProfileId.of("zeroj-test-check-qualified-v1"), CommitmentKind.SCALAR,
                    CommitmentGroup.JUBJUB, 32);
        }
    }

    /** Mentions only, never a reference: do not call CommitmentProfile.define(...) here. */
    static final class MentionOnly {
        static final String TEXT = "CommitmentProfile.define(";
    }
}
