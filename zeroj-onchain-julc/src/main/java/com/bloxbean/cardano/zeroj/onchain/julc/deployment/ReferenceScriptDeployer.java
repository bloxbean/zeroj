package com.bloxbean.cardano.zeroj.onchain.julc.deployment;

/**
 * Structured deployment configuration for Cardano CIP-0033 reference scripts.
 *
 * <p>The class does not submit transactions. It records the deployment pattern
 * and data needed by transaction-building integrations such as zeroj-ccl.</p>
 */
public final class ReferenceScriptDeployer {

    private ReferenceScriptDeployer() {}

    public enum DeploymentPattern {
        VK_IN_SCRIPT,
        REFERENCE_SCRIPT_DATUM_VK,
        VK_HASH_COMMITMENT
    }

    public record DeploymentConfig(
            DeploymentPattern pattern,
            byte[] scriptBytes,
            byte[] vkBytes,
            byte[] vkHash,
            int estimatedScriptSize
    ) {
        public static DeploymentConfig vkInScript(byte[] scriptBytes, byte[] vkBytes) {
            return new DeploymentConfig(DeploymentPattern.VK_IN_SCRIPT,
                    scriptBytes, vkBytes, null, scriptBytes.length);
        }

        public static DeploymentConfig referenceWithDatumVk(byte[] scriptBytes, byte[] vkBytes) {
            return new DeploymentConfig(DeploymentPattern.REFERENCE_SCRIPT_DATUM_VK,
                    scriptBytes, vkBytes, null, scriptBytes.length);
        }

        public static DeploymentConfig vkHashCommitment(byte[] scriptBytes, byte[] vkHash) {
            return new DeploymentConfig(DeploymentPattern.VK_HASH_COMMITMENT,
                    scriptBytes, null, vkHash, scriptBytes.length);
        }
    }
}
