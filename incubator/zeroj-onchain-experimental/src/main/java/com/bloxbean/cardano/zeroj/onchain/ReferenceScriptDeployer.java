package com.bloxbean.cardano.zeroj.onchain;

/**
 * Helper for deploying ZK verifier scripts as CIP-0033 reference scripts on Cardano.
 *
 * <p>Reference scripts allow separating the verifier logic (stored once on-chain in a UTxO)
 * from the proof submission transactions, significantly reducing per-transaction costs.</p>
 *
 * <p>Three deployment patterns are supported:</p>
 * <ul>
 *   <li><b>VK-in-script:</b> VK baked into script at deploy time. Simple but larger script; VK not rotatable.</li>
 *   <li><b>Reference script + datum VK:</b> Logic as CIP-0033 reference script, VK in a separate datum UTxO.
 *       Smallest script, VK is rotatable by spending the datum UTxO.</li>
 *   <li><b>VK hash commitment:</b> Script holds only the VK hash; full VK passed in redeemer.
 *       Smallest script, but larger redeemers. VK rotation requires new hash commitment.</li>
 * </ul>
 *
 * <p><b>Note:</b> Actual transaction construction uses CCL (cardano-client-lib).
 * This class provides the deployment patterns as structured types that
 * {@link com.bloxbean.cardano.zeroj.ccl.ZkTransactionHelper} can consume.</p>
 */
public final class ReferenceScriptDeployer {

    private ReferenceScriptDeployer() {}

    /**
     * Deployment pattern for on-chain verifier scripts.
     */
    public enum DeploymentPattern {
        /** VK baked into script at deploy time. */
        VK_IN_SCRIPT,
        /** Logic as CIP-0033, VK in datum. */
        REFERENCE_SCRIPT_DATUM_VK,
        /** Script has VK hash, full VK in redeemer. */
        VK_HASH_COMMITMENT
    }

    /**
     * Deployment configuration for a reference script.
     *
     * @param pattern           the deployment pattern
     * @param scriptBytes       compiled Plutus script bytes (CBOR)
     * @param vkBytes           verification key bytes (for VK_IN_SCRIPT or REFERENCE_SCRIPT_DATUM_VK)
     * @param vkHash            VK hash (for VK_HASH_COMMITMENT pattern)
     * @param estimatedScriptSize estimated on-chain size in bytes
     */
    public record DeploymentConfig(
            DeploymentPattern pattern,
            byte[] scriptBytes,
            byte[] vkBytes,
            byte[] vkHash,
            int estimatedScriptSize
    ) {
        /**
         * Create a VK-in-script deployment config.
         */
        public static DeploymentConfig vkInScript(byte[] scriptBytes, byte[] vkBytes) {
            return new DeploymentConfig(DeploymentPattern.VK_IN_SCRIPT,
                    scriptBytes, vkBytes, null, scriptBytes.length);
        }

        /**
         * Create a reference script + datum VK deployment config.
         */
        public static DeploymentConfig referenceWithDatumVk(byte[] scriptBytes, byte[] vkBytes) {
            return new DeploymentConfig(DeploymentPattern.REFERENCE_SCRIPT_DATUM_VK,
                    scriptBytes, vkBytes, null, scriptBytes.length);
        }

        /**
         * Create a VK hash commitment deployment config.
         */
        public static DeploymentConfig vkHashCommitment(byte[] scriptBytes, byte[] vkHash) {
            return new DeploymentConfig(DeploymentPattern.VK_HASH_COMMITMENT,
                    scriptBytes, null, vkHash, scriptBytes.length);
        }
    }
}
