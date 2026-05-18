package com.bloxbean.cardano.zeroj.onchain.julc.deployment;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ReferenceScriptDeployerTest {

    @Test
    void createsReferenceScriptWithDatumVkConfig() {
        byte[] script = {1, 2, 3};
        byte[] vk = {4, 5};

        var config = ReferenceScriptDeployer.DeploymentConfig.referenceWithDatumVk(script, vk);

        assertEquals(ReferenceScriptDeployer.DeploymentPattern.REFERENCE_SCRIPT_DATUM_VK, config.pattern());
        assertArrayEquals(script, config.scriptBytes());
        assertArrayEquals(vk, config.vkBytes());
        assertNull(config.vkHash());
        assertEquals(3, config.estimatedScriptSize());
    }

    @Test
    void createsVkInScriptConfig() {
        byte[] script = {1, 2};
        byte[] vk = {3, 4};

        var config = ReferenceScriptDeployer.DeploymentConfig.vkInScript(script, vk);

        assertEquals(ReferenceScriptDeployer.DeploymentPattern.VK_IN_SCRIPT, config.pattern());
        assertArrayEquals(script, config.scriptBytes());
        assertArrayEquals(vk, config.vkBytes());
        assertNull(config.vkHash());
        assertEquals(2, config.estimatedScriptSize());
    }

    @Test
    void createsVkHashCommitmentConfig() {
        byte[] script = {1, 2, 3, 4};
        byte[] vkHash = {5, 6};

        var config = ReferenceScriptDeployer.DeploymentConfig.vkHashCommitment(script, vkHash);

        assertEquals(ReferenceScriptDeployer.DeploymentPattern.VK_HASH_COMMITMENT, config.pattern());
        assertArrayEquals(script, config.scriptBytes());
        assertNull(config.vkBytes());
        assertArrayEquals(vkHash, config.vkHash());
        assertEquals(4, config.estimatedScriptSize());
    }
}
