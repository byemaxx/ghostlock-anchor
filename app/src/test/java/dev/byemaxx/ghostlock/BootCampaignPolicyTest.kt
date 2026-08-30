package com.anchor.bootstrap

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class BootCampaignPolicyTest {
    @Test
    fun `completed boot never launches another campaign`() {
        assertEquals(
            BootCampaignDecision.ALREADY_FINISHED,
            BootCampaignPolicy.decide(completedForCurrentBoot = true, lockAvailable = true)
        )
    }

    @Test
    fun `held campaign lock rejects duplicate broadcast`() {
        assertEquals(
            BootCampaignDecision.ALREADY_RUNNING,
            BootCampaignPolicy.decide(completedForCurrentBoot = false, lockAvailable = false)
        )
    }

    @Test
    fun `new boot with free lock starts one campaign`() {
        assertEquals(
            BootCampaignDecision.START,
            BootCampaignPolicy.decide(completedForCurrentBoot = false, lockAvailable = true)
        )
    }

    @Test
    fun `recovery marker disables a native launch`() {
        val directory = createTempDir(prefix = "anchor-disable")
        try {
            val marker = File(directory, AnchorDisableSwitch.FILE_NAME)
            assertFalse(AnchorDisableSwitch.isDisabled(marker))
            marker.writeText("")
            assertTrue(AnchorDisableSwitch.isDisabled(marker))
        } finally {
            directory.deleteRecursively()
        }
    }
}
