package ai.rever.boss.plugin.dynamic.secretmanager.security

import ai.rever.boss.plugin.api.SecretEntryWithSharingData
import ai.rever.boss.plugin.api.SecretEntryWithSharingAccessData
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class PersonalVaultOwnershipTest {
    private val owner = SecretEntryWithSharingData("1", "site", "user", "pw", createdAt = "now",
        updatedAt = "now", isOwner = true, accessLevel = "owner")

    @Test
    fun `org ownership markers override creator owner label even when management is allowed`() {
        val personal = SecretEntryWithSharingAccessData(owner, canManage = true)
        assertFalse(PersonalVaultOwnership.includes(personal.copy(isOrgOwned = true)))
        assertFalse(PersonalVaultOwnership.includes(personal.copy(orgId = "org-1")))
        assertFalse(PersonalVaultOwnership.includes(personal.copy(orgSlug = "team")))
    }

    @Test
    fun `ambiguous or denied owner metadata fails rather than skips`() {
        assertFailsWith<PersonalVaultOwnershipException> {
            PersonalVaultOwnership.includes(SecretEntryWithSharingAccessData(owner))
        }
        assertFailsWith<PersonalVaultOwnershipException> {
            PersonalVaultOwnership.includes(SecretEntryWithSharingAccessData(owner.copy(isOwner = false), canManage = true))
        }
    }

    @Test
    fun `personal owner shared with an org remains a personal owner`() {
        assertTrue(PersonalVaultOwnership.includes(SecretEntryWithSharingAccessData(owner,
            sharedWithOrgSlug = "recipient", canManage = true)))
    }

    @Test
    fun `legacy share and explicit org levels can be excluded without proving personal ownership`() {
        for (level in listOf("read", "write", "org", "new-source")) {
            assertFalse(PersonalVaultOwnership.includes(SecretEntryWithSharingAccessData(owner.copy(accessLevel = level))))
        }
    }
}
