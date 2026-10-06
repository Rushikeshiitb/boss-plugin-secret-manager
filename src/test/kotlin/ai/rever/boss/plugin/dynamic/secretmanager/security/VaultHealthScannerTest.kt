package ai.rever.boss.plugin.dynamic.secretmanager.security

import ai.rever.boss.plugin.api.SecretEntryData
import ai.rever.boss.plugin.api.SecretEntryWithSharingData
import ai.rever.boss.plugin.api.SecretDataProvider
import ai.rever.boss.plugin.api.PaginatedSecretsWithSharingData
import ai.rever.boss.plugin.dynamic.secretmanager.ai.FakeSecretDataProvider
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Integration test for [VaultHealthScanner] against the shared [FakeSecretDataProvider]:
 * it must page the WHOLE vault (reuse spanning pages is the case a single-page scan
 * would miss) and must fail rather than return a partial report.
 */
class VaultHealthScannerTest {
    private fun secret(
        id: String,
        site: String,
        password: String,
    ) = SecretEntryData(
        id = id,
        website = site,
        username = "user",
        password = password,
        createdAt = "2026-01-01",
        updatedAt = "2026-01-01",
    )

    @Test
    fun `scans across pages and detects reuse spanning them`() =
        runTest {
            val entries =
                listOf(
                    secret("1", "github.com", "shared-pw"),
                    secret("2", "gitlab.com", "shared-pw"),
                    secret("3", "a.com", "Str0ng!Passphrase"),
                    secret("4", "b.com", "abc"),
                    secret("5", "c.com", "Another9!Strongxyz"),
                )
            val provider = FakeSecretDataProvider(entries)

            val report = VaultHealthScanner.scan(provider, pageSize = 2)

            assertEquals(5, report.analyzedCount, "every page was read")
            assertEquals(1, report.reuseGroups.size, "the reuse across pages 1 is found")
            assertTrue(provider.pageRequests.size >= 3, "the vault was paged, not read once: ${provider.pageRequests}")
        }

    @Test
    fun `a failed read throws rather than returning a partial report`() =
        runTest {
            val provider = FakeSecretDataProvider(emptyList(), failReads = true)
            assertFailsWith<IllegalStateException> { VaultHealthScanner.scan(provider) }
        }
    @Test
    fun `reaching the cap fails instead of declaring a partial vault healthy`() = runTest {
        val provider = FakeSecretDataProvider((1..4).map { secret("$it", "site-$it", "Strong123!password") })
        assertFailsWith<VaultHealthScanException> { VaultHealthScanner.scan(provider, pageSize = 2, cap = 3) }
        assertEquals(listOf(2 to 0, 1 to 2), provider.pageRequests)
    }

    @Test
    fun `an empty page claiming more cannot produce an all clear`() = runTest {
        val fake = FakeSecretDataProvider(emptyList())
        val provider = object : SecretDataProvider by fake {
            override suspend fun getUserSecretsWithSharingInfo(limit: Int, offset: Int) =
                Result.success(PaginatedSecretsWithSharingData(emptyList(), hasMore = true))
        }
        assertFailsWith<VaultHealthScanException> { VaultHealthScanner.scan(provider) }
    }

    @Test
    fun `a failed later page does not publish earlier results`() = runTest {
        val fake = FakeSecretDataProvider(listOf(secret("1", "site", "strong123!"), secret("2", "site2", "abc")))
        val provider = object : SecretDataProvider by fake {
            override suspend fun getUserSecretsWithSharingInfo(limit: Int, offset: Int): Result<PaginatedSecretsWithSharingData> =
                if (offset > 0) Result.failure(IllegalStateException("offline")) else fake.getUserSecretsWithSharingInfo(limit, offset)
        }
        assertFailsWith<IllegalStateException> { VaultHealthScanner.scan(provider, pageSize = 1) }
    }

    @Test
    fun `only personal owner source is included even when org creator isOwner is true`() = runTest {
        val rows = listOf("owner" to true, "org-creator" to true, "org-colleague" to false,
            "shared" to false, "unknown" to true).map { (label, owner) ->
            SecretEntryWithSharingData(id = label, website = label, username = "user", password = "pw",
                createdAt = "now", updatedAt = "now", isOwner = owner,
                accessLevel = when (label) { "owner" -> "owner"; "org-creator", "org-colleague" -> "org";
                    "shared" -> "read"; else -> "new-source" })
        }
        val fake = FakeSecretDataProvider(emptyList())
        val provider = object : SecretDataProvider by fake {
            override suspend fun getUserSecretsWithSharingInfo(limit: Int, offset: Int): Result<PaginatedSecretsWithSharingData> =
                Result.success(PaginatedSecretsWithSharingData(rows.drop(offset).take(limit), offset + limit < rows.size))
        }
        val result = VaultHealthScanner.scan(provider, pageSize = 2)
        assertEquals(1, result.analyzedCount)
        assertEquals(listOf("owner"), result.weakEntries.map { it.id })
        assertTrue(result.reuseGroups.isEmpty())
    }

}
