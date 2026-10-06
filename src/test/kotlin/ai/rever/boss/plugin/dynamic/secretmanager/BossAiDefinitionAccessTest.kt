package ai.rever.boss.plugin.dynamic.secretmanager

import ai.rever.boss.plugin.api.*
import ai.rever.boss.plugin.dynamic.secretmanager.ai.FakeSecretDataProvider
import ai.rever.boss.plugin.dynamic.secretmanager.ai.bossAiDefinitionRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class BossAiDefinitionAccessTest {
    @Test
    fun `fresh organisation denial overrides a cached management allow`() = runTest {
        val row = definition()
        val fake = FakeSecretDataProvider(listOf(row))
        val provider = DefinitionProvider(fake, listOf(access(row, false)))
        val vm = viewModel(provider, this)
        vm.initialize()
        advanceUntilIdle()
        assertTrue(vm.canManageSecret(row.id), "precondition: UI cache holds an earlier allow")

        vm.prepareBossAiProviderDefinition()
        advanceUntilIdle()

        assertTrue(fake.updated.isEmpty())
        assertTrue(fake.created.isEmpty())
        assertTrue(vm.state.errorMessage.orEmpty().contains("cannot manage"))
        assertFalse(vm.state.isOperationInProgress)
    }

    @Test
    fun `fresh management allow upgrades a definition absent from the UI cache`() = runTest {
        val row = definition()
        val fake = FakeSecretDataProvider(listOf(row))
        val vm = viewModel(DefinitionProvider(fake, listOf(access(row, true))), this)
        assertFalse(vm.canManageSecret(row.id))

        vm.prepareBossAiProviderDefinition()
        advanceUntilIdle()

        assertEquals(row.id, fake.updated.single().secretId)
        assertEquals(bossAiDefinitionRequest().notes, fake.updated.single().notes)
        assertTrue(fake.created.isEmpty())
    }

    @Test
    fun `legacy provider without access metadata cannot upgrade a definition`() = runTest {
        val row = definition()
        val fake = FakeSecretDataProvider(listOf(row))
        val vm = viewModel(LegacyDefinitionProvider(fake, row), this)

        vm.prepareBossAiProviderDefinition()
        advanceUntilIdle()

        assertTrue(fake.updated.isEmpty())
        assertTrue(fake.created.isEmpty())
        assertTrue(vm.state.errorMessage.orEmpty().contains("cannot manage"))
    }

    @Test
    fun `an absent definition still creates the canonical inert entry`() = runTest {
        val fake = FakeSecretDataProvider(emptyList())
        val vm = viewModel(DefinitionProvider(fake, emptyList()), this)
        vm.prepareBossAiProviderDefinition()
        advanceUntilIdle()

        assertEquals(bossAiDefinitionRequest(), fake.created.single())
        assertTrue(fake.updated.isEmpty())
    }

    @Test
    fun `management allow cannot upgrade an entry containing a real credential`() = runTest {
        val row = definition().copy(password = "real-private-credential")
        val fake = FakeSecretDataProvider(listOf(row))
        val vm = viewModel(DefinitionProvider(fake, listOf(access(row, true))), this)
        vm.prepareBossAiProviderDefinition()
        advanceUntilIdle()

        assertTrue(fake.updated.isEmpty())
        assertTrue(fake.created.isEmpty())
        assertTrue(vm.state.errorMessage.orEmpty().contains("inert"))
    }

    @Test
    fun `disposing during a noncooperative definition lookup prevents either write`() = runTest {
        val row = definition()
        val fake = FakeSecretDataProvider(listOf(row))
        val gate = CompletableDeferred<Unit>()
        val base = DefinitionProvider(fake, listOf(access(row, true)))
        val provider = object : SecretDataProvider by base {
            override suspend fun searchSecretsWithAccess(query: String, limit: Int, offset: Int): Result<PaginatedSecretsWithAccessData> {
                try {
                    gate.await()
                } catch (_: CancellationException) {
                    withContext(NonCancellable) { gate.await() }
                }
                return base.searchSecretsWithAccess(query, limit, offset)
            }
        }
        val vm = viewModel(provider, this)
        vm.prepareBossAiProviderDefinition()
        runCurrent()
        vm.dispose()
        gate.complete(Unit)
        advanceUntilIdle()

        assertTrue(fake.updated.isEmpty())
        assertTrue(fake.created.isEmpty())
        assertFalse(vm.state.isOperationInProgress)
    }

    @Test
    fun `provider lookup cancellation prevents writes and clears progress`() = runTest {
        val fake = FakeSecretDataProvider(emptyList())
        val base = DefinitionProvider(fake, emptyList())
        val provider = object : SecretDataProvider by base {
            override suspend fun searchSecretsWithAccess(query: String, limit: Int, offset: Int): Result<PaginatedSecretsWithAccessData> =
                Result.failure(CancellationException("cancelled"))
        }
        val vm = viewModel(provider, this)
        vm.prepareBossAiProviderDefinition()
        advanceUntilIdle()

        assertTrue(fake.updated.isEmpty())
        assertTrue(fake.created.isEmpty())
        assertFalse(vm.state.isOperationInProgress)
    }

    @Test
    fun `definition preparation in an already cancelled scope cannot latch progress`() = runTest {
        val fake = FakeSecretDataProvider(emptyList())
        val job = Job().apply { cancel() }
        val vm = viewModel(DefinitionProvider(fake, emptyList()), CoroutineScope(coroutineContext + job))
        vm.prepareBossAiProviderDefinition()
        advanceUntilIdle()

        assertTrue(fake.created.isEmpty())
        assertFalse(vm.state.isOperationInProgress)
    }

    private fun viewModel(provider: SecretDataProvider, scope: CoroutineScope) =
        SecretManagerViewModel(provider, null, null, scope)

    private fun definition(): SecretEntryData {
        val request = bossAiDefinitionRequest()
        return SecretEntryData(
            id = "definition", website = request.website, username = request.username,
            password = request.password, notes = request.notes, tags = request.tags,
            createdAt = "then", updatedAt = "now",
        )
    }

    private fun access(row: SecretEntryData, canManage: Boolean) = SecretEntryWithAccessData(
        secret = row, orgId = "org-1", orgSlug = "acme", isOrgOwned = true, canManage = canManage,
    )

    private class DefinitionProvider(
        private val fake: FakeSecretDataProvider,
        private val rows: List<SecretEntryWithAccessData>,
    ) : SecretDataProvider by fake {
        override suspend fun searchSecretsWithAccess(query: String, limit: Int, offset: Int) =
            Result.success(PaginatedSecretsWithAccessData(rows.drop(offset).take(limit), false))

        override suspend fun searchSecrets(query: String, limit: Int, offset: Int) =
            Result.success(PaginatedSecretsData(rows.drop(offset).take(limit).map { it.secret }, false))
    }

    /** Implements only the old interface surface, exercising the real read-only default. */
    private class LegacyDefinitionProvider(
        private val fake: FakeSecretDataProvider,
        private val row: SecretEntryData,
    ) : SecretDataProvider {
        override suspend fun searchSecrets(query: String, limit: Int, offset: Int) =
            Result.success(PaginatedSecretsData(listOf(row), false))
        override suspend fun getUserSecrets(limit: Int, offset: Int) = fake.getUserSecrets(limit, offset)
        override suspend fun getUserSecretsWithSharingInfo(limit: Int, offset: Int) = fake.getUserSecretsWithSharingInfo(limit, offset)
        override suspend fun getSecretShares(secretId: String) = fake.getSecretShares(secretId)
        override suspend fun createSecret(request: CreateSecretRequestData) = fake.createSecret(request)
        override suspend fun updateSecret(request: UpdateSecretRequestData) = fake.updateSecret(request)
        override suspend fun deleteSecret(id: String) = fake.deleteSecret(id)
        override suspend fun shareSecret(request: ShareSecretRequestData) = fake.shareSecret(request)
        override suspend fun unshareSecret(request: UnshareSecretRequestData) = fake.unshareSecret(request)
    }
}
