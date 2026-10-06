package ai.rever.boss.plugin.dynamic.secretmanager.security

import ai.rever.boss.plugin.api.SecretDataProvider
import ai.rever.boss.plugin.api.PaginatedSecretsWithSharingData
import ai.rever.boss.plugin.dynamic.secretmanager.SecretManagerViewModel
import ai.rever.boss.plugin.dynamic.secretmanager.ai.FakeSecretDataProvider
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.advanceUntilIdle
import kotlin.test.Test
import kotlin.test.assertNull
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultHealthLifecycleTest {
    @Test
    fun `dispose cancels a suspended scan and clears its result`() = runTest {
        val gate = CompletableDeferred<Unit>()
        var returned = false
        val fake = FakeSecretDataProvider(emptyList())
        val provider = object : SecretDataProvider by fake {
            override suspend fun getUserSecretsWithSharingInfo(limit: Int, offset: Int): Result<PaginatedSecretsWithSharingData> {
                gate.await()
                returned = true
                return Result.success(PaginatedSecretsWithSharingData(emptyList(), false))
            }
        }
        val vm = SecretManagerViewModel(provider, null, null, scope = this)
        vm.runVaultHealthCheck()
        runCurrent()
        assertTrue(vm.state.isCheckingHealth)
        vm.dispose()
        gate.complete(Unit)
        advanceUntilIdle()
        assertFalse(returned)
        assertFalse(vm.state.isCheckingHealth)
        assertNull(vm.state.healthReport)
        vm.runVaultHealthCheck()
        assertFalse(vm.state.isCheckingHealth)
    }

    @Test
    fun `a failed rescan clears a previous healthy result`() = runTest {
        val fake = FakeSecretDataProvider(emptyList())
        var fails = false
        val provider = object : SecretDataProvider by fake {
            override suspend fun getUserSecretsWithSharingInfo(limit: Int, offset: Int): Result<PaginatedSecretsWithSharingData> =
                if (fails) Result.failure(IllegalStateException("offline")) else fake.getUserSecretsWithSharingInfo(limit, offset)
        }
        val vm = SecretManagerViewModel(provider, null, null, scope = this)
        vm.runVaultHealthCheck()
        advanceUntilIdle()
        assertTrue(vm.state.healthReport != null)
        fails = true
        vm.runVaultHealthCheck()
        assertNull(vm.state.healthReport)
        advanceUntilIdle()
        assertNull(vm.state.healthReport)
        assertFalse(vm.state.isCheckingHealth)
        assertTrue(vm.state.healthError != null)
        assertNull(vm.state.errorMessage, "health failure must keep the normal secrets list available")
        fails = false
        vm.runVaultHealthCheck()
        advanceUntilIdle()
        assertNull(vm.state.healthError)
        assertTrue(vm.state.healthReport != null)
        vm.dispose()
        assertNull(vm.state.healthReport)
        assertNull(vm.state.healthError)
    }
}
