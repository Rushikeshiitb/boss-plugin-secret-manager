package ai.rever.boss.plugin.dynamic.secretmanager.security

import ai.rever.boss.plugin.api.*
import ai.rever.boss.plugin.dynamic.secretmanager.ai.FakeSecretDataProvider

/** Implements only the legacy contract; new methods use the actual published defaults. */
internal class LegacySecretDataProvider(private val delegate: FakeSecretDataProvider) : SecretDataProvider {
    override suspend fun getUserSecrets(limit: Int, offset: Int) = delegate.getUserSecrets(limit, offset)
    override suspend fun getUserSecretsWithSharingInfo(limit: Int, offset: Int) = delegate.getUserSecretsWithSharingInfo(limit, offset)
    override suspend fun searchSecrets(query: String, limit: Int, offset: Int) = delegate.searchSecrets(query, limit, offset)
    override suspend fun createSecret(request: CreateSecretRequestData) = delegate.createSecret(request)
    override suspend fun updateSecret(request: UpdateSecretRequestData) = delegate.updateSecret(request)
    override suspend fun deleteSecret(id: String) = delegate.deleteSecret(id)
    override suspend fun getSecretShares(secretId: String) = delegate.getSecretShares(secretId)
    override suspend fun shareSecret(request: ShareSecretRequestData) = delegate.shareSecret(request)
    override suspend fun unshareSecret(request: UnshareSecretRequestData) = delegate.unshareSecret(request)
}
