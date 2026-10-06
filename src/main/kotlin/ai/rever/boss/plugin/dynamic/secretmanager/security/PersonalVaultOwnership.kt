package ai.rever.boss.plugin.dynamic.secretmanager.security

import ai.rever.boss.plugin.api.SecretEntryWithSharingAccessData

/** The current host cannot establish safe personal ownership for an owner-labelled row. */
class PersonalVaultOwnershipException : Exception(
    "This BOSS version cannot verify personal vault ownership. A compatible BOSS update is required."
)

/**
 * The server labels an org secret's creator as owner too. Organisation markers take
 * precedence over that label; a personal owner also needs explicit management proof.
 * The published API's legacy fallback defaults canManage to false, so an ambiguous owner
 * cannot be exported or turn a health scan into a misleading all-clear.
 */
internal object PersonalVaultOwnership {
    fun includes(entry: SecretEntryWithSharingAccessData): Boolean {
        if (entry.isOrgOwned || entry.orgId != null || entry.orgSlug != null) return false
        if (entry.secret.accessLevel != "owner") return false
        if (!entry.secret.isOwner || !entry.canManage) throw PersonalVaultOwnershipException()
        return true
    }
}
