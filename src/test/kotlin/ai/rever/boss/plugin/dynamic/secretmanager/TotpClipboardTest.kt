package ai.rever.boss.plugin.dynamic.secretmanager

import ai.rever.boss.plugin.api.SecretEntryData
import ai.rever.boss.plugin.api.SecretMetadataData
import androidx.compose.ui.platform.ClipboardManager
import androidx.compose.ui.text.AnnotatedString
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class TotpClipboardTest {
    @Test
    fun `copy regenerates at click time across a code rollover`() = runTest {
        var now = 59L
        val viewModel = viewModel(this) { now }
        val clipboard = FakeClipboard()

        assertTrue(viewModel.copyTotpCodeToClipboard(secret(), clipboard))
        assertEquals("287082", clipboard.getText()?.text)
        now = 60L
        assertTrue(viewModel.copyTotpCodeToClipboard(secret(), clipboard))
        // Published RFC 4226 counter 2 code, for RFC 6238's SHA-1 seed.
        assertEquals("359152", clipboard.getText()?.text)
    }

    @Test
    fun `copying malformed metadata leaves the clipboard and pending wipe intact`() = runTest {
        val viewModel = viewModel(this)
        val clipboard = FakeClipboard()
        assertTrue(viewModel.copyTotpCodeToClipboard(secret(), clipboard))
        advanceTimeBy(44_000)

        assertFalse(viewModel.copyTotpCodeToClipboard(secret("ſSAA"), clipboard))
        assertFalse(viewModel.copyTotpCodeToClipboard(secret().copy(metadata = null), clipboard))
        assertEquals("287082", clipboard.getText()?.text)
        advanceTimeBy(2_000)
        assertEquals("", clipboard.getText()?.text)
    }

    @Test
    fun `copying the same TOTP code twice starts a fresh wipe window`() = runTest {
        val viewModel = viewModel(this)
        val clipboard = FakeClipboard()
        viewModel.copyTotpCodeToClipboard(secret(), clipboard)
        advanceTimeBy(44_000)
        viewModel.copyTotpCodeToClipboard(secret(), clipboard)
        advanceTimeBy(2_000)
        assertEquals("287082", clipboard.getText()?.text)
        advanceTimeBy(44_000)
        assertEquals("", clipboard.getText()?.text)
    }

    @Test
    fun `password and TOTP copies share one wipe generation in both directions`() = runTest {
        for (passwordFirst in listOf(true, false)) {
            val viewModel = viewModel(this)
            val clipboard = FakeClipboard()
            // Same clipboard value makes the generation token the only protection
            // against an older timer clearing a fresh copy of the other kind.
            val secret = secret().copy(password = "287082")
            fun copyPassword() = viewModel.copyPasswordToClipboard(secret, clipboard)
            fun copyCode() = viewModel.copyTotpCodeToClipboard(secret, clipboard)
            if (passwordFirst) copyPassword() else copyCode()
            advanceTimeBy(44_000)
            if (passwordFirst) copyCode() else copyPassword()
            advanceTimeBy(2_000)
            assertEquals("287082", clipboard.getText()?.text)
            advanceTimeBy(44_000)
            assertEquals("", clipboard.getText()?.text)
        }
    }

    @Test
    fun `TOTP cleanup preserves unrelated clipboard contents`() = runTest {
        val viewModel = viewModel(this)
        val clipboard = FakeClipboard()
        viewModel.copyTotpCodeToClipboard(secret(), clipboard)
        clipboard.setText(AnnotatedString("shopping list"))
        advanceTimeBy(46_000)
        assertEquals("shopping list", clipboard.getText()?.text)
    }

    @Test
    fun `closing the panel does not cancel TOTP clipboard cleanup`() = runTest {
        val viewModel = viewModel(this)
        val clipboard = FakeClipboard()
        viewModel.copyTotpCodeToClipboard(secret(), clipboard)
        viewModel.dispose()
        advanceTimeBy(46_000)
        assertEquals("", clipboard.getText()?.text)
    }

    private fun viewModel(scope: CoroutineScope, clock: () -> Long = { 59L }) = SecretManagerViewModel(
        secretDataProvider = null,
        supabaseDataProvider = null,
        pluginStoreApiKeyProvider = null,
        scope = scope,
        unixTimeSeconds = clock,
    )

    private fun secret(seed: String = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") = SecretEntryData(
        id = "totp-test",
        website = "example.test",
        username = "user",
        password = "test-password",
        metadata = SecretMetadataData(twofaEnabled = true, twofaType = "totp", twofaSecret = seed),
        createdAt = "2026-01-01",
        updatedAt = "2026-01-01",
    )

    private class FakeClipboard : ClipboardManager {
        private var stored: AnnotatedString? = null
        override fun setText(annotatedString: AnnotatedString) { stored = annotatedString }
        override fun getText(): AnnotatedString? = stored
    }
}
