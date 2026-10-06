package ai.rever.boss.plugin.dynamic.secretmanager.security

import ai.rever.boss.plugin.api.CreateSecretRequestData
import ai.rever.boss.plugin.dynamic.secretmanager.SecretManagerViewModel
import ai.rever.boss.plugin.dynamic.secretmanager.ai.FakeSecretDataProvider
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlin.math.abs
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins [PasswordGenerator], including the two correctness points from the #676
 * review: the entropy must MEASURE the constrained generator (not overstate it as
 * `length * log2(pool)`), and a passphrase must not collapse distinct words.
 *
 * Randomness is injected, so every property is checked against a seeded [Random].
 */
class PasswordGeneratorTest {
    @Test
    fun `generate honours length and every selected class`() {
        val pw = PasswordGenerator.generate(PasswordGenerator.Options(length = 32), Random(1))
        assertEquals(32, pw.length)
        assertTrue(pw.any { it in PasswordGenerator.LOWERCASE }, "has a lowercase")
        assertTrue(pw.any { it in PasswordGenerator.UPPERCASE }, "has an uppercase")
        assertTrue(pw.any { it in PasswordGenerator.DIGITS }, "has a digit")
        assertTrue(pw.any { it in PasswordGenerator.SYMBOLS }, "has a symbol")
    }

    @Test
    fun `excludeAmbiguous emits no ambiguous characters`() {
        val pw =
            PasswordGenerator.generate(
                PasswordGenerator.Options(length = 200, excludeAmbiguous = true),
                Random(7),
            )
        assertTrue(pw.none { it in PasswordGenerator.AMBIGUOUS }, "no ambiguous characters: $pw")
    }

    @Test
    fun `a single selected class yields only that class`() {
        val pw =
            PasswordGenerator.generate(
                PasswordGenerator.Options(length = 16, lowercase = false, uppercase = false, symbols = false),
                Random(3),
            )
        assertEquals(16, pw.length)
        assertTrue(pw.all { it in PasswordGenerator.DIGITS }, "digits only: $pw")
    }

    @Test
    fun `generation is deterministic for a given seed`() {
        val a = PasswordGenerator.generate(PasswordGenerator.Options(length = 24), Random(42))
        val b = PasswordGenerator.generate(PasswordGenerator.Options(length = 24), Random(42))
        assertEquals(a, b)
    }

    @Test
    fun `generate rejects no classes and a length below the class count`() {
        assertFailsWith<IllegalArgumentException> {
            PasswordGenerator.generate(
                PasswordGenerator.Options(lowercase = false, uppercase = false, digits = false, symbols = false),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            PasswordGenerator.generate(PasswordGenerator.Options(length = 3))
        }
    }

    @Test
    fun `entropy measures the constrained sampler, not length times log2 pool`() {
        // length 2, lowercase + digits: pool 36, but only 520 valid strings contain
        // at least one of each class, so the entropy is log2(520) = 9.02237 bits -
        // NOT 2 * log2(36) = 10.34, which the earlier helper reported.
        val opts = PasswordGenerator.Options(length = 2, uppercase = false, symbols = false)
        assertTrue(abs(PasswordGenerator.entropyBits(opts) - 9.02237) < 1e-3, PasswordGenerator.entropyBits(opts).toString())
        assertTrue(PasswordGenerator.entropyBits(opts) < 10.0, "must not overstate as length*log2(pool)")
    }

    @Test
    fun `long password entropy stays finite and impossible policies have no entropy`() {
        val bits = PasswordGenerator.entropyBits(PasswordGenerator.Options(length = 200))
        assertTrue(bits.isFinite())
        assertTrue(bits > 1200.0)
        assertEquals(0.0, PasswordGenerator.entropyBits(PasswordGenerator.Options(length = 3)))
    }

    @Test
    fun `a failing random source cannot silently change the sampler`() {
        val alwaysLowercase = object : Random() {
            override fun nextBits(bitCount: Int): Int = 0
        }
        assertFailsWith<IllegalStateException> {
            PasswordGenerator.generate(random = alwaysLowercase)
        }
    }

    @Test
    fun `passphrase draws the requested number of words and joins them`() {
        val list = listOf("alpha", "bravo", "charlie", "delta", "echo", "foxtrot")
        val phrase =
            PasswordGenerator.passphrase(
                list,
                PasswordGenerator.PassphraseOptions(wordCount = 4, separator = "."),
                Random(9),
            )
        val parts = phrase.split(".")
        assertEquals(4, parts.size)
        assertTrue(parts.all { it in list }, "every part is a wordlist entry: $phrase")
    }

    @Test
    fun `passphrase capitalisation and number are applied`() {
        val list = listOf("alpha", "bravo", "charlie", "delta")
        val phrase =
            PasswordGenerator.passphrase(
                wordlist = list,
                options =
                    PasswordGenerator.PassphraseOptions(
                        wordCount = 3,
                        separator = "-",
                        capitalize = true,
                        includeNumber = true,
                    ),
                random = Random(5),
            )
        val parts = phrase.split("-")
        assertEquals(3, parts.size)
        assertTrue(parts.all { it.first().isUpperCase() }, "each word capitalised: $phrase")
        assertEquals(1, parts.count { it.last().isDigit() }, "exactly one trailing digit: $phrase")
    }

    @Test
    fun `passphrase rejects wordlists that would overstate entropy`() {
        val ok = PasswordGenerator.PassphraseOptions(wordCount = 3)
        assertFailsWith<IllegalArgumentException> { PasswordGenerator.passphrase(emptyList(), ok) }
        assertFailsWith<IllegalArgumentException> { PasswordGenerator.passphrase(listOf("a", "a", "b"), ok) }
        // A blank word and a word containing the separator make joining ambiguous.
        assertFailsWith<IllegalArgumentException> { PasswordGenerator.passphrase(listOf("a", " "), ok) }
        assertFailsWith<IllegalArgumentException> { PasswordGenerator.passphrase(listOf("a-b", "c"), ok) }
        // Capitalisation collision: "a" and "A" both become "A".
        assertFailsWith<IllegalArgumentException> {
            PasswordGenerator.passphrase(listOf("a", "A"), ok.copy(capitalize = true))
        }
    }

    @Test
    fun `passphrase entropy is words times log2 of the list size`() {
        assertTrue(abs(PasswordGenerator.passphraseEntropyBits(1, 7776) - 12.9248125) < 1e-4)
        assertEquals(0.0, PasswordGenerator.passphraseEntropyBits(4, 1))
    }

    @Test
    fun `separator checks cover transformed words and separator boundary overlaps`() {
        assertFailsWith<IllegalArgumentException> {
            PasswordGenerator.passphrase(
                listOf("alpha", "bravo"),
                PasswordGenerator.PassphraseOptions(separator = "A", capitalize = true),
            )
        }
        // Neither word contains "aaa", but ["a", "aa"] and ["aa", "a"]
        // both produce "aaaaaa" when joined with it.
        assertFailsWith<IllegalArgumentException> {
            PasswordGenerator.passphrase(listOf("a", "aa"), PasswordGenerator.PassphraseOptions(separator = "aaa"))
        }
    }

    @Test
    fun `numbered passphrases reserve digits so the original tuple remains recoverable`() {
        assertFailsWith<IllegalArgumentException> {
            PasswordGenerator.passphrase(listOf("a", "a1"), PasswordGenerator.PassphraseOptions(includeNumber = true))
        }
        assertFailsWith<IllegalArgumentException> {
            PasswordGenerator.passphrase(
                listOf("alpha", "bravo"),
                PasswordGenerator.PassphraseOptions(separator = "1", includeNumber = true),
            )
        }
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun `a generated password reaches the store through the create flow`() = runTest {
        val store = FakeSecretDataProvider(emptyList())
        val viewModel = SecretManagerViewModel(
            secretDataProvider = store,
            supabaseDataProvider = null,
            pluginStoreApiKeyProvider = null,
            scope = this,
        )
        viewModel.showCreateDialog()
        val pw = PasswordGenerator.generate(random = Random(11))
        assertTrue(pw.isNotBlank(), "the create form's confirm predicate")
        val request =
            CreateSecretRequestData(
                website = "github.com",
                username = "user@example.com",
                password = pw,
                notes = null,
                tags = emptyList(),
            )
        viewModel.createSecret(request)
        advanceUntilIdle()

        assertEquals(request, store.created.single())
        assertFalse(viewModel.state.showCreateDialog)
        assertFalse(viewModel.state.isOperationInProgress)
        viewModel.dispose()
    }
}
