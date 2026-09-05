package com.rick.oauthopenid

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.rick.oauthopenid.oauth.IdTokenValidator
import com.rick.oauthopenid.oauth.Jwt
import com.rick.oauthopenid.oauth.Pkce
import com.rick.oauthopenid.oauth.ValidationCheck
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

/**
 * Tests for the protocol pieces that carry security weight.
 *
 * These run on a device because [Pkce] and [Jwt] use `android.util.Base64`, which is stubbed
 * out in host-side unit tests.
 *
 * The negative cases matter more than the positive one: it is easy to write a validator that
 * accepts good tokens, and the whole point is that it also rejects bad ones.
 */
@RunWith(AndroidJUnit4::class)
class OAuthProtocolTest {

    // --- PKCE -----------------------------------------------------------------------------

    /** Confirms S256 matches the RFC 7636 appendix example. */
    @Test
    fun codeChallengeMatchesRfc7636TestVector() {
        // The worked example from RFC 7636, Appendix B.
        val verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        assertEquals(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            Pkce.codeChallenge(verifier),
        )
    }

    /** Confirms verifiers are unique and at least 43 characters. */
    @Test
    fun randomValuesAreUniqueAndLongEnough() {
        val values = List(100) { Pkce.randomValue() }
        // 32 bytes base64url-encodes to 43 characters, RFC 7636's minimum verifier length.
        values.forEach { assertEquals(43, it.length) }
        assertEquals("values must never repeat", 100, values.toSet().size)
    }

    /** Confirms the challenge is a hash, not the verifier itself. */
    @Test
    fun challengeIsNotTheVerifier() {
        // If these were ever equal we would effectively be using the `plain` method, which
        // gives an attacker who reads the authorization request everything they need.
        val verifier = Pkce.randomValue()
        assertNotEquals(verifier, Pkce.codeChallenge(verifier))
    }

    // --- ID token validation --------------------------------------------------------------

    /** A correctly signed token with matching claims should pass all checks. */
    @Test
    fun validTokenPassesEveryCheck() {
        val token = mintToken(claims())
        val results = validate(token)
        results.forEach { assertTrue("${it.name}: ${it.detail}", it.passed) }
    }

    /** Changing claims while keeping the old signature must fail. */
    @Test
    fun tamperedPayloadFailsSignatureCheck() {
        val token = mintToken(claims())
        // Swap in a different `sub` while keeping the original signature, the classic
        // "I decoded the JWT and trusted it" attack.
        val parts = token.split(".")
        val forgedPayload = encode(claims().put("sub", "attacker").toString())
        val forged = "${parts[0]}.$forgedPayload.${parts[2]}"

        assertFalse(check(validate(forged), "Signature verifies").passed)
    }

    /** A token minted for a different client id must fail `aud`. */
    @Test
    fun tokenForAnotherClientFailsAudienceCheck() {
        // A token that is perfectly valid and correctly signed, just not minted for us.
        val token = mintToken(claims().put("aud", "some.other.app"))
        val results = validate(token)

        assertTrue(check(results, "Signature verifies").passed)
        assertFalse(check(results, "aud is this client").passed)
    }

    /** A nonce from a previous request must fail. */
    @Test
    fun replayedTokenFailsNonceCheck() {
        val token = mintToken(claims().put("nonce", "nonce-from-an-older-sign-in"))
        assertFalse(check(validate(token), "nonce matches our request").passed)
    }

    /** An expired token must fail `exp`. */
    @Test
    fun expiredTokenFailsExpiryCheck() {
        val token = mintToken(claims(expiresAt = NOW - 3600))
        assertFalse(check(validate(token), "exp in the future").passed)
    }

    /** A token from a different issuer must fail `iss`. */
    @Test
    fun tokenFromAnotherIssuerFailsIssuerCheck() {
        val token = mintToken(claims().put("iss", "https://evil.example.com"))
        assertFalse(check(validate(token), "iss matches provider").passed)
    }

    /** `alg=none` tokens must be rejected. */
    @Test
    fun unsignedTokenIsRejected() {
        // alg=none with an empty signature. Several JWT libraries once accepted these.
        val header = encode(JSONObject().put("alg", "none").put("typ", "JWT").toString())
        val payload = encode(claims().toString())
        assertFalse(check(validate("$header.$payload."), "alg is allowed").passed)
    }

    /** A signature from a key not in JWKS must fail. */
    @Test
    fun tokenSignedByAnUnknownKeyIsRejected() {
        val strangerKeys = KeyPairGenerator.getInstance("RSA")
            .apply { initialize(2048) }
            .generateKeyPair()
        val token = mintToken(claims(), signingKey = strangerKeys.private as RSAPrivateKey)

        assertFalse(check(validate(token), "Signature verifies").passed)
    }

    // --- helpers --------------------------------------------------------------------------

    /** Runs the app's validator against a minted JWT. */
    private fun validate(token: String): List<ValidationCheck> = IdTokenValidator.validate(
        jwt = Jwt.parse(token),
        jwks = jwks(),
        expectedIssuer = ISSUER,
        expectedClientId = CLIENT_ID,
        expectedNonce = NONCE,
        nowSeconds = NOW,
    )

    /** Picks one named check from the validator's result list. */
    private fun check(results: List<ValidationCheck>, name: String): ValidationCheck =
        results.first { it.name == name }

    /** Builds a valid set of ID-token claims, with optional expiry/issued-at overrides. */
    private fun claims(
        expiresAt: Long = NOW + 3600,
        issuedAt: Long = NOW,
    ): JSONObject = JSONObject()
        .put("iss", ISSUER)
        .put("sub", "248289761001")
        .put("aud", CLIENT_ID)
        .put("nonce", NONCE)
        .put("exp", expiresAt)
        .put("iat", issuedAt)

    /** Signs a JWT with RS256 using the test key (or a supplied private key). */
    private fun mintToken(
        claims: JSONObject,
        signingKey: RSAPrivateKey = privateKey,
    ): String {
        val header = JSONObject().put("alg", "RS256").put("kid", KEY_ID).put("typ", "JWT")
        val signingInput = "${encode(header.toString())}.${encode(claims.toString())}"
        val signature = Signature.getInstance("SHA256withRSA").run {
            initSign(signingKey)
            update(signingInput.toByteArray(Charsets.US_ASCII))
            sign()
        }
        return "$signingInput.${encode(signature)}"
    }

    /** The public half of the test key, in the JWK shape a provider would publish. */
    private fun jwks(): JSONArray = JSONArray().put(
        JSONObject()
            .put("kty", "RSA")
            .put("use", "sig")
            .put("alg", "RS256")
            .put("kid", KEY_ID)
            .put("n", encode(publicKey.modulus.toUnsignedBytes()))
            .put("e", encode(publicKey.publicExponent.toUnsignedBytes())),
    )

    private companion object {
        const val ISSUER = "https://as.example.com"
        const val CLIENT_ID = "com.rick.oauthopenid"
        const val NONCE = "n-0S6_WzA2Mj"
        const val KEY_ID = "test-key-1"
        const val NOW = 1_789_196_400L

        const val B64_FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP

        private val keyPair by lazy {
            KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        }
        val privateKey: RSAPrivateKey get() = keyPair.private as RSAPrivateKey
        val publicKey: RSAPublicKey get() = keyPair.public as RSAPublicKey

        /** Encodes bytes as base64url with no padding. */
        fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, B64_FLAGS)

        /** Encodes UTF-8 text as a JWT segment. */
        fun encode(text: String): String = encode(text.toByteArray(Charsets.UTF_8))

        /** JWK values are unsigned big-endian; BigInteger adds a sign byte we must drop. */
        fun BigInteger.toUnsignedBytes(): ByteArray = toByteArray().let {
            if (it.size > 1 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it
        }
    }
}
