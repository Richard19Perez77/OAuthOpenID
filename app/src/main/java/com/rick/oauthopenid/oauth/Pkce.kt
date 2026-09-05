package com.rick.oauthopenid.oauth

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * PKCE, "Proof Key for Code Exchange" (RFC 7636), plus the other random values an
 * authorization request needs.
 *
 * The idea in one line: send a hash out through the browser, keep the original secret on the
 * device, then reveal the secret over the back channel to prove you started the flow. An
 * attacker who intercepts the authorization code never saw the secret, so the code is useless
 * to them.
 */
object Pkce {

    /**
     * `URL_SAFE` gives the base64url alphabet, `NO_PADDING` strips `=`, and `NO_WRAP` keeps it
     * on one line. All three matter: the result goes into a URL, and the server will compute
     * its own encoding and compare strings.
     */
    private const val B64_FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP

    private val secureRandom = SecureRandom()

    /**
     * A high-entropy random string, used for `code_verifier`, `state`, and `nonce`.
     *
     * 32 bytes encodes to 43 characters, the minimum length RFC 7636 allows for a verifier.
     * [SecureRandom] rather than [kotlin.random.Random]: these values are security tokens, and
     * a predictable one defeats the protection entirely.
     */
    fun randomValue(numBytes: Int = 32): String {
        val bytes = ByteArray(numBytes)
        secureRandom.nextBytes(bytes)
        return Base64.encodeToString(bytes, B64_FLAGS)
    }

    /**
     * `code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))` — the `S256` method.
     *
     * The other method the spec defines, `plain`, sends the verifier itself. That is useless
     * against anyone who can read the authorization request, which is exactly the attacker
     * PKCE exists to stop, so this app only ever uses S256.
     */
    fun codeChallenge(codeVerifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(codeVerifier.toByteArray(Charsets.US_ASCII))
        return Base64.encodeToString(digest, B64_FLAGS)
    }
}
