package com.rick.oauthopenid.oauth

import android.util.Base64
import org.json.JSONObject

/**
 * A parsed JSON Web Token.
 *
 * Parsing is *not* validating. Anyone can mint a JWT with any claims they like; until the
 * signature is checked against the issuer's public key, the payload is just attacker-supplied
 * JSON. [IdTokenValidator] is what makes it trustworthy.
 *
 * A JWT is also only base64-encoded, not encrypted — treat the contents as public.
 */
class Jwt(
    val header: JSONObject,
    val payload: JSONObject,
    /** The exact bytes the signature covers: ASCII of `header.payload`, before decoding. */
    val signingInput: ByteArray,
    val signature: ByteArray,
) {
    val algorithm: String? get() = header.optString("alg").takeIf { it.isNotEmpty() }
    val keyId: String? get() = header.optString("kid").takeIf { it.isNotEmpty() }

    fun prettyHeader(): String = header.toString(2)
    fun prettyPayload(): String = payload.toString(2)

    companion object {
        private const val B64_FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP

        fun decodeSegment(segment: String): ByteArray = Base64.decode(segment, B64_FLAGS)

        /**
         * Splits `header.payload.signature` and decodes the first two segments.
         *
         * @throws IllegalArgumentException if the token isn't three base64url segments.
         */
        fun parse(token: String): Jwt {
            val parts = token.split(".")
            require(parts.size == 3) {
                "Expected 3 dot-separated segments in a JWT, found ${parts.size}"
            }
            val (headerSegment, payloadSegment, signatureSegment) = parts
            return Jwt(
                header = JSONObject(String(decodeSegment(headerSegment), Charsets.UTF_8)),
                payload = JSONObject(String(decodeSegment(payloadSegment), Charsets.UTF_8)),
                signingInput = "$headerSegment.$payloadSegment".toByteArray(Charsets.US_ASCII),
                signature = decodeSegment(signatureSegment),
            )
        }
    }
}
