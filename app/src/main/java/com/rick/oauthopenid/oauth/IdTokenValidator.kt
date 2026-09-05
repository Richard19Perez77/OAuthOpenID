package com.rick.oauthopenid.oauth

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.RSAPublicKeySpec

/** One line of the validation checklist. */
data class ValidationCheck(
    val name: String,
    val passed: Boolean,
    val detail: String,
)

/**
 * Validates an OIDC ID token.
 *
 * Every check here exists because skipping it enables a specific attack. The two most
 * important are the signature (without it the token is unauthenticated JSON) and `aud`
 * (without it, a token minted for a *different* client can be replayed at this one — the
 * token substitution attack that OIDC exists to prevent).
 *
 * A production app should let a maintained library do this. It is spelled out here because
 * reading the checks is the point of this project.
 */
object IdTokenValidator {

    /**
     * Algorithms we're willing to accept. An allowlist rather than "whatever the token says"
     * is deliberate: historically, JWT libraries that trusted the header's `alg` were tricked
     * into accepting `none` (no signature at all), or into verifying an RS256 token as HS256
     * using the *public* key as an HMAC secret — which the attacker also has.
     */
    private val ALLOWED_ALGORITHMS = setOf("RS256")

    /** Tolerance for clock drift between this device and the authorization server. */
    private const val CLOCK_SKEW_SECONDS = 120L

    /** Runs every ID-token check and returns the results in checklist order. */
    fun validate(
        jwt: Jwt,
        jwks: JSONArray,
        expectedIssuer: String,
        expectedClientId: String,
        expectedNonce: String,
        nowSeconds: Long = System.currentTimeMillis() / 1000,
    ): List<ValidationCheck> = listOf(
        checkAlgorithm(jwt),
        checkSignature(jwt, jwks),
        checkIssuer(jwt, expectedIssuer),
        checkAudience(jwt, expectedClientId),
        checkExpiry(jwt, nowSeconds),
        checkIssuedAt(jwt, nowSeconds),
        checkNonce(jwt, expectedNonce),
    )

    /** Rejects `none` and any algorithm outside the RS256 allowlist. */
    private fun checkAlgorithm(jwt: Jwt): ValidationCheck {
        val alg = jwt.algorithm
        return ValidationCheck(
            name = "alg is allowed",
            passed = alg != null && alg in ALLOWED_ALGORITHMS,
            detail = when {
                alg == null -> "No alg in header"
                alg.equals("none", ignoreCase = true) -> "alg=none — unsigned token, rejected"
                alg !in ALLOWED_ALGORITHMS -> "alg=$alg is not in the allowlist $ALLOWED_ALGORITHMS"
                else -> "alg=$alg"
            },
        )
    }

    /**
     * The check that makes everything else meaningful.
     *
     * An RSA public key is just two big integers, the modulus `n` and exponent `e`, which the
     * provider publishes at its `jwks_uri`. We rebuild the key from those and verify the
     * signature over the raw `header.payload` bytes.
     */
    private fun checkSignature(jwt: Jwt, jwks: JSONArray): ValidationCheck {
        val name = "Signature verifies"
        return try {
            val jwk = findKey(jwks, jwt.keyId)
                ?: return ValidationCheck(name, false, "No key in JWKS matching kid=${jwt.keyId}")

            val keyType = jwk.optString("kty")
            if (keyType != "RSA") {
                return ValidationCheck(name, false, "Unsupported key type kty=$keyType")
            }

            val modulus = BigInteger(1, Jwt.decodeSegment(jwk.getString("n")))
            val exponent = BigInteger(1, Jwt.decodeSegment(jwk.getString("e")))
            val publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(RSAPublicKeySpec(modulus, exponent))

            val verified = Signature.getInstance("SHA256withRSA").run {
                initVerify(publicKey)
                update(jwt.signingInput)
                verify(jwt.signature)
            }

            ValidationCheck(
                name = name,
                passed = verified,
                detail = if (verified) {
                    "RS256 signature valid against JWKS key ${jwt.keyId}"
                } else {
                    "Signature did not verify — token was altered or signed by someone else"
                },
            )
        } catch (e: Exception) {
            ValidationCheck(name, false, "Verification error: ${e.message}")
        }
    }

    /** Finds the JWKS entry for this token's `kid`, or the only key if `kid` is omitted. */
    private fun findKey(jwks: JSONArray, kid: String?): JSONObject? {
        val keys = (0 until jwks.length()).mapNotNull { jwks.optJSONObject(it) }
        // Match on kid so key rotation works. If the token omits kid and there's exactly one
        // signing key, that key is unambiguous.
        return keys.firstOrNull { it.optString("kid") == kid }
            ?: keys.singleOrNull().takeIf { kid == null }
    }

    /** Confirms `iss` is exactly the provider we discovered. */
    private fun checkIssuer(jwt: Jwt, expectedIssuer: String): ValidationCheck {
        val issuer = jwt.payload.optString("iss")
        return ValidationCheck(
            name = "iss matches provider",
            // Exact string equality, not startsWith or contains: a sloppy comparison lets
            // https://evil.example.com/?x=https://good.example.com slip through.
            passed = issuer == expectedIssuer,
            detail = if (issuer == expectedIssuer) issuer else "Got '$issuer', expected '$expectedIssuer'",
        )
    }

    /**
     * `aud` is either a single string or an array of strings, and must contain our client id.
     * If `azp` (authorized party) is present it must be our client id too.
     */
    private fun checkAudience(jwt: Jwt, expectedClientId: String): ValidationCheck {
        val audiences = when (val aud = jwt.payload.opt("aud")) {
            is String -> listOf(aud)
            is JSONArray -> (0 until aud.length()).map { aud.getString(it) }
            else -> emptyList()
        }
        val authorizedParty = jwt.payload.optString("azp").takeIf { it.isNotEmpty() }
        val audienceOk = expectedClientId in audiences
        val partyOk = authorizedParty == null || authorizedParty == expectedClientId

        return ValidationCheck(
            name = "aud is this client",
            passed = audienceOk && partyOk,
            detail = when {
                !audienceOk -> "aud=$audiences does not contain '$expectedClientId'"
                !partyOk -> "azp='$authorizedParty' is not '$expectedClientId'"
                else -> "aud=$audiences"
            },
        )
    }

    /** Confirms `exp` is still in the future, allowing a small clock-skew window. */
    private fun checkExpiry(jwt: Jwt, nowSeconds: Long): ValidationCheck {
        val exp = jwt.payload.optLong("exp", 0L)
        val valid = exp > 0 && nowSeconds <= exp + CLOCK_SKEW_SECONDS
        return ValidationCheck(
            name = "exp in the future",
            passed = valid,
            detail = if (exp == 0L) {
                "No exp claim"
            } else {
                "Expires in ${exp - nowSeconds}s (exp=$exp)"
            },
        )
    }

    /** Confirms `iat` is present and not in the far future. */
    private fun checkIssuedAt(jwt: Jwt, nowSeconds: Long): ValidationCheck {
        val iat = jwt.payload.optLong("iat", 0L)
        val valid = iat > 0 && iat <= nowSeconds + CLOCK_SKEW_SECONDS
        return ValidationCheck(
            name = "iat is sane",
            passed = valid,
            detail = if (iat == 0L) {
                "No iat claim"
            } else {
                "Issued ${nowSeconds - iat}s ago (iat=$iat)"
            },
        )
    }

    /**
     * Binds this token to the one authorization request we made. Without it, a token captured
     * from an earlier sign-in could be replayed.
     */
    private fun checkNonce(jwt: Jwt, expectedNonce: String): ValidationCheck {
        val nonce = jwt.payload.optString("nonce")
        return ValidationCheck(
            name = "nonce matches our request",
            passed = nonce.isNotEmpty() && nonce == expectedNonce,
            detail = when {
                nonce.isEmpty() -> "No nonce claim in the token"
                nonce != expectedNonce -> "Got '$nonce', expected '$expectedNonce'"
                else -> nonce
            },
        )
    }
}
