package com.rick.oauthopenid.oauth

import androidx.core.net.toUri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 *
 * HTTP or protocol error from the OIDC client.
 *
 *  discovery: returned issuer != to url asked
 *  readBodyOrThrow: http status not 2xx OAuth error JSON body
 *
 *  subclassing this out is clearer in stack traces
 *
 */
class OidcException(message: String) : IOException(message)

/**
 * A deliberately small OAuth 2.0 / OpenID Connect client, written directly against
 * [HttpURLConnection] and `org.json` so every request is visible rather than hidden behind a
 * library.
 *
 * Real apps should use a maintained library. The details that get skipped in a hand-rolled
 * client — JWKS caching and key rotation, single-flight token refresh, exact redirect
 * matching — are precisely the ones that become vulnerabilities.
 */
class OidcClient {

    /**
     *
     * Asks:
     *  Where are your endpoints?
     *
     * Fetches the provider's discovery document.
     *
     * Endpoints come from the provider rather than being hardcoded.
     *
     * Which is what lets this same code work against any conforming OIDC provider.
     *
     */
    suspend fun discover(issuer: String):
            ProviderMetadata = withContext(Dispatchers.IO) {
        val url = "${issuer.trimEnd('/')}/.well-known/openid-configuration"
        val body = httpGet(url)
        val json = JSONObject(body)
        val discoveredIssuer = json.getString("issuer")
        // OIDC Discovery:
        //  The returned issuer MUST be identical to the Issuer URL used.
        //      issuer url vs document url
        if (discoveredIssuer.trimEnd('/') != issuer.trimEnd('/')) {
            throw OidcException(
                "Discovered issuer \"$discoveredIssuer\" does not match configured issuer \"$issuer\"",
            )
        }
        // snapshot of OIDC (open id connect) discover document
        ProviderMetadata(
            issuer = discoveredIssuer,
            authorizationEndpoint = json.getString("authorization_endpoint"),
            tokenEndpoint = json.getString("token_endpoint"),
            jwksUri = json.getString("jwks_uri"),
            userInfoEndpoint = json.optString("userinfo_endpoint").takeIf { it.isNotEmpty() },
            endSessionEndpoint = json.optString("end_session_endpoint").takeIf { it.isNotEmpty() },
            rawJson = json.toString(2),
        )
    }

    /** The provider's public signing keys, used to verify ID token signatures. */
    suspend fun fetchJwks(jwksUri: String): JSONArray = withContext(Dispatchers.IO) {
        JSONObject(httpGet(jwksUri)).getJSONArray("keys")
    }

    /**
     * Builds the `/authorize` URL and the secrets that go with it.
     *
     * Nothing is sent here — this only assembles the URL the browser will open. The
     * `code_verifier` stays on the device; only its SHA-256 hash goes out over the wire.
     */
    fun buildAuthorizationRequest(
        metadata: ProviderMetadata,
        config: OidcConfig,
    ): AuthorizationRequest {
        val codeVerifier = PKCE.randomValue()
        val codeChallenge = PKCE.codeChallenge(codeVerifier)
        val state = PKCE.randomValue(16)
        val nonce = PKCE.randomValue(16)

        val url = metadata.authorizationEndpoint.toUri().buildUpon()
            // "code", never "token": an access token must not travel through the browser.
            .appendQueryParameter("response_type", "code")
            .appendQueryParameter("client_id", config.clientId)
            .appendQueryParameter("redirect_uri", config.redirectUri)
            .appendQueryParameter("scope", config.scope)
            .appendQueryParameter("state", state)
            .appendQueryParameter("nonce", nonce)
            .appendQueryParameter("code_challenge", codeChallenge)
            .appendQueryParameter("code_challenge_method", "S256")
            .build()
            .toString()

        return AuthorizationRequest(url, codeVerifier, codeChallenge, state, nonce)
    }

    /**
     * Redeems the authorization code for tokens.
     *
     * This is the back-channel half of the flow: a direct HTTPS POST, no browser involved.
     * The `code_verifier` is revealed here for the first time, proving we're the same client
     * that made the authorization request.
     */
    suspend fun exchangeCode(
        metadata: ProviderMetadata,
        config: OidcConfig,
        code: String,
        codeVerifier: String,
    ): TokenResponse = postForTokens(
        endpoint = metadata.tokenEndpoint,
        form = mapOf(
            "grant_type" to "authorization_code",
            "code" to code,
            "redirect_uri" to config.redirectUri,
            "client_id" to config.clientId,
            "code_verifier" to codeVerifier,
        ),
    )

    /**
     * Trades a refresh token for a fresh access token.
     *
     * Providers that rotate refresh tokens return a *new* one here and retire the old one, so
     * the response must always be stored. Reusing a retired token is treated as theft and can
     * revoke the whole chain.
     */
    suspend fun refreshTokens(
        metadata: ProviderMetadata,
        config: OidcConfig,
        refreshToken: String,
    ): TokenResponse = postForTokens(
        endpoint = metadata.tokenEndpoint,
        form = mapOf(
            "grant_type" to "refresh_token",
            "refresh_token" to refreshToken,
            "client_id" to config.clientId,
        ),
    )

    /**
     *
     * Profile claims for the signed-in user. Authorized with the *access* token.
     *
     */
    suspend fun getUserInfo(userInfoEndpoint: String, accessToken: String): String =
        withContext(Dispatchers.IO) {
            JSONObject(httpGet(userInfoEndpoint, accessToken)).toString(2)
        }

    /**
     *
     * Calls an ordinary protected API with the access token.
     *      The whole point of OAuth.
     *
     */
    suspend fun callApi(url: String, accessToken: String): String =
        withContext(Dispatchers.IO) {
            val body = httpGet(url, accessToken)
            runCatching { JSONArray(body).toString(2) }
                .recoverCatching { JSONObject(body).toString(2) }
                .getOrDefault(body)
        }

    /** POSTs form fields to the token endpoint and maps the JSON body to [TokenResponse]. */
    private suspend fun postForTokens(
        endpoint: String,
        form: Map<String, String>,
    ): TokenResponse = withContext(Dispatchers.IO) {
        val body = httpPostForm(endpoint, form)
        val json = JSONObject(body)
        TokenResponse(
            accessToken = json.optString("access_token").takeIf { it.isNotEmpty() },
            tokenType = json.optString("token_type").takeIf { it.isNotEmpty() },
            expiresIn = json.optInt("expires_in").takeIf { it > 0 },
            refreshToken = json.optString("refresh_token").takeIf { it.isNotEmpty() },
            idToken = json.optString("id_token").takeIf { it.isNotEmpty() },
            scope = json.optString("scope").takeIf { it.isNotEmpty() },
            rawJson = json.toString(2),
        )
    }

    /** GET with JSON accept; sends a Bearer token in the Authorization header when given. */
    private fun httpGet(url: String, bearerToken: String? = null): String {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = TIMEOUT_MS
            readTimeout = TIMEOUT_MS
            setRequestProperty("Accept", "application/json")
            // The one and only correct place for an access token: the Authorization header.
            // A query string would leak it into server logs and browser history.
            bearerToken?.let { setRequestProperty("Authorization", "Bearer $it") }
        }
        return connection.readBodyOrThrow()
    }

    /** POST `application/x-www-form-urlencoded` fields and return the response body. */
    private fun httpPostForm(url: String, form: Map<String, String>): String {
        val encoded = form.entries.joinToString("&") { (key, value) ->
            "${key.urlEncoded()}=${value.urlEncoded()}"
        }
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = TIMEOUT_MS
            readTimeout = TIMEOUT_MS
            doOutput = true
            setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            setRequestProperty("Accept", "application/json")
        }
        connection.outputStream.use { it.write(encoded.toByteArray(Charsets.UTF_8)) }
        return connection.readBodyOrThrow()
    }

    /** Reads the body and throws [OidcException] on a non-2xx status. */
    private fun HttpURLConnection.readBodyOrThrow(): String = try {
        val status = responseCode
        val stream = if (status in 200..299) inputStream else errorStream
        val body = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        if (status !in 200..299) {
            // OAuth errors are a JSON body with `error` and `error_description`, and reading
            // them is the fastest way to debug a flow that won't complete.
            throw OidcException("HTTP $status from $url\n$body")
        }
        body
    } finally {
        disconnect()
    }

    /** URL-encodes a form field name or value as UTF-8. */
    private fun String.urlEncoded(): String = URLEncoder.encode(this, "UTF-8")

    private companion object {
        const val TIMEOUT_MS = 20_000
    }
}
