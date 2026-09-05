package com.rick.oauthopenid.oauth

/**
 *
 * Everything needed to talk to one OpenID Connect provider.
 *
 * Note there is no client secret.
 *
 * This app is a *public client*: the APK ships to devices we don't control, so any secret inside it can be recovered with a zip tool.
 *
 * PKCE takes the place of a secret when proving that the app redeeming the code is the app that requested it.
 *
 */
data class OidcConfig(
    val issuer: String,
    val clientId: String,
    val redirectUri: String,
    val scope: String,
) {
    companion object {
        /**
         * Duende's public demo IdentityServer. Sign in as `alice` / `alice` or `bob` / `bob`.
         *
         * This works with no setup because the demo server deliberately accepts *any* redirect
         * URI for its sample clients. A real authorization server must match redirect URIs
         * exactly, so don't read the demo's permissiveness as normal.
         */
        val DEMO = OidcConfig(
            issuer = "https://demo.duendesoftware.com",
            clientId = "interactive.public",
            redirectUri = "com.rick.oauthopenid://oauth2redirect",
            scope = "openid profile email api offline_access",
        )

        /** A protected API on the demo server, callable with an access token carrying `api` scope. */
        const val DEMO_API = "https://demo.duendesoftware.com/api/test"
    }
}

/**
 * The subset of the provider's discovery document we actually use.
 *
 * Fetching this instead of hardcoding endpoints means the same code works against any
 * OIDC provider, and keeps working when a provider moves an endpoint.
 */
data class ProviderMetadata(
    val issuer: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val jwksUri: String,
    val userInfoEndpoint: String?,
    val endSessionEndpoint: String?,
    val rawJson: String,
)

/** The token endpoint's response. */
data class TokenResponse(
    val accessToken: String?,
    val tokenType: String?,
    val expiresIn: Int?,
    val refreshToken: String?,
    val idToken: String?,
    val scope: String?,
    val rawJson: String,
)

/**
 * The per-request secrets and anti-forgery values. Generated fresh for every authorization
 * request and never reused.
 */
data class AuthorizationRequest(
    val url: String,
    val codeVerifier: String,
    val codeChallenge: String,
    val state: String,
    val nonce: String,
)
