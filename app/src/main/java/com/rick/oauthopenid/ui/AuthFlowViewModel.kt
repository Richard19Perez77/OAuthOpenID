package com.rick.oauthopenid.ui

import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.rick.oauthopenid.oauth.AuthorizationRequest
import com.rick.oauthopenid.oauth.IdTokenValidator
import com.rick.oauthopenid.oauth.Jwt
import com.rick.oauthopenid.oauth.OidcClient
import com.rick.oauthopenid.oauth.OidcConfig
import com.rick.oauthopenid.oauth.ProviderMetadata
import com.rick.oauthopenid.oauth.TokenResponse
import com.rick.oauthopenid.oauth.ValidationCheck
import kotlinx.coroutines.launch
import org.json.JSONArray

enum class StepStatus { Idle, Running, Done, Failed }

data class StepField(val label: String, val value: String)

data class FlowStep(
    val key: String,
    val title: String,
    val subtitle: String,
    val status: StepStatus = StepStatus.Idle,
    val message: String = "",
    val fields: List<StepField> = emptyList(),
)

data class FlowUiState(
    val config: OidcConfig = OidcConfig.DEMO,
    val steps: List<FlowStep> = initialSteps(),
    val validation: List<ValidationCheck> = emptyList(),
    /** Set when an authorization URL is ready; the UI consumes it by opening a Custom Tab. */
    val launchAuthorizationUrl: String? = null,
    val busy: Boolean = false,
    val signedIn: Boolean = false,
    val hasRefreshToken: Boolean = false,
    val error: String? = null,
)

object Steps {
    const val DISCOVERY = "discovery"
    const val PKCE = "pkce"
    const val AUTHORIZE = "authorize"
    const val REDIRECT = "redirect"
    const val TOKEN = "token"
    const val ID_TOKEN = "id_token"
    const val VALIDATE = "validate"
    const val API = "api"
}

private fun initialSteps() = listOf(
    FlowStep(
        key = Steps.DISCOVERY,
        title = "1 · Discover the provider",
        subtitle = "GET /.well-known/openid-configuration",
    ),
    FlowStep(
        key = Steps.PKCE,
        title = "2 · Generate PKCE, state and nonce",
        subtitle = "Three random values, three different jobs",
    ),
    FlowStep(
        key = Steps.AUTHORIZE,
        title = "3 · Authorization request",
        subtitle = "Front channel — through the browser",
    ),
    FlowStep(
        key = Steps.REDIRECT,
        title = "4 · Redirect back with the code",
        subtitle = "Verify state, then keep the one-time code",
    ),
    FlowStep(
        key = Steps.TOKEN,
        title = "5 · Token exchange",
        subtitle = "Back channel — direct HTTPS, no browser",
    ),
    FlowStep(
        key = Steps.ID_TOKEN,
        title = "6 · Decode the ID token",
        subtitle = "Base64url only — decoding is not validating",
    ),
    FlowStep(
        key = Steps.VALIDATE,
        title = "7 · Validate the ID token",
        subtitle = "Signature against JWKS, then every claim",
    ),
    FlowStep(
        key = Steps.API,
        title = "8 · Call a protected API",
        subtitle = "Authorization: Bearer <access token>",
    ),
)

class AuthFlowViewModel : ViewModel() {

    var uiState by mutableStateOf(FlowUiState())
        private set

    private val client = OidcClient()

    private var metadata: ProviderMetadata? = null
    private var jwks: JSONArray? = null
    private var pendingRequest: AuthorizationRequest? = null
    private var tokens: TokenResponse? = null

    fun updateConfig(transform: (OidcConfig) -> OidcConfig) {
        uiState = uiState.copy(config = transform(uiState.config))
    }

    /** Steps 1–3: discover, generate the per-request secrets, and build the authorize URL. */
    fun beginSignIn() {
        if (uiState.busy) return
        viewModelScope.launch {
            uiState = FlowUiState(config = uiState.config, busy = true)
            metadata = null
            jwks = null
            pendingRequest = null
            tokens = null

            val config = uiState.config
            setStatus(Steps.DISCOVERY, StepStatus.Running)
            val discovered = try {
                client.discover(config.issuer).also { metadata = it }
            } catch (e: Exception) {
                failStep(Steps.DISCOVERY, "Discovery failed: ${e.message}")
                return@launch
            }

            completeStep(
                key = Steps.DISCOVERY,
                message = "Endpoints resolved from the provider, not hardcoded.",
                fields = listOf(
                    StepField("issuer", discovered.issuer),
                    StepField("authorization_endpoint", discovered.authorizationEndpoint),
                    StepField("token_endpoint", discovered.tokenEndpoint),
                    StepField("jwks_uri", discovered.jwksUri),
                    StepField("userinfo_endpoint", discovered.userInfoEndpoint ?: "(none)"),
                    StepField("Full document", discovered.rawJson),
                ),
            )

            // Fetch signing keys now so step 7 can verify the signature without a stall.
            jwks = try {
                client.fetchJwks(discovered.jwksUri)
            } catch (e: Exception) {
                failStep(Steps.DISCOVERY, "Could not fetch JWKS: ${e.message}")
                return@launch
            }

            val request = client.buildAuthorizationRequest(discovered, config)
            pendingRequest = request

            completeStep(
                key = Steps.PKCE,
                message = "The verifier never leaves the device until step 5. Only its hash goes " +
                    "out through the browser.",
                fields = listOf(
                    StepField("code_verifier (secret)", request.codeVerifier),
                    StepField("code_challenge = SHA256(verifier)", request.codeChallenge),
                    StepField("code_challenge_method", "S256"),
                    StepField("state (CSRF)", request.state),
                    StepField("nonce (replay)", request.nonce),
                ),
            )

            completeStep(
                key = Steps.AUTHORIZE,
                message = "Opening the system browser via Custom Tabs — never a WebView, so the " +
                    "provider keeps its own cookies and the user can see the real URL bar.",
                fields = listOf(StepField("Authorization URL", request.url)),
            )

            uiState = uiState.copy(busy = false, launchAuthorizationUrl = request.url)
        }
    }

    /** Called once the UI has opened the Custom Tab, so the URL isn't launched twice. */
    fun onAuthorizationLaunched() {
        uiState = uiState.copy(launchAuthorizationUrl = null)
    }

    /** Steps 4–7: handle the redirect, exchange the code, then validate what came back. */
    fun onRedirect(redirectUri: String) {
        val request = pendingRequest ?: return
        val discovered = metadata ?: return
        if (uiState.busy) return

        viewModelScope.launch {
            uiState = uiState.copy(busy = true)
            setStatus(Steps.REDIRECT, StepStatus.Running)

            val uri = Uri.parse(redirectUri)
            val error = uri.getQueryParameter("error")
            if (error != null) {
                val description = uri.getQueryParameter("error_description").orEmpty()
                failStep(Steps.REDIRECT, "Provider returned error=$error $description")
                return@launch
            }

            val code = uri.getQueryParameter("code")
            val returnedState = uri.getQueryParameter("state")

            if (code == null) {
                failStep(Steps.REDIRECT, "No authorization code in the redirect")
                return@launch
            }

            // The CSRF check. A mismatch means this callback did not come from the request we
            // started, so the flow must be abandoned rather than "fixed up".
            if (returnedState != request.state) {
                failStep(
                    key = Steps.REDIRECT,
                    message = "state mismatch — expected '${request.state}', got '$returnedState'. " +
                        "Aborting: this response did not come from our request.",
                )
                return@launch
            }

            completeStep(
                key = Steps.REDIRECT,
                message = "state matched, so this really is the response to our request. The code " +
                    "is single-use and useless without the verifier.",
                fields = listOf(
                    StepField("Redirect URI received", redirectUri),
                    StepField("code (one-time)", code),
                    StepField("state returned", returnedState.orEmpty()),
                    StepField("state expected", request.state),
                ),
            )

            setStatus(Steps.TOKEN, StepStatus.Running)
            val tokenResponse = try {
                client.exchangeCode(discovered, uiState.config, code, request.codeVerifier)
            } catch (e: Exception) {
                failStep(Steps.TOKEN, "Token exchange failed: ${e.message}")
                return@launch
            }
            tokens = tokenResponse

            completeStep(
                key = Steps.TOKEN,
                message = "Tokens arrived over a direct HTTPS call. They never touched the browser.",
                fields = listOfNotNull(
                    StepField("token_type", tokenResponse.tokenType ?: "(none)"),
                    StepField("expires_in", tokenResponse.expiresIn?.let { "$it seconds" } ?: "(none)"),
                    StepField("scope", tokenResponse.scope ?: "(none)"),
                    StepField("access_token", tokenResponse.accessToken ?: "(none)"),
                    tokenResponse.refreshToken?.let { StepField("refresh_token", it) },
                    StepField("Raw response", tokenResponse.rawJson),
                ),
            )

            decodeAndValidateIdToken(tokenResponse)

            uiState = uiState.copy(
                busy = false,
                signedIn = tokenResponse.accessToken != null,
                hasRefreshToken = tokenResponse.refreshToken != null,
            )
        }
    }

    private fun decodeAndValidateIdToken(tokenResponse: TokenResponse) {
        val request = pendingRequest ?: return
        val idToken = tokenResponse.idToken
        if (idToken == null) {
            failStep(Steps.ID_TOKEN, "No id_token returned — was 'openid' in the scope?")
            return
        }

        val jwt = try {
            Jwt.parse(idToken)
        } catch (e: Exception) {
            failStep(Steps.ID_TOKEN, "Could not parse the ID token: ${e.message}")
            return
        }

        completeStep(
            key = Steps.ID_TOKEN,
            message = "Anyone can read this — a JWT is encoded, not encrypted. Nothing here is " +
                "trustworthy until step 7 checks the signature.",
            fields = listOf(
                StepField("Header", jwt.prettyHeader()),
                StepField("Payload (claims)", jwt.prettyPayload()),
                StepField("sub — the stable user id", jwt.payload.optString("sub")),
                StepField("Raw id_token", idToken),
            ),
        )

        val keys = jwks
        if (keys == null) {
            failStep(Steps.VALIDATE, "No JWKS available to verify against")
            return
        }

        val checks = IdTokenValidator.validate(
            jwt = jwt,
            jwks = keys,
            expectedIssuer = metadata?.issuer.orEmpty(),
            expectedClientId = uiState.config.clientId,
            expectedNonce = request.nonce,
        )
        val allPassed = checks.all { it.passed }

        uiState = uiState.copy(validation = checks)
        updateStep(Steps.VALIDATE) {
            it.copy(
                status = if (allPassed) StepStatus.Done else StepStatus.Failed,
                message = if (allPassed) {
                    "Every check passed. Only now is it safe to treat this as proof of who signed in."
                } else {
                    "At least one check failed — this token must not be trusted."
                },
            )
        }
    }

    /** Step 8: use the access token the way it is meant to be used. */
    fun callProtectedApi() {
        val accessToken = tokens?.accessToken ?: return
        if (uiState.busy) return
        viewModelScope.launch {
            uiState = uiState.copy(busy = true)
            setStatus(Steps.API, StepStatus.Running)
            try {
                val response = client.callApi(OidcConfig.DEMO_API, accessToken)
                val userInfo = metadata?.userInfoEndpoint?.let {
                    runCatching { client.getUserInfo(it, accessToken) }.getOrNull()
                }
                completeStep(
                    key = Steps.API,
                    message = "The API validated the token itself. It never saw a password, and " +
                        "it does not care who we are beyond what the token allows.",
                    fields = listOfNotNull(
                        StepField("GET ${OidcConfig.DEMO_API}", response),
                        userInfo?.let { StepField("UserInfo endpoint", it) },
                    ),
                )
            } catch (e: Exception) {
                failStep(Steps.API, "API call failed: ${e.message}")
                return@launch
            }
            uiState = uiState.copy(busy = false)
        }
    }

    /** Exchanges the refresh token for a new access token, without involving the user. */
    fun refreshAccessToken() {
        val refreshToken = tokens?.refreshToken ?: return
        val discovered = metadata ?: return
        if (uiState.busy) return
        viewModelScope.launch {
            uiState = uiState.copy(busy = true)
            setStatus(Steps.TOKEN, StepStatus.Running)
            val refreshed = try {
                client.refreshTokens(discovered, uiState.config, refreshToken)
            } catch (e: Exception) {
                failStep(Steps.TOKEN, "Refresh failed: ${e.message}")
                return@launch
            }
            // Store the whole response: with rotation the old refresh token is now dead, and
            // reusing it can revoke the entire token family.
            tokens = refreshed
            completeStep(
                key = Steps.TOKEN,
                message = "Refreshed with no user interaction. Note the new refresh token — the " +
                    "previous one is now retired.",
                fields = listOfNotNull(
                    StepField("expires_in", refreshed.expiresIn?.let { "$it seconds" } ?: "(none)"),
                    StepField("New access_token", refreshed.accessToken ?: "(none)"),
                    refreshed.refreshToken?.let { StepField("New refresh_token", it) },
                    StepField("Raw response", refreshed.rawJson),
                ),
            )
            uiState = uiState.copy(busy = false, hasRefreshToken = refreshed.refreshToken != null)
        }
    }

    /**
     * Clears local state only.
     *
     * This is the weakest of the three levels of "log out": the provider still has a session
     * cookie, so signing in again may not prompt for credentials. A full logout also revokes
     * the tokens and visits the provider's end_session_endpoint.
     */
    fun reset() {
        metadata = null
        jwks = null
        pendingRequest = null
        tokens = null
        uiState = FlowUiState(config = uiState.config)
    }

    private fun setStatus(key: String, status: StepStatus) {
        updateStep(key) { it.copy(status = status) }
    }

    private fun completeStep(key: String, message: String, fields: List<StepField>) {
        updateStep(key) {
            it.copy(status = StepStatus.Done, message = message, fields = fields)
        }
    }

    private fun failStep(key: String, message: String) {
        updateStep(key) { it.copy(status = StepStatus.Failed, message = message) }
        uiState = uiState.copy(busy = false, error = message)
    }

    private fun updateStep(key: String, transform: (FlowStep) -> FlowStep) {
        uiState = uiState.copy(
            steps = uiState.steps.map { if (it.key == key) transform(it) else it },
        )
    }
}
