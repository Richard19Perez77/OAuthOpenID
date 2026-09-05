package com.rick.oauthopenid

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.browser.customtabs.CustomTabsIntent
import androidx.core.net.toUri
import com.rick.oauthopenid.ui.AuthFlowScreen
import com.rick.oauthopenid.ui.AuthFlowViewModel
import com.rick.oauthopenid.ui.theme.OAuthOpenIDTheme

class MainActivity : ComponentActivity() {

    private val viewModel: AuthFlowViewModel by viewModels()

    /** Sets up the Compose UI and checks if this launch is already an OAuth redirect. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            OAuthOpenIDTheme {
                AuthFlowScreen(
                    viewModel = viewModel,
                    onLaunchAuthorization = ::launchAuthorization,
                )
            }
        }
        handlePossibleRedirect(intent)
    }

    /**
     *
     * Returns from browser hook.
     *
     * Reuse on main from singleTask not a new one.
     *
     * The authorization server sends the user back here. Because this activity is
     * `singleTask`, the redirect arrives as a new intent on the existing instance rather than
     * starting a second copy.
     */
    override fun onNewIntent(intent: Intent) {
        // let the base class record the new intent
        super.onNewIntent(intent)
        // replace the old launch intent with this one
        setIntent(intent)
        // url in app redirect and hand it to view model for exchange for tokens
        handlePossibleRedirect(intent)
    }

    /**
     * Opens the authorization request in the system browser via Custom Tabs.
     *
     * RFC 8252 requires this instead of a WebView. A WebView is controlled by this app, so it
     * could read the password the user types into the provider's page; it also has its own
     * cookie jar, which breaks single sign-on, password managers and passkeys.
     */
    private fun launchAuthorization(url: String) {
        CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()
            .launchUrl(this, url.toUri())
    }

    /** If the intent is our OAuth redirect, pass the URI to the ViewModel and consume it. */
    private fun handlePossibleRedirect(intent: Intent?) {
        val data = intent?.data ?: return // can be null
        // redirect uri this app registered
        val expected = viewModel.uiState.config.redirectUri.toUri()
        // schema and host check, matches android manifest intent-filter
        if (data.scheme == expected.scheme && data.host == expected.host) {
            // pass uri into flow for exchange
            viewModel.onRedirect(data.toString())
            // clearing data means redirect is handled
            intent.data = null
        }
    }
}
