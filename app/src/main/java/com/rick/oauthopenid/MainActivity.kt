package com.rick.oauthopenid

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.browser.customtabs.CustomTabsIntent
import com.rick.oauthopenid.ui.AuthFlowScreen
import com.rick.oauthopenid.ui.AuthFlowViewModel
import com.rick.oauthopenid.ui.theme.OAuthOpenIDTheme

class MainActivity : ComponentActivity() {

    private val viewModel: AuthFlowViewModel by viewModels()

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
     * The authorization server sends the user back here. Because this activity is
     * `singleTask`, the redirect arrives as a new intent on the existing instance rather than
     * starting a second copy.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
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
            .launchUrl(this, Uri.parse(url))
    }

    private fun handlePossibleRedirect(intent: Intent?) {
        val data = intent?.data ?: return
        val expected = Uri.parse(viewModel.uiState.config.redirectUri)
        // Align with the manifest intent-filter and exact redirect-URI guidance: scheme + host.
        if (data.scheme == expected.scheme && data.host == expected.host) {
            viewModel.onRedirect(data.toString())
            // Consume it, so a rotation doesn't replay the same one-time code.
            intent.data = null
        }
    }
}
