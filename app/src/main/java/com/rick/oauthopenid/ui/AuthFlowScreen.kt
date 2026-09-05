package com.rick.oauthopenid.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rick.oauthopenid.oauth.OidcConfig
import com.rick.oauthopenid.oauth.ValidationCheck

private val PASS_COLOR = Color(0xFF2E7D32)
private val FAIL_COLOR = Color(0xFFC62828)
private val IDLE_COLOR = Color(0xFF9E9E9E)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthFlowScreen(
    viewModel: AuthFlowViewModel,
    onLaunchAuthorization: (String) -> Unit,
) {
    val state = viewModel.uiState

    // The ViewModel signals "a URL is ready"; opening the browser is the UI's job.
    LaunchedEffect(state.launchAuthorizationUrl) {
        state.launchAuthorizationUrl?.let { url ->
            onLaunchAuthorization(url)
            viewModel.onAuthorizationLaunched()
        }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("OAuth 2.0 + OpenID Connect", fontWeight = FontWeight.SemiBold)
                        Text(
                            text = "Authorization Code flow with PKCE",
                            style = MaterialTheme.typography.labelMedium,
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
            )
        },
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { ConfigCard(state, viewModel) }
            item { ActionsCard(state, viewModel) }

            state.error?.let { message ->
                item { ErrorCard(message) }
            }

            items(state.steps, key = { it.key }) { step ->
                StepCard(
                    step = step,
                    validation = if (step.key == Steps.VALIDATE) state.validation else emptyList(),
                )
            }

            item { FooterCard() }
        }
    }
}

@Composable
private fun ConfigCard(state: FlowUiState, viewModel: AuthFlowViewModel) {
    var expanded by remember { mutableStateOf(false) }
    val config = state.config
    val editable = !state.busy && !state.signedIn

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Provider", fontWeight = FontWeight.SemiBold)
                    Text(
                        text = config.issuer,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }
                Text(if (expanded) "▾" else "▸", fontSize = 18.sp)
            }

            AnimatedVisibility(expanded) {
                Column {
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = config.issuer,
                        onValueChange = { new -> viewModel.updateConfig { it.copy(issuer = new) } },
                        label = { Text("Issuer") },
                        singleLine = true,
                        enabled = editable,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = config.clientId,
                        onValueChange = { new -> viewModel.updateConfig { it.copy(clientId = new) } },
                        label = { Text("Client ID") },
                        singleLine = true,
                        enabled = editable,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = config.scope,
                        onValueChange = { new -> viewModel.updateConfig { it.copy(scope = new) } },
                        label = { Text("Scopes") },
                        enabled = editable,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = config.redirectUri,
                        onValueChange = {},
                        label = { Text("Redirect URI (fixed by AndroidManifest)") },
                        singleLine = true,
                        enabled = false,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(
                        text = "No client secret: this app is a public client, so PKCE proves it " +
                            "started the flow instead.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    if (config.issuer == OidcConfig.DEMO.issuer) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = "Demo sign-in: alice / alice  ·  bob / bob",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                    if (!editable) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = "Reset the flow to edit these.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ActionsCard(state: FlowUiState, viewModel: AuthFlowViewModel) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(
                    onClick = { viewModel.beginSignIn() },
                    enabled = !state.busy,
                ) {
                    Text(if (state.signedIn) "Sign in again" else "Start sign-in")
                }
                OutlinedButton(
                    onClick = { viewModel.reset() },
                    enabled = !state.busy,
                ) {
                    Text("Reset")
                }
                if (state.busy) {
                    Spacer(Modifier.width(4.dp))
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                }
            }

            if (state.signedIn) {
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = { viewModel.callProtectedApi() },
                        enabled = !state.busy,
                    ) {
                        Text("Call API")
                    }
                    OutlinedButton(
                        onClick = { viewModel.refreshAccessToken() },
                        enabled = !state.busy && state.hasRefreshToken,
                    ) {
                        Text("Refresh token")
                    }
                }
            }
        }
    }
}

@Composable
private fun ErrorCard(message: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
        ),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Flow stopped", fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(message, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun StepCard(step: FlowStep, validation: List<ValidationCheck>) {
    var expanded by remember { mutableStateOf(false) }
    val hasDetail = step.message.isNotEmpty() || step.fields.isNotEmpty() || validation.isNotEmpty()

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(enabled = hasDetail) { expanded = !expanded },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                StatusDot(step.status)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(step.title, fontWeight = FontWeight.SemiBold)
                    Text(step.subtitle, style = MaterialTheme.typography.bodySmall)
                }
                if (hasDetail) {
                    Text(if (expanded) "▾" else "▸", fontSize = 18.sp)
                }
            }

            AnimatedVisibility(expanded && hasDetail) {
                Column {
                    if (step.message.isNotEmpty()) {
                        Spacer(Modifier.height(12.dp))
                        Text(step.message, style = MaterialTheme.typography.bodySmall)
                    }
                    if (validation.isNotEmpty()) {
                        Spacer(Modifier.height(12.dp))
                        validation.forEach { ValidationRow(it) }
                    }
                    step.fields.forEach { field ->
                        Spacer(Modifier.height(12.dp))
                        HorizontalDivider()
                        Spacer(Modifier.height(8.dp))
                        FieldBlock(field)
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusDot(status: StepStatus) {
    val (color, glyph) = when (status) {
        StepStatus.Idle -> IDLE_COLOR to "•"
        StepStatus.Running -> MaterialTheme.colorScheme.primary to "…"
        StepStatus.Done -> PASS_COLOR to "✓"
        StepStatus.Failed -> FAIL_COLOR to "✕"
    }
    Box(
        modifier = Modifier
            .size(24.dp)
            .background(color, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Text(glyph, color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun ValidationRow(check: ValidationCheck) {
    Row(Modifier.padding(vertical = 4.dp)) {
        Text(
            text = if (check.passed) "✓" else "✕",
            color = if (check.passed) PASS_COLOR else FAIL_COLOR,
            fontWeight = FontWeight.Bold,
        )
        Spacer(Modifier.width(10.dp))
        Column {
            Text(check.name, style = MaterialTheme.typography.bodyMedium)
            Text(
                text = check.detail,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
            )
        }
    }
}

@Composable
private fun FieldBlock(field: StepField) {
    var showAll by remember { mutableStateOf(false) }
    val isLong = field.value.length > TRUNCATE_AT
    val shown = if (isLong && !showAll) field.value.take(TRUNCATE_AT) + "…" else field.value

    Column {
        Text(
            text = field.label,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(Modifier.height(4.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    MaterialTheme.colorScheme.surfaceVariant,
                    RoundedCornerShape(6.dp),
                )
                .padding(8.dp),
        ) {
            SelectionContainer {
                Text(
                    text = shown,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                )
            }
        }
        if (isLong) {
            TextButton(onClick = { showAll = !showAll }) {
                Text(
                    text = if (showAll) "Show less" else "Show all (${field.value.length} chars)",
                    fontSize = 12.sp,
                )
            }
        }
    }
}

@Composable
private fun FooterCard() {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Why it looks like this", fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))
            Text(
                text = "Only the one-time code travels through the browser. Tokens are fetched " +
                    "over a direct HTTPS call, so they never appear in a URL, browser history " +
                    "or a server log.\n\n" +
                    "The flow is hand-written here so every value is visible. Production apps " +
                    "should use a maintained library — the easy-to-miss details are exactly the " +
                    "ones that turn into vulnerabilities.\n\n" +
                    "See README.md and OVERVIEW.md in the repo for the full walkthrough.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

private const val TRUNCATE_AT = 240
