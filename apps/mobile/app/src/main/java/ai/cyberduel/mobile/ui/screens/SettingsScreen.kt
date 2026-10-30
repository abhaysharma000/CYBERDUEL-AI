package ai.cyberduel.mobile.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ai.cyberduel.mobile.ui.theme.CyberBackground
import ai.cyberduel.mobile.ui.theme.CyberPrimary
import ai.cyberduel.mobile.ui.theme.CyberSurface
import ai.cyberduel.mobile.ui.theme.CyberSurfaceVariant
import ai.cyberduel.mobile.ui.theme.DecisionAllow
import ai.cyberduel.mobile.ui.theme.TextMuted
import ai.cyberduel.mobile.ui.theme.TextPrimary
import ai.cyberduel.mobile.ui.theme.TextSecondary
import ai.cyberduel.mobile.ui.viewmodel.SettingsViewModel

@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    var backendUrlInput by remember(state.backendUrl) { mutableStateOf(state.backendUrl) }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(CyberBackground)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text(
                text = "Settings & Privacy",
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Control local protection preferences and telemetry disclosure.",
                fontSize = 12.sp,
                color = TextSecondary
            )
        }

        // Toggles Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CyberSurface),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                ) {
                    // Protection Switch
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(text = "Local URL Protection", fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = TextPrimary)
                            Text(text = "Evaluate destinations against offline declarative rules & threat DB", fontSize = 11.sp, color = TextSecondary)
                        }
                        Switch(
                            checked = state.isProtectionEnabled,
                            onCheckedChange = { viewModel.setProtectionEnabled(it) },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = CyberBackground,
                                checkedTrackColor = DecisionAllow,
                                uncheckedThumbColor = TextMuted,
                                uncheckedTrackColor = CyberSurfaceVariant
                            )
                        )
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    // Telemetry Switch
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(text = "Privacy-Conscious Telemetry", fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = TextPrimary)
                            Text(text = "Share anonymous threat indicators (no cookies, no sensitive queries)", fontSize = 11.sp, color = TextSecondary)
                        }
                        Switch(
                            checked = state.isTelemetryEnabled,
                            onCheckedChange = { viewModel.setTelemetryEnabled(it) },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = CyberBackground,
                                checkedTrackColor = CyberPrimary,
                                uncheckedThumbColor = TextMuted,
                                uncheckedTrackColor = CyberSurfaceVariant
                            )
                        )
                    }
                }
            }
        }

        // Cloud Backend URL Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CyberSurface),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                ) {
                    Text(text = "Cloud Research Lab Endpoint", fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = TextPrimary)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(text = "Base URL for policy updates and threat intelligence synchronization.", fontSize = 11.sp, color = TextSecondary)

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedTextField(
                        value = backendUrlInput,
                        onValueChange = { backendUrlInput = it },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = CyberPrimary,
                            unfocusedBorderColor = CyberSurfaceVariant,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        shape = RoundedCornerShape(8.dp)
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    Button(
                        onClick = { viewModel.setBackendUrl(backendUrlInput) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = CyberPrimary),
                        shape = RoundedCornerShape(8.dp),
                        enabled = backendUrlInput.isNotBlank() && backendUrlInput != state.backendUrl
                    ) {
                        Text("Save Backend URL", color = CyberBackground, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }
                }
            }
        }

        // Security Scope Disclosure Card (Transparent & Honest Architecture)
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CyberSurface),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                ) {
                    Text(text = "Security Architecture & Scope Disclosure", fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = TextPrimary)
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "• On-Device Evaluation: Threat scoring runs locally using pure declarative AST logic and offline threat DB indicators. No executable code or dynamic bytecode is ever evaluated.\n" +
                                "• Share-to-Check Workflow: Inspects links shared from messaging apps, email, or browsers. No full-device VPN or kernel interception is claimed.\n" +
                                "• Cryptographic Trust: Updates require detached Ed25519 digital signatures and monotonic sequence numbers to prevent downgrade attacks.\n" +
                                "• Anonymous Client ID: ${state.clientId.take(16)}...",
                        fontSize = 11.sp,
                        color = TextSecondary,
                        lineHeight = 17.sp
                    )
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

