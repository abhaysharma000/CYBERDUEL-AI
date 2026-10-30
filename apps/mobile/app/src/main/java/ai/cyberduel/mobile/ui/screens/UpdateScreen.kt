package ai.cyberduel.mobile.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ai.cyberduel.mobile.data.model.ReleaseChannel
import ai.cyberduel.mobile.domain.updates.UpdateState
import ai.cyberduel.mobile.ui.theme.BorderStroke
import ai.cyberduel.mobile.ui.theme.CyberBackground
import ai.cyberduel.mobile.ui.theme.CyberPrimary
import ai.cyberduel.mobile.ui.theme.CyberSurface
import ai.cyberduel.mobile.ui.theme.CyberSurfaceVariant
import ai.cyberduel.mobile.ui.theme.DecisionAllow
import ai.cyberduel.mobile.ui.theme.DecisionBlock
import ai.cyberduel.mobile.ui.theme.DecisionWarn
import ai.cyberduel.mobile.ui.theme.TextMuted
import ai.cyberduel.mobile.ui.theme.TextPrimary
import ai.cyberduel.mobile.ui.theme.TextSecondary
import ai.cyberduel.mobile.ui.viewmodel.UpdateViewModel

@Composable
fun UpdateScreen(
    viewModel: UpdateViewModel,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val isBusy = state.updateState is UpdateState.Checking ||
            state.updateState is UpdateState.Downloading ||
            state.updateState is UpdateState.Verifying

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(CyberBackground)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text(
                text = "Signed Policy Updates",
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Autonomous threat defenses published via cryptographically signed release manifests.",
                fontSize = 12.sp,
                color = TextSecondary
            )
        }

        // Active Policy Status Card
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
                    Text(
                        text = "Current Active Defense Policy",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = TextPrimary
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(text = "Policy Version", fontSize = 12.sp, color = TextMuted)
                        Text(
                            text = "v${state.activePolicyVersion}",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = CyberPrimary,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    Spacer(modifier = Modifier.height(6.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(text = "Monotonic Sequence", fontSize = 12.sp, color = TextMuted)
                        Text(
                            text = "#${state.sequenceNumber}",
                            fontSize = 12.sp,
                            color = TextPrimary,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    Spacer(modifier = Modifier.height(6.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(text = "Last Check", fontSize = 12.sp, color = TextMuted)
                        Text(
                            text = state.lastCheckTimeFormatted,
                            fontSize = 12.sp,
                            color = TextPrimary,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }

        // Release Channel Selection
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
                    Text(
                        text = "Release Channel",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = TextPrimary
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        ChannelChip(
                            title = "Stable",
                            selected = state.releaseChannel == ReleaseChannel.STABLE,
                            onClick = { viewModel.setReleaseChannel(ReleaseChannel.STABLE) },
                            modifier = Modifier.weight(1f)
                        )
                        ChannelChip(
                            title = "Dev",
                            selected = state.releaseChannel == ReleaseChannel.DEVELOPMENT,
                            onClick = { viewModel.setReleaseChannel(ReleaseChannel.DEVELOPMENT) },
                            modifier = Modifier.weight(1f)
                        )
                        ChannelChip(
                            title = "Canary",
                            selected = state.releaseChannel == ReleaseChannel.CANARY,
                            onClick = { viewModel.setReleaseChannel(ReleaseChannel.CANARY) },
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        }

        // Action & Status Card
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
                    Button(
                        onClick = { viewModel.checkForUpdates() },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = CyberPrimary),
                        shape = RoundedCornerShape(10.dp),
                        enabled = !isBusy
                    ) {
                        if (isBusy) {
                            CircularProgressIndicator(
                                color = CyberBackground,
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Verifying Update...", color = CyberBackground, fontWeight = FontWeight.Bold)
                        } else {
                            Text("Check for Updates Now", color = CyberBackground, fontWeight = FontWeight.Bold)
                        }
                    }

                    if (state.statusMessage != null) {
                        Spacer(modifier = Modifier.height(10.dp))
                        val statusColor = when (state.updateState) {
                            is UpdateState.Installed, is UpdateState.RolledBack -> DecisionAllow
                            is UpdateState.Failed -> DecisionBlock
                            else -> CyberPrimary
                        }
                        Text(
                            text = state.statusMessage!!,
                            fontSize = 12.sp,
                            color = statusColor,
                            lineHeight = 16.sp
                        )
                    }

                    if (state.canRollback) {
                        Spacer(modifier = Modifier.height(10.dp))
                        OutlinedButton(
                            onClick = { viewModel.rollback() },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = DecisionWarn),
                            shape = RoundedCornerShape(10.dp),
                            enabled = !isBusy
                        ) {
                            Text("Rollback to Previous Policy", fontSize = 13.sp)
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = { viewModel.resetToFactory() },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = TextMuted),
                        shape = RoundedCornerShape(10.dp),
                        enabled = !isBusy
                    ) {
                        Text("Reset to Factory Bootstrap Policy", fontSize = 12.sp)
                    }
                }
            }
        }

        // 7-Step Verification Checklist Card
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
                    Text(
                        text = "Client Verification Pipeline (7 Steps)",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = TextPrimary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Updates are verified strictly on-device before installation:",
                        fontSize = 11.sp,
                        color = TextSecondary
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    VerificationStepRow(number = "1", title = "Trust Anchor Validation", detail = "Publisher Ed25519 key must be active and trusted")
                    VerificationStepRow(number = "2", title = "Detached Ed25519 Signature", detail = "Verified against RFC 8785 canonical JSON payload")
                    VerificationStepRow(number = "3", title = "Monotonic Anti-Replay Order", detail = "Seq > current seq prevents downgrade attacks")
                    VerificationStepRow(number = "4", title = "Platform Compatibility", detail = "Matches 'mobile_app'/'android' engine versions")
                    VerificationStepRow(number = "5", title = "Expiration Cutoff Check", detail = "Rejects expired security update manifests")
                    VerificationStepRow(number = "6", title = "SHA-256 Bundle Digest", detail = "Verifies untampered policy artifact payload")
                    VerificationStepRow(number = "7", title = "Declarative AST Safety", detail = "Guarantees zero dynamic code evaluation")
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

@Composable
fun ChannelChip(title: String, selected: Boolean, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val bgColor = if (selected) CyberPrimary.copy(alpha = 0.2f) else CyberSurfaceVariant
    val borderColor = if (selected) CyberPrimary else BorderStroke
    val textColor = if (selected) CyberPrimary else TextSecondary

    Box(
        modifier = modifier
            .background(bgColor, shape = RoundedCornerShape(8.dp))
            .border(1.dp, borderColor, shape = RoundedCornerShape(8.dp))
            .clickable { onClick() }
            .padding(vertical = 8.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(text = title, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = textColor)
    }
}

@Composable
fun VerificationStepRow(number: String, title: String, detail: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.Top
    ) {
        Box(
            modifier = Modifier
                .size(18.dp)
                .background(CyberPrimary.copy(alpha = 0.2f), shape = RoundedCornerShape(4.dp)),
            contentAlignment = Alignment.Center
        ) {
            Text(text = number, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = CyberPrimary)
        }
        Spacer(modifier = Modifier.width(8.dp))
        Column {
            Text(text = title, fontSize = 12.sp, fontWeight = FontWeight.Medium, color = TextPrimary)
            Text(text = detail, fontSize = 10.sp, color = TextMuted)
        }
    }
}

