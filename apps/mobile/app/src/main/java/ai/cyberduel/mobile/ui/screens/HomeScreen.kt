package ai.cyberduel.mobile.ui.screens

import androidx.compose.foundation.background
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ai.cyberduel.mobile.R
import ai.cyberduel.mobile.data.local.HistoryEntry
import ai.cyberduel.mobile.ui.components.DecisionBadge
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
import ai.cyberduel.mobile.ui.viewmodel.HomeViewModel

@Composable
fun HomeScreen(
    viewModel: HomeViewModel,
    onNavigateToAnalyze: (String) -> Unit,
    onNavigateToHistory: () -> Unit,
    onNavigateToUpdates: () -> Unit,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    var inputUrl by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        viewModel.loadState()
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(CyberBackground)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // App Header
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "CYBERDUEL AI",
                        fontSize = 22.sp,
                        fontWeight = FontWeight.Bold,
                        color = CyberPrimary,
                        letterSpacing = 1.5.sp
                    )
                    Text(
                        text = "Mobile Threat Shield",
                        fontSize = 13.sp,
                        color = TextSecondary
                    )
                }

                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(CyberSurfaceVariant),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_shield_foreground),
                        contentDescription = "Shield",
                        tint = if (state.isProtectionEnabled) DecisionAllow else TextMuted,
                        modifier = Modifier.size(32.dp)
                    )
                }
            }
        }

        // Protection Status Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CyberSurface),
                shape = RoundedCornerShape(16.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = if (state.isProtectionEnabled) "Real-Time Protection Active" else "Protection Paused",
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 15.sp,
                            color = if (state.isProtectionEnabled) DecisionAllow else DecisionWarn
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Policy v${state.policyVersion} • Seq #${state.sequenceNumber}",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            color = TextMuted
                        )
                    }

                    Switch(
                        checked = state.isProtectionEnabled,
                        onCheckedChange = { viewModel.toggleProtection(it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = CyberBackground,
                            checkedTrackColor = DecisionAllow,
                            uncheckedThumbColor = TextMuted,
                            uncheckedTrackColor = CyberSurfaceVariant
                        )
                    )
                }
            }
        }

        // Quick Scan Input Box
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
                        text = "Scan Destination Link",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 15.sp,
                        color = TextPrimary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Enter a URL or share links from any browser or app to inspect.",
                        fontSize = 12.sp,
                        color = TextSecondary
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    OutlinedTextField(
                        value = inputUrl,
                        onValueChange = { inputUrl = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("https://example.com/login", color = TextMuted) },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = CyberPrimary,
                            unfocusedBorderColor = CyberSurfaceVariant,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        shape = RoundedCornerShape(10.dp)
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Button(
                        onClick = {
                            if (inputUrl.isNotBlank()) {
                                onNavigateToAnalyze(inputUrl.trim())
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = CyberPrimary),
                        shape = RoundedCornerShape(10.dp),
                        enabled = inputUrl.isNotBlank()
                    ) {
                        Text("Analyze Link", color = CyberBackground, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // Stats Overview Row
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                StatCard(title = "Total Scans", value = state.totalScans.toString(), color = CyberPrimary, modifier = Modifier.weight(1f))
                StatCard(title = "Threats Blocked", value = state.threatsBlocked.toString(), color = DecisionBlock, modifier = Modifier.weight(1f))
                StatCard(title = "Suspicious", value = state.suspiciousWarned.toString(), color = DecisionWarn, modifier = Modifier.weight(1f))
            }
        }

        // Recent Scans Header
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Recent Activity",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 15.sp,
                    color = TextPrimary
                )
                if (state.recentScans.isNotEmpty()) {
                    Text(
                        text = "View All",
                        fontSize = 13.sp,
                        color = CyberPrimary,
                        modifier = Modifier.clickable { onNavigateToHistory() }
                    )
                }
            }
        }

        if (state.recentScans.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "No recent scans. Analyze a link above or use Share-to-Check.",
                        fontSize = 13.sp,
                        color = TextMuted
                    )
                }
            }
        } else {
            items(state.recentScans) { entry ->
                RecentScanItem(entry = entry, onClick = { onNavigateToAnalyze(entry.rawUrl) })
            }
        }

        item {
            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

@Composable
fun StatCard(title: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(text = value, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = color, fontFamily = FontFamily.Monospace)
            Spacer(modifier = Modifier.height(2.dp))
            Text(text = title, fontSize = 11.sp, color = TextMuted)
        }
    }
}

@Composable
fun RecentScanItem(entry: HistoryEntry, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape = RoundedCornerShape(10.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = entry.rawUrl,
                    maxLines = 1,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    color = TextPrimary
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = "Risk: %.2f • %s".format(entry.riskScore, entry.timestamp.take(19)),
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = TextMuted
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            DecisionBadge(decision = entry.decision)
        }
    }
}

