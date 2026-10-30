package ai.cyberduel.mobile.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ai.cyberduel.mobile.ui.components.DecisionBadge
import ai.cyberduel.mobile.ui.components.ScoreGauge
import ai.cyberduel.mobile.ui.components.ThreatEvidenceCard
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
import ai.cyberduel.mobile.ui.viewmodel.AnalysisViewModel

@Composable
fun AnalysisScreen(
    viewModel: AnalysisViewModel,
    initialUrl: String = "",
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    var inputUrl by remember { mutableStateOf(initialUrl) }
    var showDisputeDialog by remember { mutableStateOf(false) }
    var disputeReason by remember { mutableStateOf("") }

    LaunchedEffect(initialUrl) {
        if (initialUrl.isNotBlank()) {
            inputUrl = initialUrl
            viewModel.analyze(initialUrl)
        }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(CyberBackground)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Top Bar
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "URL Threat Analysis",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextPrimary
                )

                OutlinedButton(
                    onClick = onNavigateBack,
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("Close", fontSize = 12.sp)
                }
            }
        }

        // Input & Re-analyze row
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = inputUrl,
                    onValueChange = { inputUrl = it },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("https://...", color = TextMuted) },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberPrimary,
                        unfocusedBorderColor = CyberSurfaceVariant,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    ),
                    shape = RoundedCornerShape(8.dp)
                )

                Spacer(modifier = Modifier.width(8.dp))

                Button(
                    onClick = { viewModel.analyze(inputUrl) },
                    colors = ButtonDefaults.buttonColors(containerColor = CyberPrimary),
                    shape = RoundedCornerShape(8.dp),
                    enabled = inputUrl.isNotBlank() && !state.isAnalyzing
                ) {
                    if (state.isAnalyzing) {
                        CircularProgressIndicator(
                            color = CyberBackground,
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Text("Check", color = CyberBackground, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // Analysis Result Card
        if (state.result != null) {
            val result = state.result!!

            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = CyberSurface),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(18.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            DecisionBadge(decision = result.decision)

                            Box(
                                modifier = Modifier
                                    .background(CyberSurfaceVariant, shape = RoundedCornerShape(6.dp))
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    text = "Provenance: ${result.provenance.name.lowercase()}",
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = TextSecondary
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(16.dp))

                        ScoreGauge(score = result.riskScore)

                        Spacer(modifier = Modifier.height(14.dp))

                        Text(
                            text = result.explanation,
                            fontSize = 14.sp,
                            color = TextPrimary,
                            lineHeight = 20.sp
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = "Policy: ${result.policyVersion} • Confidence: ${(result.confidence * 100).toInt()}% • Evaluated: ${result.evaluatedAt.take(19)}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = TextMuted
                        )
                    }
                }
            }

            // Normalization Breakdown Card
            if (state.normalizedUrl != null) {
                val norm = state.normalizedUrl!!
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
                                text = "Canonical Normalization",
                                fontSize = 14.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = TextPrimary
                            )
                            Spacer(modifier = Modifier.height(8.dp))

                            NormRow("Host", norm.host)
                            NormRow("Domain", norm.domain)
                            NormRow("Scheme", norm.scheme)
                            NormRow("Path", norm.path)
                            NormRow("URL SHA-256", norm.urlSha256.take(24) + "...")
                        }
                    }
                }
            }

            // Evidence Header
            item {
                Text(
                    text = "Evaluation Evidence (${result.evidence.size})",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary
                )
            }

            if (result.evidence.isEmpty()) {
                item {
                    Text(
                        text = "No malicious heuristics or threat signatures triggered.",
                        fontSize = 13.sp,
                        color = TextMuted
                    )
                }
            } else {
                items(result.evidence) { ev ->
                    ThreatEvidenceCard(evidence = ev)
                }
            }

            // Dispute / Feedback section
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
                            text = "Incorrect Assessment?",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = TextPrimary
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Submit an anonymous false positive report to improve the threat model.",
                            fontSize = 12.sp,
                            color = TextSecondary
                        )

                        if (state.disputeSuccessMessage != null) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = state.disputeSuccessMessage!!,
                                fontSize = 12.sp,
                                color = DecisionAllow
                            )
                        } else if (!showDisputeDialog) {
                            Spacer(modifier = Modifier.height(10.dp))
                            OutlinedButton(
                                onClick = { showDisputeDialog = true },
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberPrimary),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Text("Report False Positive", fontSize = 12.sp)
                            }
                        } else {
                            Spacer(modifier = Modifier.height(10.dp))
                            OutlinedTextField(
                                value = disputeReason,
                                onValueChange = { disputeReason = it },
                                modifier = Modifier.fillMaxWidth(),
                                placeholder = { Text("Why do you consider this URL safe?", color = TextMuted) },
                                maxLines = 3,
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedBorderColor = CyberPrimary,
                                    unfocusedBorderColor = CyberSurfaceVariant,
                                    focusedTextColor = TextPrimary,
                                    unfocusedTextColor = TextPrimary
                                ),
                                shape = RoundedCornerShape(8.dp)
                            )

                            Spacer(modifier = Modifier.height(8.dp))

                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(
                                    onClick = {
                                        viewModel.submitFalsePositiveDispute(disputeReason)
                                        showDisputeDialog = false
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = CyberPrimary),
                                    shape = RoundedCornerShape(8.dp),
                                    enabled = disputeReason.isNotBlank() && !state.isReportingDispute
                                ) {
                                    Text("Submit Feedback", color = CyberBackground, fontSize = 12.sp)
                                }

                                OutlinedButton(
                                    onClick = { showDisputeDialog = false },
                                    shape = RoundedCornerShape(8.dp)
                                ) {
                                    Text("Cancel", fontSize = 12.sp, color = TextMuted)
                                }
                            }
                        }
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
fun NormRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, fontSize = 12.sp, color = TextMuted)
        Text(text = value, fontSize = 12.sp, fontFamily = FontFamily.Monospace, color = TextPrimary)
    }
}

