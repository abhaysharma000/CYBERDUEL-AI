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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import ai.cyberduel.mobile.CyberDuelApp
import ai.cyberduel.mobile.data.local.HistoryEntry
import ai.cyberduel.mobile.data.model.Decision
import ai.cyberduel.mobile.ui.components.DecisionBadge
import ai.cyberduel.mobile.ui.theme.CyberBackground
import ai.cyberduel.mobile.ui.theme.CyberSurface
import ai.cyberduel.mobile.ui.theme.DecisionBlock
import ai.cyberduel.mobile.ui.theme.TextMuted
import ai.cyberduel.mobile.ui.theme.TextPrimary
import ai.cyberduel.mobile.ui.theme.TextSecondary

@Composable
fun ThreatHistoryScreen(
    onNavigateToAnalyze: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val app = CyberDuelApp.instance
    var historyList by remember { mutableStateOf(app.settingsRepository.getHistory()) }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(CyberBackground)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "Inspection History",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "${historyList.size} destinations analyzed locally",
                        fontSize = 12.sp,
                        color = TextSecondary
                    )
                }

                if (historyList.isNotEmpty()) {
                    OutlinedButton(
                        onClick = {
                            app.settingsRepository.clearHistory()
                            historyList = emptyList()
                        },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = DecisionBlock),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text("Clear", fontSize = 12.sp)
                    }
                }
            }
        }

        if (historyList.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 40.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "History is empty. Scanned links will appear here.",
                        fontSize = 13.sp,
                        color = TextMuted
                    )
                }
            }
        } else {
            items(historyList) { entry ->
                HistoryCard(entry = entry, onClick = { onNavigateToAnalyze(entry.rawUrl) })
            }
        }

        item {
            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

@Composable
fun HistoryCard(entry: HistoryEntry, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                DecisionBadge(decision = entry.decision)

                Text(
                    text = "Risk: %.2f".format(entry.riskScore),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    color = TextPrimary
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = entry.rawUrl,
                maxLines = 2,
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                color = TextPrimary
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = entry.explanation,
                maxLines = 2,
                fontSize = 11.sp,
                color = TextSecondary
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = entry.timestamp.take(19).replace('T', ' '),
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                color = TextMuted
            )
        }
    }
}

