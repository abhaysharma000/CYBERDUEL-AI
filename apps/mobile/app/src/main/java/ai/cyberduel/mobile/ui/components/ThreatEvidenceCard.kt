package ai.cyberduel.mobile.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ai.cyberduel.mobile.data.model.EvidenceItem
import ai.cyberduel.mobile.data.model.ThreatSeverity
import ai.cyberduel.mobile.ui.theme.CyberSurface
import ai.cyberduel.mobile.ui.theme.CyberSurfaceVariant
import ai.cyberduel.mobile.ui.theme.DecisionAllow
import ai.cyberduel.mobile.ui.theme.DecisionBlock
import ai.cyberduel.mobile.ui.theme.DecisionWarn
import ai.cyberduel.mobile.ui.theme.TextMuted
import ai.cyberduel.mobile.ui.theme.TextPrimary
import ai.cyberduel.mobile.ui.theme.TextSecondary

@Composable
fun ThreatEvidenceCard(evidence: EvidenceItem, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier.fillMaxWidth(),
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
                Text(
                    text = evidence.ruleId,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 12.sp,
                    color = TextPrimary
                )

                SeverityBadge(severity = evidence.severity)
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = evidence.description,
                fontSize = 13.sp,
                color = TextSecondary,
                lineHeight = 18.sp
            )

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "Contribution: %+.2f".format(evidence.scoreContribution),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = if (evidence.scoreContribution > 0) DecisionBlock else DecisionAllow
                )

                Text(
                    text = "Confidence: ${(evidence.confidence * 100).toInt()}%",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = TextMuted
                )
            }
        }
    }
}

@Composable
fun SeverityBadge(severity: ThreatSeverity) {
    val (color, text) = when (severity) {
        ThreatSeverity.CRITICAL -> Pair(DecisionBlock, "CRITICAL")
        ThreatSeverity.HIGH -> Pair(DecisionBlock, "HIGH")
        ThreatSeverity.MEDIUM -> Pair(DecisionWarn, "MEDIUM")
        ThreatSeverity.LOW -> Pair(DecisionAllow, "LOW")
    }

    Box(
        modifier = Modifier
            .background(CyberSurfaceVariant, shape = RoundedCornerShape(4.dp))
            .border(1.dp, color.copy(alpha = 0.5f), shape = RoundedCornerShape(4.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(
            text = text,
            color = color,
            fontWeight = FontWeight.Bold,
            fontSize = 10.sp
        )
    }
}

