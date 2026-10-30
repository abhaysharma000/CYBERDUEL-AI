package ai.cyberduel.mobile.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ai.cyberduel.mobile.ui.theme.CyberSurfaceVariant
import ai.cyberduel.mobile.ui.theme.DecisionAllow
import ai.cyberduel.mobile.ui.theme.DecisionBlock
import ai.cyberduel.mobile.ui.theme.DecisionWarn
import ai.cyberduel.mobile.ui.theme.TextMuted
import ai.cyberduel.mobile.ui.theme.TextPrimary
import kotlin.math.max
import kotlin.math.min

@Composable
fun ScoreGauge(score: Double, modifier: Modifier = Modifier) {
    val clampedScore = min(1.0, max(0.0, score))
    val scoreColor = when {
        clampedScore >= 0.85 -> DecisionBlock
        clampedScore >= 0.50 -> DecisionWarn
        else -> DecisionAllow
    }

    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.Bottom
        ) {
            Text(
                text = "%.2f".format(clampedScore),
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold,
                color = scoreColor,
                fontFamily = FontFamily.Monospace
            )
            Text(
                text = " / 1.00 Risk Score",
                fontSize = 13.sp,
                color = TextMuted,
                modifier = Modifier.padding(bottom = 4.dp, start = 4.dp)
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Progress track
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(10.dp)
                .clip(RoundedCornerShape(5.dp))
                .background(CyberSurfaceVariant)
        ) {
            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .fillMaxWidth(clampedScore.toFloat())
                    .clip(RoundedCornerShape(5.dp))
                    .background(scoreColor)
            )
        }
    }
}

