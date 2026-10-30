package ai.cyberduel.mobile.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ai.cyberduel.mobile.data.model.Decision
import ai.cyberduel.mobile.ui.theme.DecisionAllow
import ai.cyberduel.mobile.ui.theme.DecisionAllowBg
import ai.cyberduel.mobile.ui.theme.DecisionBlock
import ai.cyberduel.mobile.ui.theme.DecisionBlockBg
import ai.cyberduel.mobile.ui.theme.DecisionWarn
import ai.cyberduel.mobile.ui.theme.DecisionWarnBg

@Composable
fun DecisionBadge(decision: Decision, modifier: Modifier = Modifier) {
    val (text, bgColor, textColor, borderColor) = when (decision) {
        Decision.ALLOW -> Quadruple("SAFE", DecisionAllowBg, DecisionAllow, DecisionAllow)
        Decision.WARN -> Quadruple("SUSPICIOUS", DecisionWarnBg, DecisionWarn, DecisionWarn)
        Decision.BLOCK -> Quadruple("THREAT DETECTED", DecisionBlockBg, DecisionBlock, DecisionBlock)
    }

    Box(
        modifier = modifier
            .background(bgColor, shape = RoundedCornerShape(8.dp))
            .border(1.dp, borderColor, shape = RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        Text(
            text = text,
            color = textColor,
            fontWeight = FontWeight.Bold,
            fontSize = 12.sp,
            letterSpacing = 1.sp
        )
    }
}

private data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

