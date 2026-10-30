package ai.cyberduel.mobile

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import ai.cyberduel.mobile.domain.sharing.ShareLinkParser
import ai.cyberduel.mobile.ui.MainScreen
import ai.cyberduel.mobile.ui.theme.CyberDuelTheme

class MainActivity : ComponentActivity() {

    private var sharedUrlToInspect by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIntent(intent)

        setContent {
            CyberDuelTheme {
                MainScreen(
                    sharedUrl = sharedUrlToInspect,
                    onUrlConsumed = { sharedUrlToInspect = null }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        if (intent == null) return

        if (Intent.ACTION_SEND == intent.action && "text/plain" == intent.type) {
            val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
            val extractedUrls = ShareLinkParser.extractUrls(sharedText)
            if (extractedUrls.isNotEmpty()) {
                sharedUrlToInspect = extractedUrls.first()
            }
        }
    }
}

