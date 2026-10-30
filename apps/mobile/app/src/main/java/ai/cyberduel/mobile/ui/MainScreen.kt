package ai.cyberduel.mobile.ui

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import ai.cyberduel.mobile.ui.screens.AnalysisScreen
import ai.cyberduel.mobile.ui.screens.HomeScreen
import ai.cyberduel.mobile.ui.screens.SettingsScreen
import ai.cyberduel.mobile.ui.screens.ThreatHistoryScreen
import ai.cyberduel.mobile.ui.screens.UpdateScreen
import ai.cyberduel.mobile.ui.theme.CyberBackground
import ai.cyberduel.mobile.ui.theme.CyberPrimary
import ai.cyberduel.mobile.ui.theme.CyberSurface
import ai.cyberduel.mobile.ui.theme.TextMuted
import ai.cyberduel.mobile.ui.theme.TextSecondary
import ai.cyberduel.mobile.ui.viewmodel.AnalysisViewModel
import ai.cyberduel.mobile.ui.viewmodel.HomeViewModel
import ai.cyberduel.mobile.ui.viewmodel.SettingsViewModel
import ai.cyberduel.mobile.ui.viewmodel.UpdateViewModel

enum class NavigationTab(val label: String, val icon: ImageVector) {
    HOME("Home", Icons.Default.Security),
    ANALYZE("Analyze", Icons.Default.Search),
    UPDATES("Updates", Icons.Default.SystemUpdate),
    HISTORY("History", Icons.Default.History),
    SETTINGS("Settings", Icons.Default.Settings)
}

@Composable
fun MainScreen(
    sharedUrl: String? = null,
    onUrlConsumed: () -> Unit = {}
) {
    var selectedTab by remember { mutableStateOf(NavigationTab.HOME) }
    var activeAnalyzeUrl by remember { mutableStateOf("") }

    val homeViewModel: HomeViewModel = viewModel()
    val analysisViewModel: AnalysisViewModel = viewModel()
    val updateViewModel: UpdateViewModel = viewModel()
    val settingsViewModel: SettingsViewModel = viewModel()

    LaunchedEffect(sharedUrl) {
        if (!sharedUrl.isNullOrBlank()) {
            activeAnalyzeUrl = sharedUrl
            selectedTab = NavigationTab.ANALYZE
            onUrlConsumed()
        }
    }

    Scaffold(
        containerColor = CyberBackground,
        bottomBar = {
            NavigationBar(
                containerColor = CyberSurface,
                contentColor = TextSecondary
            ) {
                NavigationTab.values().forEach { tab ->
                    NavigationBarItem(
                        selected = selectedTab == tab,
                        onClick = { selectedTab = tab },
                        icon = { Icon(imageVector = tab.icon, contentDescription = tab.label) },
                        label = { Text(text = tab.label, fontSize = 11.sp) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = CyberBackground,
                            selectedTextColor = CyberPrimary,
                            indicatorColor = CyberPrimary,
                            unselectedIconColor = TextMuted,
                            unselectedTextColor = TextMuted
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        val contentModifier = Modifier
            .fillMaxSize()
            .padding(innerPadding)

        when (selectedTab) {
            NavigationTab.HOME -> HomeScreen(
                viewModel = homeViewModel,
                onNavigateToAnalyze = { url ->
                    activeAnalyzeUrl = url
                    selectedTab = NavigationTab.ANALYZE
                },
                onNavigateToHistory = {
                    selectedTab = NavigationTab.HISTORY
                },
                onNavigateToUpdates = {
                    selectedTab = NavigationTab.UPDATES
                },
                modifier = contentModifier
            )
            NavigationTab.ANALYZE -> AnalysisScreen(
                viewModel = analysisViewModel,
                initialUrl = activeAnalyzeUrl,
                onNavigateBack = {
                    selectedTab = NavigationTab.HOME
                },
                modifier = contentModifier
            )
            NavigationTab.UPDATES -> UpdateScreen(
                viewModel = updateViewModel,
                modifier = contentModifier
            )
            NavigationTab.HISTORY -> ThreatHistoryScreen(
                onNavigateToAnalyze = { url ->
                    activeAnalyzeUrl = url
                    selectedTab = NavigationTab.ANALYZE
                },
                modifier = contentModifier
            )
            NavigationTab.SETTINGS -> SettingsScreen(
                viewModel = settingsViewModel,
                modifier = contentModifier
            )
        }
    }
}

