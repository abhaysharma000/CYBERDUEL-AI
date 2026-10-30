# CyberDuel AI — Android Mobile Security Application

## Status: Operational (Prompt 8/10 Complete)

The CyberDuel AI Android Mobile Security Application (`apps/mobile`) provides native on-device threat protection, local URL scanning, Android Share-to-Check workflow integration, cryptographically authenticated policy updates, and privacy-conscious threat reporting connecting to the CyberDuel AI cloud platform.

---

## 1. Features & Capabilities

- **100% Offline-Capable Local Detection:**
  Evaluates destination URLs entirely on-device without cloud dependence using canonical RFC 3986 URL normalization, 19 structural and lexical features, exact threat indicators (SHA-256 hashes), declarative AST rules, and calibrated heuristic risk scoring.
- **Android Share-to-Check Workflow:**
  Integrates directly with Android's system Share Sheet via `android.intent.action.SEND` (`text/plain`). Users can share suspicious links directly from WhatsApp, Signal, SMS, Gmail, or web browsers for immediate security analysis.
- **Privacy-Preserving Sanitization:**
  Extracts candidate URLs from shared text, strips surrounding punctuation, bounds extraction (max 5 URLs, 4096 chars), and strictly discards surrounding message text. Telemetry reports send only irreversible SHA-256 digests and domain metadata.
- **7-Step Cryptographic Policy Verification:**
  Verifies all downloaded security updates against an on-device 7-step cryptographic pipeline:
  1. Active Trust Anchor Validation (Ed25519 publisher key)
  2. Detached Ed25519 Signature Verification over RFC 8785 canonical JSON
  3. Anti-Replay Monotonic Sequence Ordering ($S_{new} > S_{current}$)
  4. Platform & Engine Version Compatibility (`mobile_app`, `android`, `all`)
  5. Manifest Expiration Cutoff
  6. Artifact Canonical SHA-256 Digest Verification
  7. Pure Declarative AST Safety & Quota Inspection (Zero executable code)
- **Atomic Rollback & Recovery:**
  Automatically backs up previous policies before updates; supports immediate local rollback or emergency remote rollback.
- **Jetpack Compose Material 3 UI:**
  Features a cyber-defense dark theme with Home protection toggle, URL analysis screen, risk gauge, matched evidence cards, update management with multi-channel selection, threat history, and settings.

---

## 2. Directory Structure

```
apps/mobile/
├── app/
│   ├── build.gradle.kts           # Android application module build config
│   ├── proguard-rules.pro         # R8 & Proguard rules for Kotlinx serialization
│   └── src/
│       ├── main/
│       │   ├── AndroidManifest.xml # Permissions, CyberDuelApp, MainActivity, Share filter
│       │   ├── java/ai/cyberduel/mobile/
│       │   │   ├── CyberDuelApp.kt # Application class & service locator
│       │   │   ├── MainActivity.kt # ComponentActivity & intent handler
│       │   │   ├── data/
│       │   │   │   ├── local/      # FactoryDefaults, PolicyStorage, SettingsRepository
│       │   │   │   ├── model/      # Enums, NormalizedURL, PolicyModels, ReleaseModels, Telemetry
│       │   │   │   └── remote/     # ApiClient (OkHttp)
│       │   │   ├── domain/
│       │   │   │   ├── crypto/     # CanonicalJson, DigestUtil, Ed25519Verifier, ClientUpdateVerifier
│       │   │   │   ├── engine/     # URLNormalizer, FeatureExtractor, Heuristics, Rules, ThreatEngine
│       │   │   │   ├── sharing/    # ShareLinkParser
│       │   │   │   └── updates/    # MobileUpdateManager
│       │   │   └── ui/
│       │   │       ├── MainScreen.kt # Navigation Scaffold & tabs
│       │   │       ├── components/   # DecisionBadge, ThreatEvidenceCard, ScoreGauge
│       │   │       ├── screens/      # HomeScreen, AnalysisScreen, UpdateScreen, History, Settings
│       │   │       ├── theme/        # Color, Theme, Type
│       │   │       └── viewmodel/    # HomeViewModel, AnalysisViewModel, UpdateViewModel, SettingsViewModel
│       │   └── res/                # Drawables, mipmaps, strings, colors, themes
│       └── test/java/ai/cyberduel/mobile/ # 39 Unit Tests (100% green)
│           ├── CanonicalJsonTest.kt
│           ├── ClientUpdateVerifierTest.kt
│           ├── DigestUtilTest.kt
│           ├── Ed25519VerifierTest.kt
│           ├── HeuristicsAndRulesTest.kt
│           ├── LocalThreatEngineTest.kt
│           ├── ShareLinkParserTest.kt
│           └── URLNormalizerTest.kt
├── gradle/
│   └── wrapper/                    # Gradle 8.9 wrapper binaries and properties
├── build.gradle.kts                # Root project build configuration (AGP 8.5.1, Kotlin 1.9.24)
├── gradle.properties               # JVM args, android.useAndroidX=true
├── gradlew.bat / gradlew           # Gradle executable wrappers
├── local.properties                # Android SDK directory configuration
├── settings.gradle.kts             # Settings script including :app
└── README.md                       # This document
```

---

## 3. Building and Testing

### Prerequisites
- Java 17 or Java 21 LTS (`JAVA_HOME` set)
- Android SDK (API 34, Build Tools 34.0.0) configured in `local.properties`

### Execute Unit Tests
```powershell
cd apps\mobile
.\gradlew.bat testDebugUnitTest
```

### Build Debug APK
```powershell
cd apps\mobile
.\gradlew.bat assembleDebug
```
The compiled package will be produced at:
`apps/mobile/app/build/outputs/apk/debug/app-debug.apk`

---

## 4. Architecture Documentation
For deep technical architecture, security threat models, and cryptographic protocols, refer to:
[docs/MOBILE_APP_ARCHITECTURE.md](../../docs/MOBILE_APP_ARCHITECTURE.md)
