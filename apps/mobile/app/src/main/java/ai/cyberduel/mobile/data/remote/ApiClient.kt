package ai.cyberduel.mobile.data.remote

import ai.cyberduel.mobile.data.model.PolicyBundle
import ai.cyberduel.mobile.data.model.ReleaseManifest
import ai.cyberduel.mobile.data.model.ThreatObservationReport
import ai.cyberduel.mobile.data.model.TrustAnchorSet
import ai.cyberduel.mobile.data.model.UpdateAcknowledgement
import ai.cyberduel.mobile.data.model.UpdateCheckRequest
import ai.cyberduel.mobile.data.model.UpdateCheckResponse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit

class ApiClient(private var baseUrl: String) {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .build()

    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    fun setBaseUrl(url: String) {
        this.baseUrl = url.trimEnd('/')
    }

    fun getBaseUrl(): String = baseUrl

    suspend fun checkForUpdates(request: UpdateCheckRequest): UpdateCheckResponse = withContext(Dispatchers.IO) {
        val url = "$baseUrl/api/v1/updates/check"
        val requestBody = json.encodeToString(request).toRequestBody(jsonMediaType)
        val httpRequest = Request.Builder()
            .url(url)
            .post(requestBody)
            .build()

        httpClient.newCall(httpRequest).execute().use { response ->
            if (!response.isSuccessful) {
                throw IOException("Update check failed with HTTP ${response.code}: ${response.message}")
            }
            val bodyString = response.body?.string() ?: throw IOException("Empty update response")
            json.decodeFromString<UpdateCheckResponse>(bodyString)
        }
    }

    suspend fun fetchManifest(versionOrId: String): ReleaseManifest = withContext(Dispatchers.IO) {
        val encoded = URLEncoder.encode(versionOrId, StandardCharsets.UTF_8.name())
        val url = "$baseUrl/api/v1/updates/manifests/$encoded"
        val httpRequest = Request.Builder()
            .url(url)
            .get()
            .build()

        httpClient.newCall(httpRequest).execute().use { response ->
            if (!response.isSuccessful) {
                throw IOException("Failed to fetch manifest '$versionOrId': HTTP ${response.code}")
            }
            val bodyString = response.body?.string() ?: throw IOException("Empty manifest response")
            json.decodeFromString<ReleaseManifest>(bodyString)
        }
    }

    suspend fun fetchArtifact(digest: String): Pair<String, PolicyBundle> = withContext(Dispatchers.IO) {
        val encoded = URLEncoder.encode(digest, StandardCharsets.UTF_8.name())
        val url = "$baseUrl/api/v1/updates/artifacts/$encoded"
        val httpRequest = Request.Builder()
            .url(url)
            .get()
            .build()

        httpClient.newCall(httpRequest).execute().use { response ->
            if (!response.isSuccessful) {
                throw IOException("Failed to fetch artifact '$digest': HTTP ${response.code}")
            }
            val rawText = response.body?.string() ?: throw IOException("Empty artifact response")
            val bundle = json.decodeFromString<PolicyBundle>(rawText)
            Pair(rawText, bundle)
        }
    }

    suspend fun sendAcknowledgement(ack: UpdateAcknowledgement): Boolean = withContext(Dispatchers.IO) {
        try {
            val url = "$baseUrl/api/v1/updates/ack"
            val requestBody = json.encodeToString(ack).toRequestBody(jsonMediaType)
            val httpRequest = Request.Builder()
                .url(url)
                .post(requestBody)
                .build()

            httpClient.newCall(httpRequest).execute().use { response ->
                response.isSuccessful
            }
        } catch (_: Exception) {
            false
        }
    }

    suspend fun fetchTrustAnchors(): TrustAnchorSet = withContext(Dispatchers.IO) {
        val url = "$baseUrl/api/v1/updates/trust-anchors"
        val httpRequest = Request.Builder()
            .url(url)
            .get()
            .build()

        httpClient.newCall(httpRequest).execute().use { response ->
            if (!response.isSuccessful) {
                throw IOException("Failed to fetch trust anchors: HTTP ${response.code}")
            }
            val bodyString = response.body?.string() ?: throw IOException("Empty trust anchors response")
            json.decodeFromString<TrustAnchorSet>(bodyString)
        }
    }

    suspend fun reportObservation(report: ThreatObservationReport): Boolean = withContext(Dispatchers.IO) {
        try {
            val url = "$baseUrl/api/v1/telemetry/observations"
            val requestBody = json.encodeToString(report).toRequestBody(jsonMediaType)
            val httpRequest = Request.Builder()
                .url(url)
                .post(requestBody)
                .build()

            httpClient.newCall(httpRequest).execute().use { response ->
                response.isSuccessful
            }
        } catch (_: Exception) {
            false
        }
    }
}

