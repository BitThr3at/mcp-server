package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine
import burp.api.montoya.collaborator.*
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpProtocol
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHistoryFilter
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.utilities.Base64Utils
import burp.api.montoya.utilities.RandomUtils
import burp.api.montoya.utilities.URLUtils
import burp.api.montoya.utilities.Utilities
import io.mockk.*
import java.net.InetAddress
import java.time.ZonedDateTime
import java.util.Optional
import io.modelcontextprotocol.kotlin.sdk.CallToolResultBase
import io.modelcontextprotocol.kotlin.sdk.TextContent
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import net.portswigger.mcp.KtorServerManager
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.TestSseMcpClient
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.HttpRequestResponse
import net.portswigger.mcp.schema.toSerializableForm
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.util.regex.Pattern
import javax.swing.JTextArea

class ToolsKtTest {
    
    private val client = TestSseMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api)
    private val testPort = findAvailablePort()
    private var serverStarted = false
    private val config: McpConfig
    private val mockHeaders = mutableListOf<HttpHeader>()
    private val capturedRequest = slot<HttpRequest>()

    init {
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean("enabled") } returns true
            every { getBoolean("configEditingTooling") } returns true
            every { getBoolean("requireHttpRequestApproval") } returns false
            every { getBoolean("requireDataAccessApproval") } returns false
            every { getBoolean("_alwaysAllowHttpHistory") } returns false
            every { getBoolean("_alwaysAllowWebSocketHistory") } returns false
            every { getBoolean("_alwaysAllowOrganizer") } returns false
            every { getString("host") } returns "127.0.0.1"
            every { getString("_autoApproveTargets") } returns ""
            every { getInteger("port") } returns testPort
            every { setBoolean(any(), any()) } returns Unit
            every { setString(any(), any()) } returns Unit
            every { setInteger(any(), any()) } returns Unit
        }
        val mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
            every { logToOutput(any<String>()) } returns Unit
        }

        config = McpConfig(persistedObject, mockLogging)
        
        mockkStatic(HttpHeader::class)
        mockkStatic(burp.api.montoya.http.HttpService::class)
        mockkStatic(HttpRequest::class)
    }

    private fun CallToolResultBase?.expectTextContent(
        expected: String? = null,
    ): String {
        assertNotNull(this, "Tool result cannot be null")
        val result = this!!

        val content = result.content
        assertNotNull(content, "Tool result content cannot be null")

        val nonNullContent = content
        assertEquals(1, nonNullContent.size, "Expected exactly one content element")

        val textContent = nonNullContent.firstOrNull() as? TextContent
        assertNotNull(textContent, "Expected content to be TextContent")

        val text = textContent!!.text
        assertNotNull(text, "Text content cannot be null")

        if (expected != null) {
            assertEquals(expected, text, "Text content doesn't match expected value")
        }

        return text!!
    }

    private fun setupHttpHeaderMocks() {
        every { HttpHeader.httpHeader(any<String>(), any<String>()) } answers {
            val name = firstArg<String>()
            val value = secondArg<String>()
            mockk<HttpHeader>().also {
                every { it.name() } returns name
                every { it.value() } returns value
                mockHeaders.add(it)
            }
        }

        every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } answers {
            val host = firstArg<String>()
            val port = secondArg<Int>()
            val secure = thirdArg<Boolean>()
            mockk<burp.api.montoya.http.HttpService>().also {
                every { it.host() } returns host
                every { it.port() } returns port
                every { it.secure() } returns secure
            }
        }
    }
    
    @BeforeEach
    fun setup() {
        setupHttpHeaderMocks()

        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}")
            assertNotNull(client.ping(), "Ping should return a result")
        }
    }

    private fun findAvailablePort() = ServerSocket(0).use { it.localPort }

    @AfterEach
    fun tearDown() {
        runBlocking { if (client.isConnected()) client.close() }
        serverManager.stop {}
    }

    @Nested
    @Disabled("Tools intentionally disabled: send_http1_request, send_http2_request, create_repeater_tab_http2")
    inner class HttpToolsTests {
        @Test
        fun `http1 line endings should be normalized`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpResponse.toString() } returns "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            every { httpService.sendRequest(capture(capturedRequest)) } returns httpResponse

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\nHost: example.com\n\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { httpService.sendRequest(any<HttpRequest>()) }
            assertEquals("GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n", capturedRequest.captured.toString(), "Request body should match")
        }

        @Test
        fun `http1 request should handle no response`() {
            val httpService = mockk<Http>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpService.sendRequest(any()) } returns null

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }

        @Test
        fun `http2 request should be formatted properly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val requestSlot = slot<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { httpResponse.toString() } returns "HTTP/2 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            every { api.http() } returns httpService
            every { httpService.sendRequest(capture(requestSlot), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "authority" to "example.com", "scheme" to "https", "method" to "GET", ":path" to "/test"
            )
            val headers = mapOf(
                "User-Agent" to "Test Agent", "Accept" to "*/*"
            )
            val requestBody = "Test body"

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { HttpRequest.http2Request(any(), any(), any<String>()) }
            
            assertEquals("Test body", bodySlot.captured, "Request body should match")
            
            val pseudoHeaderList = headersSlot.captured.filter { it.name().startsWith(":") }
            val normalHeaderList = headersSlot.captured.filter { !it.name().startsWith(":") }
            
            assertTrue(pseudoHeaderList.any { it.name() == ":scheme" && it.value() == "https" })
            assertTrue(pseudoHeaderList.any { it.name() == ":method" && it.value() == "GET" })
            assertTrue(pseudoHeaderList.any { it.name() == ":path" && it.value() == "/test" })
            assertTrue(pseudoHeaderList.any { it.name() == ":authority" && it.value() == "example.com" })
            
            assertTrue(normalHeaderList.any { it.name() == "user-agent" && it.value() == "Test Agent" })
            assertTrue(normalHeaderList.any { it.name() == "accept" && it.value() == "*/*" })
        }
        
        @Test
        fun `http2 request should handle null response`() {
            val httpService = mockk<Http>()
            val httpRequest = mockk<HttpRequest>()

            every { HttpRequest.http2Request(any(), any(), any<String>()) } returns httpRequest
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns null

            val pseudoHeaders = mapOf("method" to "GET", "path" to "/test")
            val headers = mapOf("User-Agent" to "Test Agent")

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }
        
        @Test
        fun `http2 pseudo headers should be ordered correctly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), any<String>()) } returns httpRequest
            every { httpResponse.toString() } returns "HTTP/2 200 OK"
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "path" to "/test",
                ":authority" to "example.com", 
                "method" to "GET",
                "scheme" to "https"
            )

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(emptyMap<String, String>()),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )
                
                delay(100)
                assertNotNull(result)
            }
            
            val pseudoHeaderNames = headersSlot.captured
                .filter { it.name().startsWith(":") }
                .map { it.name() }
            
            val expectedOrder = listOf(":scheme", ":method", ":path", ":authority")
            for (i in 0 until minOf(expectedOrder.size, pseudoHeaderNames.size)) {
                assertEquals(expectedOrder[i], pseudoHeaderNames[i],
                    "Pseudo headers should follow the order: scheme, method, path, authority")
            }
        }

        @Test
        fun `create repeater tab http2 should build http2 request`() {
            val repeater = mockk<burp.api.montoya.repeater.Repeater>(relaxed = true)
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { api.repeater() } returns repeater

            val pseudoHeaders = mapOf(
                "method" to "POST", "path" to "/api/x", "authority" to "example.com", "scheme" to "https"
            )
            val headers = mapOf("Content-Type" to "application/json")
            val requestBody = "{\"k\":\"v\"}"

            runBlocking {
                val result = client.callTool(
                    "create_repeater_tab_http2", mapOf(
                        "tabName" to "h2-tab",
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                assertNotNull(result)
            }

            verify(exactly = 1) { repeater.sendToRepeater(httpRequest, "h2-tab") }
            assertEquals("{\"k\":\"v\"}", bodySlot.captured, "Request body should be passed through unchanged")

            val pseudoHeaderNames = headersSlot.captured.filter { it.name().startsWith(":") }.map { it.name() }
            assertEquals(listOf(":scheme", ":method", ":path", ":authority"), pseudoHeaderNames)
            assertTrue(headersSlot.captured.any { it.name() == "content-type" && it.value() == "application/json" })
        }
    }

    @Nested
    @Disabled("Tools intentionally disabled: url_encode, url_decode, base64_encode, base64_decode, generate_random_string")
    inner class UtilityToolsTests {
        @Test
        fun `url encode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.encode(any<String>()) } returns "test+string+with+spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_encode", mapOf(
                        "content" to "test string with spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test+string+with+spaces")
            }
            
            verify(exactly = 1) { urlUtils.encode(any<String>()) }
        }
        
        @Test
        fun `url decode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.decode(any<String>()) } returns "test string with spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_decode", mapOf(
                        "content" to "test+string+with+spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test string with spaces")
            }
            
            verify(exactly = 1) { urlUtils.decode(any<String>()) }
        }
        
        @Test
        fun `base64 encode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.encodeToString(any<String>()) } returns "dGVzdCBzdHJpbmc="
            
            runBlocking {
                val result = client.callTool(
                    "base64_encode", mapOf(
                        "content" to "test string"
                    )
                )
                
                delay(100)
                result.expectTextContent("dGVzdCBzdHJpbmc=")
            }
            
            verify(exactly = 1) { base64Utils.encodeToString(any<String>()) }
        }
        
        @Test
        fun `base64 decode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            val burpByteArray = mockk<ByteArray>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.decode(any<String>()) } returns burpByteArray
            every { burpByteArray.toString() } returns "test string"
            
            runBlocking {
                val result = client.callTool(
                    "base64_decode", mapOf(
                        "content" to "dGVzdCBzdHJpbmc="
                    )
                )
                
                delay(100)
                result.expectTextContent("test string")
            }
            
            verify(exactly = 1) { base64Utils.decode(any<String>()) }
        }
        
        @Test
        fun `generate random string should work properly`() {
            val randomUtils = mockk<RandomUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.randomUtils() } returns randomUtils
            every { randomUtils.randomString(any<Int>(), any<String>()) } returns "1a2b3c1a2b"
            
            runBlocking {
                val result = client.callTool(
                    "generate_random_string", mapOf(
                        "length" to 10,
                        "characterSet" to "abc123"
                    )
                )
                
                delay(100)
                result.expectTextContent("1a2b3c1a2b")
            }
            
            verify(exactly = 1) { randomUtils.randomString(any<Int>(), any<String>()) }
        }
    }
    
    @Nested
    @Disabled("Tools intentionally disabled: set_task_execution_engine_state, set_proxy_intercept_state, set_project_options")
    inner class ConfigurationToolsTests {
        @Test
        fun `set task execution engine state should work properly`() {
            val taskExecutionEngine = mockk<TaskExecutionEngine>()
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            every { taskExecutionEngine.state = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now running")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.RUNNING }
            
            clearMocks(taskExecutionEngine, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now paused")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.PAUSED }
        }
        
        @Test
        fun `set proxy intercept state should work properly`() {
            val proxy = mockk<Proxy>()
            
            every { api.proxy() } returns proxy
            every { proxy.enableIntercept() } just runs
            every { proxy.disableIntercept() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been enabled")
            }
            
            verify(exactly = 1) { proxy.enableIntercept() }
            
            clearMocks(proxy, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been disabled")
            }
            
            verify(exactly = 1) { proxy.disableIntercept() }
        }
        
        @Test
        fun `config editing tools should respect config settings`() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { api.logging().logToOutput(any()) } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("Project configuration has been applied")
            }
            
            verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(any()) }
            
            clearMocks(burpSuite, answers = false)
            
            every { config.configEditingTooling } returns false
            
            runBlocking {
                
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'")
            }
            
            verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        }
    }

    @Nested
    inner class ProxyHistorySummaryTests {
        private val proxy = mockk<Proxy>()

        @BeforeEach
        fun setupProxy() {
            unmockkStatic("net.portswigger.mcp.schema.SerializationKt")
            every { api.proxy() } returns proxy
        }

        private fun bodyOffsetOf(message: String): Int {
            val blankLine = message.indexOf("\r\n\r\n")
            return if (blankLine < 0) message.length else blankLine + 4
        }

        private fun historyItem(
            id: Int,
            method: String = "POST",
            path: String = "/PaymentProcessing.aspx",
            host: String = "www.travelboutiqueonline.com",
            port: Int = 443,
            secure: Boolean = true,
            hasParams: Boolean = true,
            edited: Boolean = false,
            statusCode: Short? = 200,
            responseLength: Int = 870,
            mimeType: MimeType = MimeType.HTML,
            requestText: String = "$method $path HTTP/1.1\r\nHost: $host\r\n\r\n",
            responseText: String = "HTTP/1.1 200 OK\r\n\r\nbody",
            notes: String = "",
            requestHeaders: Map<String, String> = emptyMap(),
            responseHeaders: Map<String, String> = emptyMap()
        ): ProxyHttpRequestResponse {
            val scheme = if (secure) "https" else "http"

            fun headerMocks(headers: Map<String, String>): List<HttpHeader> = headers.map { (name, value) ->
                mockk<HttpHeader>().also {
                    every { it.name() } returns name
                    every { it.value() } returns value
                }
            }

            val request = mockk<HttpRequest>().also {
                every { it.hasParameters() } returns hasParams
                every { it.toString() } returns requestText
                every { it.bodyOffset() } returns bodyOffsetOf(requestText)
                every { it.method() } returns method
                every { it.path() } returns path
                every { it.url() } returns "$scheme://$host$path"
                every { it.hasHeader(any<String>()) } answers { requestHeaders.containsKey(firstArg<String>()) }
                every { it.headerValue(any<String>()) } answers { requestHeaders[firstArg<String>()] }
                every { it.headers() } returns headerMocks(requestHeaders)
            }

            val response = statusCode?.let { code ->
                mockk<burp.api.montoya.http.message.responses.HttpResponse>().also {
                    every { it.statusCode() } returns code
                    every { it.toByteArray() } returns mockk<ByteArray>().also { bytes ->
                        every { bytes.length() } returns responseLength
                    }
                    every { it.toString() } returns responseText
                    every { it.bodyOffset() } returns bodyOffsetOf(responseText)
                    every { it.hasHeader(any<String>()) } answers { responseHeaders.containsKey(firstArg<String>()) }
                    every { it.headerValue(any<String>()) } answers { responseHeaders[firstArg<String>()] }
                    every { it.headers() } returns headerMocks(responseHeaders)
                }
            }

            val httpService = mockk<burp.api.montoya.http.HttpService>().also {
                every { it.host() } returns host
                every { it.port() } returns port
                every { it.secure() } returns secure
            }

            return mockk<ProxyHttpRequestResponse>().also {
                every { it.id() } returns id
                every { it.httpService() } returns httpService
                every { it.edited() } returns edited
                every { it.mimeType() } returns mimeType
                every { it.hasResponse() } returns (statusCode != null)
                every { it.request() } returns request
                every { it.response() } returns response
                every { it.contains(any<Pattern>()) } answers {
                    firstArg<Pattern>().matcher(requestText + responseText).find()
                }
                every { it.annotations() } returns mockk<burp.api.montoya.core.Annotations>().also { annotations ->
                    every { annotations.notes() } returns notes
                }
            }
        }

        /** Applies the tool's own [ProxyHistoryFilter] the way Burp would, so filters are really exercised. */
        private fun filterableHistory(items: List<ProxyHttpRequestResponse>) {
            every { proxy.history(any()) } answers {
                val filter = firstArg<ProxyHistoryFilter>()
                items.filter { filter.matches(it) }
            }
        }

        private fun summaryIds(text: String): List<Int> =
            Regex("\"id\":(\\d+)").findAll(text).map { it.groupValues[1].toInt() }.toList()

        @Test
        fun `summary should report burp history columns`() {
            every { proxy.history() } returns listOf(historyItem(54160))

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "count" to 10,
                        "offset" to 0
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertEquals(
                    "{\"id\":54160,\"host\":\"https://www.travelboutiqueonline.com\",\"method\":\"POST\"," +
                            "\"url\":\"/PaymentProcessing.aspx\",\"params\":true,\"edited\":false," +
                            "\"statusCode\":200,\"length\":870}\n\n" +
                            "-- showing 1-1 of 1 (oldest first), no more items --",
                    text
                )
            }
        }

        @Test
        fun `summary should omit status code and length when there is no response`() {
            every { proxy.history() } returns listOf(historyItem(1, statusCode = null))

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "count" to 10,
                        "offset" to 0
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"statusCode\":null"), "Expected null status code in: $text")
                assertTrue(text.contains("\"length\":null"), "Expected null length in: $text")
            }
        }

        @Test
        fun `summary should include the port for non-default ports`() {
            every { proxy.history() } returns listOf(historyItem(1, secure = false, port = 8080))

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "count" to 10,
                        "offset" to 0
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertTrue(
                    text.contains("\"host\":\"http://www.travelboutiqueonline.com:8080\""),
                    "Expected scheme and port in: $text"
                )
            }
        }

        @Test
        fun `summary should page from the newest item and report totals`() {
            every { proxy.history() } returns (1..5).map { historyItem(it, path = "/item$it") }

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "count" to 2,
                        "offset" to 0,
                        "newestFirst" to true
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertEquals(listOf(5, 4), summaryIds(text))
                assertTrue(
                    text.endsWith("-- showing 1-2 of 5 (newest first), nextOffset=2 --"),
                    "Expected a pagination footer in: $text"
                )
            }
        }

        @Test
        fun `summary should report the total when the offset is past the end`() {
            every { proxy.history() } returns listOf(historyItem(1), historyItem(2))

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "count" to 2,
                        "offset" to 5
                    )
                )

                delay(100)
                result.expectTextContent("Reached end of items (2 total)")
            }
        }

        @Test
        fun `summary should reject a non-positive count`() {
            every { proxy.history() } returns listOf(historyItem(1))

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "count" to 0,
                        "offset" to 0
                    )
                )

                delay(100)
                result.expectTextContent("count must be greater than 0")
            }
        }

        @Test
        fun `summary should filter on host method status code and mime type`() {
            filterableHistory(
                listOf(
                    historyItem(1, host = "api.example.com", method = "GET", statusCode = 200, mimeType = MimeType.JSON),
                    historyItem(2, host = "api.example.com", method = "POST", statusCode = 500, mimeType = MimeType.JSON),
                    historyItem(3, host = "www.example.com", method = "GET", statusCode = 200, mimeType = MimeType.HTML)
                )
            )

            runBlocking {
                val byHost = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "host" to "API.example",
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                assertEquals(listOf(1, 2), summaryIds(byHost.expectTextContent()))

                val byMethodAndStatus = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "method" to "get",
                        "statusCode" to 200,
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                assertEquals(listOf(1, 3), summaryIds(byMethodAndStatus.expectTextContent()))

                val byMimeType = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "mimeType" to "json",
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                assertEquals(listOf(1, 2), summaryIds(byMimeType.expectTextContent()))
            }

            verify(exactly = 0) { proxy.history() }
        }

        @Test
        fun `summary should filter on header presence and value in the requested scope`() {
            filterableHistory(
                listOf(
                    historyItem(1, requestHeaders = mapOf("Authorization" to "Bearer abc")),
                    historyItem(2, requestHeaders = emptyMap()),
                    historyItem(3, responseHeaders = mapOf("Set-Cookie" to "session=1337; Path=/"))
                )
            )

            runBlocking {
                val byPresence = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "headerName" to "Authorization",
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                assertEquals(listOf(1), summaryIds(byPresence.expectTextContent()))

                val byValueInResponse = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "headerName" to "Set-Cookie",
                        "headerValueContains" to "1337",
                        "headerIn" to "response",
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                assertEquals(listOf(3), summaryIds(byValueInResponse.expectTextContent()))

                val missingInRequestOnly = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "headerName" to "Set-Cookie",
                        "headerIn" to "request",
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                assertEquals(emptyList<Int>(), summaryIds(missingInRequestOnly.expectTextContent()))
            }
        }

        @Test
        fun `summary should search every header for a substring when headerName is omitted`() {
            filterableHistory(
                listOf(
                    historyItem(1, responseHeaders = mapOf("Server" to "nginx/4.0.1")),
                    historyItem(2, requestHeaders = mapOf("X-Powered-By" to "PHP/4.0.1")),
                    historyItem(3, responseHeaders = mapOf("Server" to "nginx/1.25.0"))
                )
            )

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "headerValueContains" to "4.0.1",
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                assertEquals(listOf(1, 2), summaryIds(result.expectTextContent()))
            }
        }

        @Test
        fun `summary should filter on url substring id range and missing responses`() {
            filterableHistory(
                listOf(
                    historyItem(10, path = "/PaymentProcessing.aspx"),
                    historyItem(20, path = "/AjaxHandler.aspx"),
                    historyItem(30, path = "/PaymentHistory.aspx", statusCode = null)
                )
            )

            runBlocking {
                val byUrl = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "urlContains" to "payment",
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                assertEquals(listOf(10, 30), summaryIds(byUrl.expectTextContent()))

                val byIdRange = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "fromId" to 20,
                        "toId" to 29,
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                assertEquals(listOf(20), summaryIds(byIdRange.expectTextContent()))

                val withoutResponse = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "hasResponse" to false,
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                assertEquals(listOf(30), summaryIds(withoutResponse.expectTextContent()))
            }
        }

        @Test
        fun `summary should filter on burp target scope`() {
            val scope = mockk<burp.api.montoya.scope.Scope>()
            every { api.scope() } returns scope
            every { scope.isInScope(any()) } answers { firstArg<String>().contains("in-scope") }

            filterableHistory(
                listOf(
                    historyItem(1, host = "in-scope.example.com"), historyItem(2, host = "other.example.com")
                )
            )

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "inScopeOnly" to true,
                        "count" to 10,
                        "offset" to 0
                    )
                )

                delay(100)
                assertEquals(listOf(1), summaryIds(result.expectTextContent()))
            }
        }

        @Test
        fun `summary regex should search request and response bodies`() {
            filterableHistory(
                listOf(
                    historyItem(
                        1,
                        requestText = "POST /login HTTP/1.1\r\nHost: h\r\n\r\nuser=admin&token=SECRET-A",
                        responseText = "HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}"
                    ),
                    historyItem(
                        2,
                        requestText = "GET /profile HTTP/1.1\r\nHost: h\r\n\r\n",
                        responseText = "HTTP/1.1 200 OK\r\n\r\n{\"session\":\"SECRET-B\"}"
                    ),
                    historyItem(
                        3,
                        requestText = "GET /health HTTP/1.1\r\nHost: h\r\n\r\n",
                        responseText = "HTTP/1.1 200 OK\r\n\r\nfine"
                    )
                )
            )

            runBlocking {
                val bothBodies = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "regex" to "SECRET-\\w",
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                val bothText = bothBodies.expectTextContent()
                assertEquals(listOf(1, 2), summaryIds(bothText))
                assertTrue(bothText.contains("\"matchedIn\":[\"request\"],\"match\":\"SECRET-A\""), bothText)
                assertTrue(bothText.contains("\"matchedIn\":[\"response\"],\"match\":\"SECRET-B\""), bothText)

                val responsesOnly = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "regex" to "SECRET-\\w",
                        "searchIn" to "response",
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                assertEquals(listOf(2), summaryIds(responsesOnly.expectTextContent()))

                val requestsOnly = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "regex" to "SECRET-\\w",
                        "searchIn" to "request",
                        "count" to 10,
                        "offset" to 0
                    )
                )
                delay(100)
                assertEquals(listOf(1), summaryIds(requestsOnly.expectTextContent()))
            }
        }

        @Test
        fun `summary regex should report a hit in both messages`() {
            filterableHistory(
                listOf(
                    historyItem(
                        1,
                        requestText = "GET /x HTTP/1.1\r\n\r\nneedle",
                        responseText = "HTTP/1.1 200 OK\r\n\r\nneedle"
                    )
                )
            )

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "regex" to "needle",
                        "count" to 10,
                        "offset" to 0
                    )
                )

                delay(100)
                assertTrue(
                    result.expectTextContent().contains("\"matchedIn\":[\"request\",\"response\"]"),
                    "Expected both messages to be reported"
                )
            }
        }

        @Test
        fun `summary should omit match details when no regex is given`() {
            every { proxy.history() } returns listOf(historyItem(1))

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "count" to 10,
                        "offset" to 0
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("matchedIn"), "matchedIn should be absent: $text")
                assertFalse(text.contains("\"match\""), "match should be absent: $text")
            }
        }

        @Test
        fun `summary should reject an unknown searchIn value`() {
            every { proxy.history() } returns listOf(historyItem(1))

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "regex" to "x",
                        "searchIn" to "headers",
                        "count" to 10,
                        "offset" to 0
                    )
                )

                delay(100)
                result.expectTextContent("searchIn must be one of 'both', 'request' or 'response'")
            }
        }

        @Test
        fun `summary should filter by regex and paginate`() {
            filterableHistory(
                listOf(
                    historyItem(1, path = "/one"), historyItem(2, path = "/two"), historyItem(3, path = "/three")
                )
            )

            runBlocking {
                val page1 = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "regex" to "HTTP/1\\.1",
                        "count" to 2,
                        "offset" to 0
                    )
                )

                delay(100)
                val text1 = page1.expectTextContent()
                assertTrue(text1.contains("\"url\":\"/one\""))
                assertTrue(text1.contains("\"url\":\"/two\""))
                assertFalse(text1.contains("\"url\":\"/three\""))

                val page2 = client.callTool(
                    "get_proxy_http_history_summary", mapOf(
                        "regex" to "HTTP/1\\.1",
                        "count" to 2,
                        "offset" to 2
                    )
                )

                delay(100)
                assertTrue(page2.expectTextContent().contains("\"url\":\"/three\""))
            }

            verify(exactly = 0) { proxy.history() }
        }

        @Test
        fun `item should return the full request and response for an id`() {
            every { proxy.history() } returns listOf(
                historyItem(54018, path = "/other"),
                historyItem(
                    54019,
                    requestText = "POST /PaymentProcessing.aspx HTTP/1.1",
                    responseText = "HTTP/1.1 200 OK",
                    notes = "interesting"
                )
            )

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_item", mapOf(
                        "ids" to Json.encodeToJsonElement(listOf(54019))
                    )
                )

                delay(100)
                result.expectTextContent(
                    "[{\"id\":54019,\"request\":\"POST /PaymentProcessing.aspx HTTP/1.1\"," +
                            "\"response\":\"HTTP/1.1 200 OK\",\"notes\":\"interesting\"," +
                            "\"requestBodyLength\":0,\"responseBodyLength\":0}]"
                )
            }
        }

        @Test
        fun `item should return only the requested message`() {
            every { proxy.history() } returns listOf(
                historyItem(1, requestText = "GET /x HTTP/1.1\r\n\r\nreq", responseText = "HTTP/1.1 200 OK\r\n\r\nresp")
            )

            runBlocking {
                val onlyResponse = client.callTool(
                    "get_proxy_http_history_item", mapOf(
                        "ids" to Json.encodeToJsonElement(listOf(1)),
                        "include" to "response"
                    )
                )
                delay(100)
                val responseText = onlyResponse.expectTextContent()
                assertFalse(responseText.contains("\"request\""), "Request should be omitted: $responseText")
                assertTrue(responseText.contains("\"response\":\"HTTP/1.1 200 OK\\r\\n\\r\\nresp\""))

                val onlyRequest = client.callTool(
                    "get_proxy_http_history_item", mapOf(
                        "ids" to Json.encodeToJsonElement(listOf(1)),
                        "include" to "request"
                    )
                )
                delay(100)
                val requestText = onlyRequest.expectTextContent()
                assertFalse(requestText.contains("\"response\""), "Response should be omitted: $requestText")
                assertTrue(requestText.contains("\"request\":\"GET /x HTTP/1.1\\r\\n\\r\\nreq\""))
            }
        }

        @Test
        fun `item should reject an unknown include value`() {
            every { proxy.history() } returns listOf(historyItem(1))

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_item", mapOf(
                        "ids" to Json.encodeToJsonElement(listOf(1)),
                        "include" to "headers"
                    )
                )

                delay(100)
                result.expectTextContent("include must be one of 'both', 'request' or 'response'")
            }
        }

        @Test
        fun `item should drop bodies when headersOnly is set`() {
            every { proxy.history() } returns listOf(
                historyItem(
                    1,
                    requestText = "GET /x HTTP/1.1\r\nHost: h\r\n\r\nrequest body",
                    responseText = "HTTP/1.1 200 OK\r\nServer: s\r\n\r\nresponse body"
                )
            )

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_item", mapOf(
                        "ids" to Json.encodeToJsonElement(listOf(1)),
                        "headersOnly" to true
                    )
                )

                delay(100)
                result.expectTextContent(
                    "[{\"id\":1,\"request\":\"GET /x HTTP/1.1\\r\\nHost: h\\r\\n\\r\\n\"," +
                            "\"response\":\"HTTP/1.1 200 OK\\r\\nServer: s\\r\\n\\r\\n\",\"notes\":\"\"," +
                            "\"requestBodyLength\":12,\"responseBodyLength\":13}]"
                )
            }
        }

        @Test
        fun `item should window the body and keep the headers`() {
            every { proxy.history() } returns listOf(
                historyItem(
                    1,
                    requestText = "GET /x HTTP/1.1\r\n\r\nabcdefghij",
                    responseText = "HTTP/1.1 200 OK\r\n\r\n0123456789"
                )
            )

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_item", mapOf(
                        "ids" to Json.encodeToJsonElement(listOf(1)),
                        "include" to "response",
                        "bodyOffset" to 4,
                        "bodyLength" to 3
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertTrue(
                    text.contains(
                        "\"response\":\"HTTP/1.1 200 OK\\r\\n\\r\\n... (skipped first 4 characters of body)\\n456... (truncated)\""
                    ),
                    "Expected a windowed body in: $text"
                )
                assertTrue(text.contains("\"responseBodyLength\":10"), "Full body length should be reported: $text")
            }
        }

        @Test
        fun `item should return several ids in the order requested`() {
            every { proxy.history() } returns listOf(
                historyItem(1, requestText = "GET /one HTTP/1.1", responseText = "HTTP/1.1 200 one"),
                historyItem(2, requestText = "GET /two HTTP/1.1", responseText = "HTTP/1.1 200 two"),
                historyItem(3, requestText = "GET /three HTTP/1.1", responseText = "HTTP/1.1 200 three")
            )

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_item", mapOf(
                        "ids" to Json.encodeToJsonElement(listOf(3, 1, 3))
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertEquals(
                    "[{\"id\":3,\"request\":\"GET /three HTTP/1.1\",\"response\":\"HTTP/1.1 200 three\",\"notes\":\"\"," +
                            "\"requestBodyLength\":0,\"responseBodyLength\":0}," +
                            "{\"id\":1,\"request\":\"GET /one HTTP/1.1\",\"response\":\"HTTP/1.1 200 one\",\"notes\":\"\"," +
                            "\"requestBodyLength\":0,\"responseBodyLength\":0}]",
                    text
                )
            }
        }

        @Test
        fun `item should report ids that are missing alongside the ones found`() {
            every { proxy.history() } returns listOf(
                historyItem(1, requestText = "GET /one HTTP/1.1", responseText = "HTTP/1.1 200 one")
            )

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_item", mapOf(
                        "ids" to Json.encodeToJsonElement(listOf(1, 42, 43))
                    )
                )

                delay(100)
                result.expectTextContent(
                    "[{\"id\":1,\"request\":\"GET /one HTTP/1.1\",\"response\":\"HTTP/1.1 200 one\",\"notes\":\"\"," +
                            "\"requestBodyLength\":0,\"responseBodyLength\":0}]\n" +
                            "No proxy HTTP history items with ids: 42, 43"
                )
            }
        }

        @Test
        fun `item should reject an empty id list`() {
            every { proxy.history() } returns listOf(historyItem(1))

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_item", mapOf(
                        "ids" to Json.encodeToJsonElement(emptyList<Int>())
                    )
                )

                delay(100)
                result.expectTextContent("No ids requested")
            }
        }

        @Test
        fun `item should cap the body and keep the headers when maxLength is set`() {
            every { proxy.history() } returns listOf(
                historyItem(
                    7,
                    requestText = "GET /long HTTP/1.1\r\n\r\nabcdefghij",
                    responseText = "HTTP/1.1 200 OK\r\n\r\n0123456789"
                )
            )

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_item", mapOf(
                        "ids" to Json.encodeToJsonElement(listOf(7)),
                        "maxLength" to 4
                    )
                )

                delay(100)
                result.expectTextContent(
                    "[{\"id\":7,\"request\":\"GET /long HTTP/1.1\\r\\n\\r\\nabcd... (truncated)\"," +
                            "\"response\":\"HTTP/1.1 200 OK\\r\\n\\r\\n0123... (truncated)\",\"notes\":\"\"," +
                            "\"requestBodyLength\":10,\"responseBodyLength\":10}]"
                )
            }
        }

        @Test
        fun `item should keep a windowed body even when maxLength is smaller than the headers`() {
            val longHeaders = "HTTP/1.1 200 OK\r\n" + (1..20).joinToString("") { "X-Filler-$it: padding value\r\n" }

            every { proxy.history() } returns listOf(
                historyItem(1, responseText = "$longHeaders\r\n0123456789abcdefghij")
            )

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_item", mapOf(
                        "ids" to Json.encodeToJsonElement(listOf(1)),
                        "include" to "response",
                        "bodyOffset" to 10,
                        "bodyLength" to 5,
                        "maxLength" to 20
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertTrue(
                    text.contains("... (skipped first 10 characters of body)\\nabcde... (truncated)"),
                    "The requested window should survive a maxLength smaller than the headers: $text"
                )
                assertTrue(text.contains("X-Filler-20: padding value"), "Headers should be intact: $text")
            }
        }

        @Test
        fun `item should report an unknown id`() {
            every { proxy.history() } returns listOf(historyItem(1))

            runBlocking {
                val result = client.callTool(
                    "get_proxy_http_history_item", mapOf(
                        "ids" to Json.encodeToJsonElement(listOf(999))
                    )
                )

                delay(100)
                result.expectTextContent("No proxy HTTP history items with ids: 999")
            }
        }
    }

    @Nested
    @Disabled("Tools intentionally disabled: get_active_editor_contents, set_active_editor_contents")
    inner class EditorTests {
        @Test
        fun `get active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `get active editor contents should return text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.text } returns "Editor content"
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("Editor content")
            }
        }
        
        @Test
        fun `set active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `set active editor contents should handle non-editable editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns false
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<Current editor is not editable>")
            }
        }
        
        @Test
        fun `set active editor contents should update text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns true
            every { textArea.text = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("Editor text has been set")
            }
            
            verify(exactly = 1) { textArea.text = "New content" }
        }
    }
    
    // Pagination itself is covered by ProxyHistorySummaryTests, against the tools that are enabled.
    
    @Nested
    inner class CollaboratorToolsTests {
        private val collaborator = mockk<Collaborator>()
        private val collaboratorClient = mockk<CollaboratorClient>()
        private val collaboratorServer = mockk<CollaboratorServer>()

        @BeforeEach
        fun setupCollaborator() {
            mockkStatic(InteractionFilter::class)

            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val version = mockk<burp.api.montoya.core.Version>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
            every { burpSuite.exportProjectOptionsAsJson() } returns "{}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{}"
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { burpSuite.importUserOptionsFromJson(any()) } just runs

            every { api.collaborator() } returns collaborator
            every { collaborator.createClient() } returns collaboratorClient
            every { collaboratorClient.server() } returns collaboratorServer
            every { collaboratorServer.address() } returns "burpcollaborator.net"

            serverManager.stop {}
            serverStarted = false
            serverManager.start(config) { state ->
                if (state is ServerState.Running) serverStarted = true
            }

            runBlocking {
                var attempts = 0
                while (!serverStarted && attempts < 30) {
                    delay(100)
                    attempts++
                }
                if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
                client.connectToServer("http://127.0.0.1:${testPort}")
            }
        }

        @AfterEach
        fun cleanupCollaborator() {
            unmockkStatic(InteractionFilter::class)
        }

        private fun mockInteraction(
            id: String,
            type: InteractionType,
            clientIp: String = "10.0.0.1",
            clientPort: Int = 54321,
            customData: String? = null,
            dnsDetails: DnsDetails? = null,
            httpDetails: HttpDetails? = null,
            smtpDetails: SmtpDetails? = null
        ): Interaction {
            val interactionId = mockk<InteractionId>()
            every { interactionId.toString() } returns id

            return mockk<Interaction>().also {
                every { it.id() } returns interactionId
                every { it.type() } returns type
                every { it.timeStamp() } returns ZonedDateTime.parse("2025-01-01T12:00:00Z")
                every { it.clientIp() } returns InetAddress.getByName(clientIp)
                every { it.clientPort() } returns clientPort
                every { it.customData() } returns Optional.ofNullable(customData)
                every { it.dnsDetails() } returns Optional.ofNullable(dnsDetails)
                every { it.httpDetails() } returns Optional.ofNullable(httpDetails)
                every { it.smtpDetails() } returns Optional.ofNullable(smtpDetails)
            }
        }

        @Test
        fun `generate payload should return payload and server info`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "abc123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "abc123"
            every { collaboratorClient.generatePayload() } returns payload

            runBlocking {
                val result = client.callTool("generate_collaborator_payload", emptyMap())
                delay(100)
                result.expectTextContent(
                    "Payload: abc123.burpcollaborator.net\n" +
                    "Payload ID: abc123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload() }
        }

        @Test
        fun `generate payload with custom data should pass custom data`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "custom123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "custom123"
            every { collaboratorClient.generatePayload(any<String>()) } returns payload

            runBlocking {
                val result = client.callTool(
                    "generate_collaborator_payload", mapOf(
                        "customData" to "mydata"
                    )
                )
                delay(100)
                result.expectTextContent(
                    "Payload: custom123.burpcollaborator.net\n" +
                    "Payload ID: custom123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload("mydata") }
        }

        @Test
        fun `get interactions should return dns interaction details`() {
            val dnsDetails = mockk<DnsDetails>().also {
                every { it.queryType() } returns DnsQueryType.A
            }
            val interaction = mockInteraction("int-001", InteractionType.DNS, dnsDetails = dnsDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"id\":\"int-001\""))
                assertTrue(text.contains("\"type\":\"DNS\""))
                assertTrue(text.contains("\"queryType\":\"A\""))
                assertTrue(text.contains("\"clientIp\":\"10.0.0.1\""))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return http interaction details`() {
            val mockRequest = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            every { mockRequest.toString() } returns "GET / HTTP/1.1"
            val mockResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { mockResponse.toString() } returns "HTTP/1.1 200 OK"
            val mockRequestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            every { mockRequestResponse.request() } returns mockRequest
            every { mockRequestResponse.response() } returns mockResponse

            val httpDetails = mockk<HttpDetails>().also {
                every { it.protocol() } returns HttpProtocol.HTTP
                every { it.requestResponse() } returns mockRequestResponse
            }
            val interaction = mockInteraction("int-002", InteractionType.HTTP, httpDetails = httpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"HTTP\""))
                assertTrue(text.contains("\"protocol\":\"HTTP\""))
                assertTrue(text.contains("GET / HTTP/1.1"))
                assertTrue(text.contains("HTTP/1.1 200 OK"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return smtp interaction details`() {
            val smtpDetails = mockk<SmtpDetails>().also {
                every { it.protocol() } returns SmtpProtocol.SMTP
                every { it.conversation() } returns "EHLO test\r\n250 OK"
            }
            val interaction = mockInteraction("int-003", InteractionType.SMTP, smtpDetails = smtpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"SMTP\""))
                assertTrue(text.contains("\"protocol\":\"SMTP\""))
                assertTrue(text.contains("EHLO test"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions with payloadId should use filter`() {
            val mockFilter = mockk<InteractionFilter>()
            every { InteractionFilter.interactionIdFilter("abc123") } returns mockFilter
            every { collaboratorClient.getInteractions(mockFilter) } returns emptyList()

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions", mapOf(
                        "payloadId" to "abc123"
                    )
                )
                delay(100)
                result.expectTextContent("No interactions detected")
            }

            verify(exactly = 1) { collaboratorClient.getInteractions(mockFilter) }
        }

        @Test
        fun `get interactions should return no interactions message when empty`() {
            every { collaboratorClient.getAllInteractions() } returns emptyList()

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                result.expectTextContent("No interactions detected")
            }
        }
    }

    @Test
    fun `intentionally disabled tools should not be registered`() {
        val disabledTools = listOf(
            "send_http1_request",
            "send_http2_request",
            "create_repeater_tab",
            "create_repeater_tab_http2",
            "send_to_intruder",
            "url_encode",
            "url_decode",
            "base64_encode",
            "base64_decode",
            "generate_random_string",
            "output_project_options",
            "output_user_options",
            "set_project_options",
            "set_user_options",
            "get_scanner_issues",
            "get_proxy_http_history",
            "get_proxy_http_history_regex",
            "get_organizer_items",
            "get_organizer_items_regex",
            "set_task_execution_engine_state",
            "set_proxy_intercept_state",
            "get_active_editor_contents",
            "set_active_editor_contents"
        )

        runBlocking {
            val toolNames = client.listTools().map { it.name }

            disabledTools.forEach { tool ->
                assertFalse(toolNames.contains(tool), "$tool is intentionally disabled and should not be registered")
            }

            assertTrue(toolNames.contains("get_proxy_http_history_summary"))
            assertTrue(toolNames.contains("get_proxy_http_history_bambda"))
            assertTrue(toolNames.contains("get_proxy_http_history_item"))
            assertTrue(toolNames.contains("get_proxy_websocket_history"))
            assertTrue(toolNames.contains("get_proxy_websocket_history_regex"))
        }
    }

    @Test
    fun `tool name conversion should work properly`() {
        assertEquals("send_http1_request", "SendHttp1Request".toLowerSnakeCase())
        assertEquals("test_case_conversion", "TestCaseConversion".toLowerSnakeCase())
        assertEquals("multiple_upper_case_letters", "MultipleUpperCaseLetters".toLowerSnakeCase())
    }
    
    @Test
    fun `edition specific tools should only register in professional edition`() {
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
        val version = mockk<burp.api.montoya.core.Version>()
        
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        
        every { version.edition() } returns BurpSuiteEdition.COMMUNITY_EDITION
        runBlocking {
            val tools = client.listTools()
            assertFalse(tools.any { it.name == "generate_collaborator_payload" })
            assertFalse(tools.any { it.name == "get_collaborator_interactions" })
        }

        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL

        serverManager.stop {}
        serverStarted = false
        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}")

            val tools = client.listTools()
            assertTrue(tools.any { it.name == "generate_collaborator_payload" })
            assertTrue(tools.any { it.name == "get_collaborator_interactions" })
            // get_scanner_issues is intentionally disabled, so it never registers in any edition
            assertFalse(tools.any { it.name == "get_scanner_issues" })
        }
    }
}