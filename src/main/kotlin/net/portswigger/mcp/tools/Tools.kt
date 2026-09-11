package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toItemForm
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.schema.toSummaryForm
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTextArea

/**
 * Project data access is intentionally always allowed: the approval prompt is not wanted for this
 * build, so tools log the access and proceed. To restore the prompt, call
 * `DataAccessSecurity.checkDataAccessPermission` here again and deny on false, and put the data
 * access checkboxes back in ServerConfigurationPanel.
 */
private fun logDataAccess(api: MontoyaApi, logMessage: String) {
    api.logging().logToOutput("MCP $logMessage access granted")
}

private fun truncateIfNeeded(serialized: String): String = serialized.truncateTo(5000)

private fun String.truncateTo(maxLength: Int?): String {
    val limit = (maxLength ?: return this).coerceAtLeast(0)

    return if (length > limit) substring(0, limit) + "... (truncated)" else this
}

private class MessageSelection(val request: Boolean, val response: Boolean)

private const val MESSAGE_SELECTION_VALUES = "'both', 'request' or 'response'"

private fun parseMessageSelection(value: String?): MessageSelection? = when (value?.lowercase()) {
    null, "both" -> MessageSelection(request = true, response = true)
    "request" -> MessageSelection(request = true, response = false)
    "response" -> MessageSelection(request = false, response = true)
    else -> null
}

/**
 * Searches the raw messages rather than Burp's own `contains` so that request and response bodies
 * are definitely covered, and reports which messages hit plus the first matching text.
 */
private fun ProxyHttpRequestResponse.regexSearch(pattern: Pattern, scope: MessageSelection): RegexSearchResult? {
    val searched = buildList {
        if (scope.request) request()?.let { add("request" to it.toString()) }
        if (scope.response && hasResponse()) response()?.let { add("response" to it.toString()) }
    }

    val hits = searched.mapNotNull { (name, message) ->
        val matcher = pattern.matcher(message)
        if (matcher.find()) name to matcher.group() else null
    }

    return if (hits.isEmpty()) null else RegexSearchResult(
        matchedIn = hits.map { it.first }, match = hits.first().second.truncateTo(MATCH_SNIPPET_LENGTH)
    )
}

private const val MATCH_SNIPPET_LENGTH = 200

private class RegexSearchResult(val matchedIn: List<String>, val match: String)

/**
 * Burp's own filtering runs inside Burp, so the predicates are handed to
 * `Proxy.history(ProxyHistoryFilter)` rather than applied to a fully materialized history.
 *
 * Cheap metadata checks come first so that the regex, which has to pull whole messages, only runs
 * on the items everything else already accepted.
 */
private fun GetProxyHttpHistorySummary.historyFilters(
    api: MontoyaApi, compiledRegex: Pattern?, searchScope: MessageSelection
): List<(ProxyHttpRequestResponse) -> Boolean> = buildList {
    host?.let { value -> add { it.httpService().host().contains(value, ignoreCase = true) } }
    urlContains?.let { value -> add { it.request()?.path()?.contains(value, ignoreCase = true) == true } }
    method?.let { value -> add { it.request()?.method().equals(value, ignoreCase = true) } }
    mimeType?.let { value -> add { it.mimeType().name.equals(value, ignoreCase = true) } }
    statusCode?.let { value -> add { it.hasResponse() && it.response().statusCode().toInt() == value } }
    hasResponse?.let { value -> add { it.hasResponse() == value } }
    fromId?.let { value -> add { it.id() >= value } }
    toId?.let { value -> add { it.id() <= value } }
    if (inScopeOnly == true) {
        add { request -> request.request()?.url()?.let { api.scope().isInScope(it) } == true }
    }
    compiledRegex?.let { pattern -> add { it.regexSearch(pattern, searchScope) != null } }
}

/**
 * Narrows a raw HTTP message. Headers are always kept in full so that a windowed body still arrives
 * with its status line and content type, and so a small [maxLength] can never discard the very body
 * the caller asked for; [bodyOffset], [bodyLength] and [maxLength] all apply to the body alone.
 */
private fun sliceHttpMessage(
    message: String,
    messageBodyOffset: Int,
    headersOnly: Boolean,
    bodyOffset: Int?,
    bodyLength: Int?,
    maxLength: Int?
): String {
    val headerEnd = messageBodyOffset.coerceIn(0, message.length)
    val headers = message.substring(0, headerEnd)

    if (headersOnly) {
        return headers
    }

    val body = message.substring(headerEnd)
    val from = (bodyOffset ?: 0).coerceIn(0, body.length)

    val windowEnd = bodyLength?.let { (from + it.coerceAtLeast(0)).coerceAtMost(body.length) } ?: body.length
    val to = maxLength?.let { (from + it.coerceAtLeast(0)).coerceAtMost(windowEnd) } ?: windowEnd

    if (from == 0 && to == body.length) {
        return message
    }

    return buildString {
        append(headers)
        if (from > 0) {
            append("... (skipped first $from characters of body)\n")
        }
        append(body, from, to)
        if (to < body.length) {
            append("... (truncated)")
        }
    }
}

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    // Intentionally disabled: HTTP sending, Repeater/Intruder handoff, encoding/decoding
    // utilities, random string generation, and project/user options read+write.
    /*
    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }
    */

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        // Intentionally disabled: scanner issue retrieval.
        /*
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            paginated(api.siteMap().issues()) { Json.encodeToString(it.toSerializableForm()) }
        }
        */

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    // Intentionally disabled: unfiltered proxy HTTP history dump (regex variant stays enabled).
    /*
    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        logDataAccess(api, "HTTP history")

        paginated(api.proxy().history()) { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }
    */

    mcpPaginatedTool<GetProxyHttpHistorySummary>(
        "Searches and summarises the proxy HTTP history, one line per item, mirroring the columns of Burp's HTTP " +
                "history table: id (the '#' column), host, method, url, params, edited, statusCode and length. " +
                "Pass a regex to search the whole history: it is matched against the complete raw messages, headers " +
                "and bodies included, and searchIn ('both', 'request' or 'response') narrows which messages are " +
                "searched. Matching rows also report matchedIn and the first matching text. " +
                "Every filter is optional and they combine: host and urlContains (case-insensitive substrings), " +
                "method, statusCode, mimeType (Burp's type name, e.g. JSON or HTML), hasResponse, inScopeOnly (uses " +
                "Burp's target scope), and the fromId/toId id range. Narrowing with these makes a regex search much " +
                "cheaper, since the regex only runs on what they accept. " +
                "Set newestFirst to page back from the most recent request, which is usually what you want. " +
                "Use this to survey traffic cheaply, then call get_proxy_http_history_item with the ids you care about for the full requests and responses."
    ) {
        logDataAccess(api, "HTTP history")

        val searchScope = parseMessageSelection(searchIn)
            ?: return@mcpPaginatedTool paginationMessage("searchIn must be one of $MESSAGE_SELECTION_VALUES")

        val compiledRegex = regex?.let { Pattern.compile(it) }
        val filters = historyFilters(api, compiledRegex, searchScope)

        val history = if (filters.isEmpty()) {
            api.proxy().history()
        } else {
            api.proxy().history { item -> filters.all { it(item) } }
        }

        paginated(history) { item ->
            val search = compiledRegex?.let { item.regexSearch(it, searchScope) }

            Json.encodeToString(
                item.toSummaryForm().copy(matchedIn = search?.matchedIn, match = search?.match)
            )
        }
    }

    mcpTool<GetProxyHttpHistoryItem>(
        "Returns the request and response of one or more proxy HTTP history items, identified by the ids shown in " +
                "the '#' column of Burp's HTTP history (see get_proxy_http_history_summary). " +
                "Pass a single id as a one-element array; results come back as a JSON array in the order requested, and " +
                "any ids that are not in the history are reported at the end. " +
                "Proxied messages can be megabytes long, so narrow what comes back: include ('both', 'request' or " +
                "'response') picks which messages to return, headersOnly drops the bodies, bodyOffset/bodyLength window " +
                "the body, and maxLength caps each body as a last resort. Headers are always returned in full, and " +
                "bodyOffset, bodyLength and maxLength all apply to the body alone. " +
                "requestBodyLength and responseBodyLength always report the full body sizes, so you can window through " +
                "a large body across several calls."
    ) {
        logDataAccess(api, "HTTP history")

        val requestedIds = ids.distinct()
        if (requestedIds.isEmpty()) {
            return@mcpTool "No ids requested"
        }

        val messages = parseMessageSelection(include)
            ?: return@mcpTool "include must be one of $MESSAGE_SELECTION_VALUES"

        val wantedIds = requestedIds.toSet()
        val matches = api.proxy().history().filter { it.id() in wantedIds }.associateBy { it.id() }

        val items = requestedIds.mapNotNull { matches[it] }.map { item ->
            item.toItemForm(
                includeRequest = messages.request, includeResponse = messages.response
            ) { message, messageBodyOffset ->
                sliceHttpMessage(
                    message = message,
                    messageBodyOffset = messageBodyOffset,
                    headersOnly = headersOnly == true,
                    bodyOffset = bodyOffset,
                    bodyLength = bodyLength,
                    maxLength = maxLength
                )
            }
        }
        val missingIds = requestedIds.filterNot { matches.containsKey(it) }

        buildString {
            if (items.isNotEmpty()) {
                append(Json.encodeToString(items))
            }
            if (missingIds.isNotEmpty()) {
                if (isNotEmpty()) appendLine()
                append("No proxy HTTP history items with ids: ${missingIds.joinToString(", ")}")
            }
        }
    }

    // Intentionally disabled: regex search over the proxy HTTP history. It returned every matching
    // request and response in full, which is enormously expensive and never showed what matched;
    // get_proxy_http_history_summary now takes the same regex, searches bodies as well, and reports
    // the hit per row, with get_proxy_http_history_item for the messages themselves.
    /*
    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        logDataAccess(api, "HTTP history")

        val compiledRegex = Pattern.compile(regex)
        paginated(api.proxy().history { it.contains(compiledRegex) }) {
            truncateIfNeeded(Json.encodeToString(it.toSerializableForm()))
        }
    }
    */

    // Intentionally disabled: Organizer item retrieval.
    /*
    mcpPaginatedTool<GetOrganizerItems>("Displays items within the Organizer tab") {
        logDataAccess(api, "Organizer")

        paginated(api.organizer().items()) { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>("Displays items matching a specified regex within the Organizer tab") {
        logDataAccess(api, "Organizer")

        val compiledRegex = Pattern.compile(regex)
        paginated(api.organizer().items { it.contains(compiledRegex) }) {
            truncateIfNeeded(Json.encodeToString(it.toSerializableForm()))
        }
    }
    */

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        logDataAccess(api, "WebSocket history")

        paginated(api.proxy().webSocketHistory()) {
            truncateIfNeeded(Json.encodeToString(it.toSerializableForm()))
        }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        logDataAccess(api, "WebSocket history")

        val compiledRegex = Pattern.compile(regex)
        paginated(api.proxy().webSocketHistory { it.contains(compiledRegex) }) {
            truncateIfNeeded(Json.encodeToString(it.toSerializableForm()))
        }
    }

    // Intentionally disabled: task execution engine control, proxy intercept toggle, and
    // active editor read/write.
    /*
    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }
    */
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(
    override val count: Int, override val offset: Int, override val newestFirst: Boolean? = null
) : Paginated

@Serializable
data class GetProxyHttpHistory(
    override val count: Int, override val offset: Int, override val newestFirst: Boolean? = null
) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    override val newestFirst: Boolean? = null
) : Paginated

@Serializable
data class GetProxyHttpHistorySummary(
    val regex: String? = null,
    val searchIn: String? = null,
    val host: String? = null,
    val urlContains: String? = null,
    val method: String? = null,
    val mimeType: String? = null,
    val statusCode: Int? = null,
    val hasResponse: Boolean? = null,
    val inScopeOnly: Boolean? = null,
    val fromId: Int? = null,
    val toId: Int? = null,
    override val count: Int,
    override val offset: Int,
    override val newestFirst: Boolean? = null
) : Paginated

@Serializable
data class GetProxyHttpHistoryItem(
    val ids: List<Int>,
    val include: String? = null,
    val headersOnly: Boolean? = null,
    val bodyOffset: Int? = null,
    val bodyLength: Int? = null,
    val maxLength: Int? = null
)

@Serializable
data class GetOrganizerItems(
    override val count: Int, override val offset: Int, override val newestFirst: Boolean? = null
) : Paginated

@Serializable
data class GetOrganizerItemsRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    override val newestFirst: Boolean? = null
) : Paginated

@Serializable
data class GetProxyWebsocketHistory(
    override val count: Int, override val offset: Int, override val newestFirst: Boolean? = null
) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    override val newestFirst: Boolean? = null
) : Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)
