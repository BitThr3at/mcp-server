package net.portswigger.mcp.schema

import burp.api.montoya.collaborator.Interaction as CollaboratorInteraction
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import kotlinx.serialization.Serializable

fun AuditIssue.toSerializableForm(): IssueDetails {
    return IssueDetails(
        name = name(),
        detail = detail(),
        remediation = remediation(),
        httpService = HttpService(
            host = httpService().host(),
            port = httpService().port(),
            secure = httpService().secure()
        ),
        baseUrl = baseUrl(),
        severity = AuditIssueSeverity.valueOf(severity().name),
        confidence = AuditIssueConfidence.valueOf(confidence().name),
        requestResponses = requestResponses().map { it.toSerializableForm() },
        collaboratorInteractions = collaboratorInteractions().map {
            Interaction(
                interactionId = it.id().toString(),
                timestamp = it.timeStamp().toString()
            )
        },
        definition = AuditIssueDefinition(
            id = definition().name(),
            background = definition().background(),
            remediation = definition().remediation(),
            typeIndex = definition().typeIndex(),
        )
    )
}

fun burp.api.montoya.http.message.HttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun ProxyHttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

/**
 * Compact form of a proxy history row, mirroring the columns shown in Burp's
 * Proxy > HTTP history table: #, Host, URL, Method, Params, Edited, Status code, Length.
 *
 * `length` is the size of the full response in bytes, matching Burp's Length column.
 */
fun ProxyHttpRequestResponse.toSummaryForm(): HttpHistorySummary {
    val request = request()
    val response = if (hasResponse()) response() else null

    return HttpHistorySummary(
        id = id(),
        host = originString(),
        method = request?.method() ?: "",
        url = request?.path() ?: "",
        params = request?.hasParameters() ?: false,
        edited = edited(),
        statusCode = response?.statusCode()?.toInt(),
        length = response?.toByteArray()?.length()
    )
}

/**
 * Full form of a proxy history row, keyed by the id from Burp's '#' column so that several
 * items can be returned together and still be correlated with a history summary.
 *
 * Messages are rendered through [slice], which decides how much of each message to keep;
 * body lengths are always reported in full so a caller can window through a large body.
 */
fun ProxyHttpRequestResponse.toItemForm(
    includeRequest: Boolean = true,
    includeResponse: Boolean = true,
    slice: (message: String, bodyOffset: Int) -> String = { message, _ -> message }
): ProxyHistoryItem {
    val request = request()
    val response = if (hasResponse()) response() else null

    return ProxyHistoryItem(
        id = id(),
        request = when {
            !includeRequest -> null
            request == null -> "<no request>"
            else -> slice(request.toString(), request.bodyOffset())
        },
        response = when {
            !includeResponse -> null
            response == null -> "<no response>"
            else -> slice(response.toString(), response.bodyOffset())
        },
        notes = annotations().notes(),
        requestBodyLength = request?.let { it.toString().length - it.bodyOffset() },
        responseBodyLength = response?.let { it.toString().length - it.bodyOffset() }
    )
}

private fun ProxyHttpRequestResponse.originString(): String {
    val service = httpService()
    val secure = service.secure()
    val port = service.port()

    val scheme = if (secure) "https" else "http"
    val isDefaultPort = (secure && port == 443) || (!secure && port == 80)

    return if (isDefaultPort) "$scheme://${service.host()}" else "$scheme://${service.host()}:$port"
}

fun OrganizerItem.toSerializableForm(): OrganizerItemDetails {
    return OrganizerItemDetails(
        id = id(),
        status = status().displayName(),
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun ProxyWebSocketMessage.toSerializableForm(): WebSocketMessage {
    return WebSocketMessage(
        payload = payload()?.toString() ?: "<no payload>",
        direction =
            if (direction() == Direction.CLIENT_TO_SERVER)
                WebSocketMessageDirection.CLIENT_TO_SERVER
            else
                WebSocketMessageDirection.SERVER_TO_CLIENT,
        notes = annotations().notes()
    )
}

@Serializable
data class IssueDetails(
    val name: String?,
    val detail: String?,
    val remediation: String?,
    val httpService: HttpService?,
    val baseUrl: String?,
    val severity: AuditIssueSeverity,
    val confidence: AuditIssueConfidence,
    val requestResponses: List<HttpRequestResponse>,
    val collaboratorInteractions: List<Interaction>,
    val definition: AuditIssueDefinition
)

@Serializable
data class HttpService(
    val host: String,
    val port: Int,
    val secure: Boolean
)

@Serializable
enum class AuditIssueSeverity {
    HIGH,
    MEDIUM,
    LOW,
    INFORMATION,
    FALSE_POSITIVE;
}

@Serializable
enum class AuditIssueConfidence {
    CERTAIN,
    FIRM,
    TENTATIVE
}

@Serializable
data class HttpRequestResponse(
    val request: String?,
    val response: String?,
    val notes: String?
)

@Serializable
data class ProxyHistoryItem(
    val id: Int,
    val request: String? = null,
    val response: String? = null,
    val notes: String? = null,
    val requestBodyLength: Int? = null,
    val responseBodyLength: Int? = null
)

@Serializable
data class HttpHistorySummary(
    val id: Int,
    val host: String,
    val method: String,
    val url: String,
    val params: Boolean,
    val edited: Boolean,
    val statusCode: Int?,
    val length: Int?,
    /** Which messages a regex search hit, and the first matching text; only set for regex searches. */
    val matchedIn: List<String>? = null,
    val match: String? = null
)

@Serializable
data class OrganizerItemDetails(
    val id: Int,
    val status: String,
    val request: String?,
    val response: String?,
    val notes: String?
)

@Serializable
data class Interaction(
    val interactionId: String,
    val timestamp: String
)

@Serializable
data class AuditIssueDefinition(
    val id: String,
    val background: String?,
    val remediation: String?,
    val typeIndex: Int
)


@Serializable
enum class WebSocketMessageDirection {
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT
}

@Serializable
data class WebSocketMessage(
    val payload: String?,
    val direction: WebSocketMessageDirection,
    val notes: String?
)

fun CollaboratorInteraction.toSerializableForm(): CollaboratorInteractionDetails {
    return CollaboratorInteractionDetails(
        id = id().toString(),
        type = type().name,
        timestamp = timeStamp().toString(),
        clientIp = clientIp().hostAddress,
        clientPort = clientPort(),
        customData = customData().orElse(null),
        dnsDetails = dnsDetails().orElse(null)?.let {
            CollaboratorDnsDetails(queryType = it.queryType().name)
        },
        httpDetails = httpDetails().orElse(null)?.let {
            CollaboratorHttpDetails(
                protocol = it.protocol().name,
                request = it.requestResponse()?.request()?.toString(),
                response = it.requestResponse()?.response()?.toString()
            )
        },
        smtpDetails = smtpDetails().orElse(null)?.let {
            CollaboratorSmtpDetails(
                protocol = it.protocol().name,
                conversation = it.conversation()
            )
        }
    )
}

@Serializable
data class CollaboratorInteractionDetails(
    val id: String,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val clientPort: Int,
    val customData: String?,
    val dnsDetails: CollaboratorDnsDetails?,
    val httpDetails: CollaboratorHttpDetails?,
    val smtpDetails: CollaboratorSmtpDetails?
)

@Serializable
data class CollaboratorDnsDetails(
    val queryType: String
)

@Serializable
data class CollaboratorHttpDetails(
    val protocol: String,
    val request: String?,
    val response: String?
)

@Serializable
data class CollaboratorSmtpDetails(
    val protocol: String,
    val conversation: String
)