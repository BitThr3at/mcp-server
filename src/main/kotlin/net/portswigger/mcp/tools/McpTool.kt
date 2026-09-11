package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.PromptMessageContent
import io.modelcontextprotocol.kotlin.sdk.TextContent
import io.modelcontextprotocol.kotlin.sdk.Tool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import net.portswigger.mcp.schema.asInputSchema
import kotlin.experimental.ExperimentalTypeInference

/**
 * MCP clients routinely pass along parameters a tool doesn't declare; drop them rather than
 * failing the whole call.
 */
@PublishedApi
internal val toolInputJson: Json = Json { ignoreUnknownKeys = true }

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> List<PromptMessageContent>
) {
    val toolName = I::class.simpleName?.toLowerSnakeCase() ?: error("Couldn't find name for ${I::class}")

    addTool(
        name = toolName,
        description = description,
        inputSchema = I::class.asInputSchema(),
        handler = { request ->
            try {
                CallToolResult(
                    content = execute(
                        toolInputJson.decodeFromJsonElement(
                            I::class.serializer(),
                            request.arguments
                        )
                    )
                )
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("Error: ${e.message}")),
                    isError = true
                )
            }
        }
    )
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolString")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> String
) {
    mcpTool<I>(description, execute = {
        listOf(TextContent(execute(this)))
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolUnit")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> Unit
) {
    mcpTool<I>(description, execute = {
        execute(this)

        listOf(TextContent("Executed tool"))
    })
}

/**
 * What a paginated tool hands back: either the full result set to page over, or a message
 * that replaces the page (an access denial, for instance).
 *
 * Items are only rendered once the requested window has been sliced, so tools can return the
 * whole underlying collection without paying to serialize all of it.
 */
class PaginatedContent(
    val total: Int,
    val slice: (from: Int, to: Int, newestFirst: Boolean) -> List<String>,
    val message: String?
)

fun <T> paginated(items: List<T>, render: (T) -> String): PaginatedContent = PaginatedContent(
    total = items.size,
    slice = { from, to, newestFirst ->
        val ordered = if (newestFirst) items.asReversed() else items
        ordered.subList(from, to).map(render)
    },
    message = null
)

fun paginationMessage(text: String): PaginatedContent =
    PaginatedContent(total = 0, slice = { _, _, _ -> emptyList() }, message = text)

@PublishedApi
internal fun paginationFooter(from: Int, to: Int, total: Int, newestFirst: Boolean): String {
    val order = if (newestFirst) "newest first" else "oldest first"
    val more = if (to < total) "nextOffset=$to" else "no more items"

    return "-- showing ${from + 1}-$to of $total ($order), $more --"
}

inline fun <reified I : Paginated> Server.mcpPaginatedTool(
    description: String,
    crossinline execute: I.() -> PaginatedContent
) {
    mcpTool<I>(description, execute = {
        val content = execute(this)

        when {
            content.message != null -> content.message!!

            count <= 0 -> "count must be greater than 0"

            offset < 0 -> "offset cannot be negative"

            offset >= content.total -> "Reached end of items (${content.total} total)"

            else -> {
                val to = (offset + count).coerceAtMost(content.total)
                val orderNewestFirst = newestFirst == true
                val rendered = content.slice(offset, to, orderNewestFirst)

                rendered.joinToString(separator = "\n\n") +
                        "\n\n" + paginationFooter(offset, to, content.total, orderNewestFirst)
            }
        }
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpNamedToolString")
inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: () -> List<PromptMessageContent>
) {
    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            CallToolResult(
                content = execute()
            )
        }
    )
}

inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: () -> String
) {
    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            CallToolResult(
                content = listOf(TextContent(execute()))
            )
        }
    )
}

fun String.toLowerSnakeCase(): String {
    return this
        .replace(Regex("([a-z0-9])([A-Z])"), "$1_$2")
        .replace(Regex("([A-Z])([A-Z][a-z])"), "$1_$2")
        .replace(Regex("[\\s-]+"), "_")
        .lowercase()
}

interface Paginated {
    val count: Int
    val offset: Int

    /**
     * Burp hands back history oldest-first, but the interesting traffic is usually the most
     * recent. Setting this pages backwards from the newest item instead.
     */
    val newestFirst: Boolean? get() = null
}

