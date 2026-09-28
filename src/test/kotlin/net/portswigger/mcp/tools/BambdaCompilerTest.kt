package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.utilities.Utilities
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BambdaCompilerTest {

    private val api = mockk<MontoyaApi> {
        every { utilities() } returns mockk<Utilities>()
        every { logging() } returns mockk<Logging>()
    }

    @Test
    fun `compiles and evaluates a true predicate`() {
        val compiled = BambdaCompiler.compile("return true;").getOrThrow()
        assertTrue(compiled.matches(mockk<ProxyHttpRequestResponse>(), api))
    }

    @Test
    fun `compiles and evaluates a predicate that inspects the request`() {
        val compiled = BambdaCompiler.compile(
            "return requestResponse.request().method().equals(\"POST\");"
        ).getOrThrow()

        val item = mockk<ProxyHttpRequestResponse> {
            every { request().method() } returns "POST"
        }
        val other = mockk<ProxyHttpRequestResponse> {
            every { request().method() } returns "GET"
        }

        assertTrue(compiled.matches(item, api))
        assertEquals(false, compiled.matches(other, api))
    }

    @Test
    fun `reports a compile error instead of throwing`() {
        val result = BambdaCompiler.compile("this is not java;")
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()!!.message!!.isNotBlank())
    }

    @Test
    fun `compiles a real PortSwigger bambdas example verbatim`() {
        // From Filter/Proxy/HTTP/FilterOnCookieValue.bambda in github.com/PortSwigger/bambdas.
        val compiled = BambdaCompiler.compile(
            """
            if (requestResponse.request().hasParameter("foo", HttpParameterType.COOKIE)) {
              var cookieValue = requestResponse
                .request()
                .parameter("foo", HttpParameterType.COOKIE)
                .value();

              return cookieValue.contains("1337");
            }

            return false;
            """.trimIndent()
        ).getOrThrow()

        val item = mockk<ProxyHttpRequestResponse> {
            every { request().hasParameter("foo", any()) } returns false
        }

        assertEquals(false, compiled.matches(item, api))
    }

    @Test
    fun `supports the example-library method-call style for utilities and logging`() {
        val compiled = BambdaCompiler.compile(
            "utilities(); logging(); return true;"
        ).getOrThrow()

        assertTrue(compiled.matches(mockk<ProxyHttpRequestResponse>(), api))
    }

    // Kept in sync by hand with the examples in Tools.kt's BAMBDA_TOOL_DESCRIPTION (file-private there,
    // so duplicated here) to make sure every example the tool advertises actually compiles.
    private val descriptionExamples = listOf(
        """return !requestResponse.request().method().equals("OPTIONS");""",
        """return requestResponse.hasResponse() && requestResponse.response().statusCode() == 403;""",
        """return requestResponse.hasResponse() && requestResponse.response().statusCode() >= 300 && requestResponse.response().statusCode() <= 399 && requestResponse.response().body().length() > 1000;""",
        """return requestResponse.hasResponse() && requestResponse.response().bodyToString().contains("You have an error in your SQL syntax");""",
        """if (!requestResponse.request().hasParameter("session", HttpParameterType.COOKIE)) return false; return requestResponse.request().parameter("session", HttpParameterType.COOKIE).value().contains("1337");""",
        """return requestResponse.request().hasParameter("query", HttpParameterType.JSON) || requestResponse.request().hasParameter("query", HttpParameterType.BODY);""",
        """if (!requestResponse.hasResponse()) return false; for (ParsedHttpParameter p : requestResponse.request().parameters()) { if (p.value().length() > 3 && requestResponse.response().contains(p.value(), true)) return true; } return false;""",
        """return !requestResponse.httpService().host().contains("internal.example.com");""",
        """logging().logToOutput("checked " + requestResponse.request().url()); return utilities().urlUtils().decode(requestResponse.request().path()).contains("../");"""
    )

    @Test
    fun `every example in the tool description compiles`() {
        descriptionExamples.forEach { example ->
            val result = BambdaCompiler.compile(example)
            assertTrue(result.isSuccess, "failed to compile: $example\n${result.exceptionOrNull()?.message}")
        }
    }

    @Test
    fun `wraps a runtime exception thrown by the generated code`() {
        val compiled = BambdaCompiler.compile("throw new RuntimeException(\"boom\");").getOrThrow()
        val error = runCatching { compiled.matches(mockk<ProxyHttpRequestResponse>(), api) }.exceptionOrNull()
        assertTrue(error is java.lang.reflect.InvocationTargetException)
        assertEquals("boom", (error as java.lang.reflect.InvocationTargetException).cause?.message)
    }
}
