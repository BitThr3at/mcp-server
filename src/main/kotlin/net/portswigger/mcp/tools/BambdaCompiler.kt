package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import java.io.File
import java.net.URLClassLoader
import java.nio.file.Files
import java.util.Locale
import javax.tools.Diagnostic
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.ToolProvider

private const val GENERATED_PACKAGE = "net.portswigger.mcp.bambda.generated"
private const val GENERATED_CLASS = "GeneratedBambdaFilter"

/**
 * Compiles a Bambda-style filter body (the same Java snippet Burp's own Proxy history "Script mode"
 * filter, and the PortSwigger/bambdas example library, both accept) into a
 * `matches(ProxyHttpRequestResponse, Utilities, Logging)` predicate, then runs it via reflection.
 *
 * This runs untrusted, MCP-client-supplied Java source with full Montoya API access inside the
 * extension's own JVM: no sandboxing beyond what compiling to a throwaway classloader gives for free.
 * It is exactly as trusted as a human pasting the same snippet into Burp's Bambda editor, except the
 * author is now whoever is on the other end of the MCP connection. Restrict this tool to trusted
 * clients only.
 */
class BambdaCompiler private constructor(private val instance: Any, private val method: java.lang.reflect.Method) {

    fun matches(item: ProxyHttpRequestResponse, api: MontoyaApi): Boolean =
        method.invoke(instance, item, api.utilities(), api.logging()) as Boolean

    companion object {
        fun compile(body: String): Result<BambdaCompiler> {
            val compiler = ToolProvider.getSystemJavaCompiler()
                ?: return Result.failure(IllegalStateException("No Java compiler available in this runtime"))

            val montoyaClasspath = MontoyaApi::class.java.protectionDomain.codeSource?.location?.let { File(it.toURI()) }
                ?: return Result.failure(IllegalStateException("Could not locate the Montoya API on the classpath"))

            // Real Bambdas from PortSwigger's example library call `utilities()` and `logging()` as
            // no-arg methods rather than referencing them as parameters, and never write their own
            // imports (Burp's own Bambda compiler injects a broad set). Both `utilities`/`logging` as
            // bare identifiers (the current Script-mode signature) and `utilities()`/`logging()` as
            // calls (the example-library style) are supported here so either snippet style compiles
            // unmodified; a parameter and a same-named no-arg method don't collide in Java.
            val source = """
                package $GENERATED_PACKAGE;

                import java.util.*;
                import java.util.regex.*;
                import burp.api.montoya.core.*;
                import burp.api.montoya.http.*;
                import burp.api.montoya.http.message.*;
                import burp.api.montoya.http.message.requests.*;
                import burp.api.montoya.http.message.responses.*;
                import burp.api.montoya.http.message.params.*;
                import burp.api.montoya.proxy.*;
                import burp.api.montoya.scope.*;
                import burp.api.montoya.utilities.*;
                import burp.api.montoya.logging.*;

                public class $GENERATED_CLASS {
                    private Utilities currentUtilities;
                    private Logging currentLogging;

                    public Utilities utilities() { return currentUtilities; }
                    public Logging logging() { return currentLogging; }

                    public boolean matches(ProxyHttpRequestResponse requestResponse, Utilities utilities, Logging logging) throws Exception {
                        this.currentUtilities = utilities;
                        this.currentLogging = logging;
                        $body
                    }
                }
            """.trimIndent()

            val outputDir = Files.createTempDirectory("bambda").toFile()
            outputDir.deleteOnExit()

            val diagnostics = DiagnosticCollector<JavaFileObject>()
            val fileManager = compiler.getStandardFileManager(diagnostics, null, Charsets.UTF_8)
            val sourceFile = InMemorySource("$GENERATED_PACKAGE.$GENERATED_CLASS", source)

            val options = listOf(
                "-classpath", montoyaClasspath.path, "-d", outputDir.path
            )

            val success = compiler.getTask(null, fileManager, diagnostics, options, null, listOf(sourceFile)).call()

            if (!success) {
                val errors = diagnostics.diagnostics
                    .filter { it.kind == Diagnostic.Kind.ERROR }
                    .joinToString("\n") { "line ${it.lineNumber}: ${it.getMessage(Locale.ROOT)}" }
                return Result.failure(IllegalArgumentException(errors.ifBlank { "Compilation failed" }))
            }

            return try {
                val classLoader = URLClassLoader(arrayOf(outputDir.toURI().toURL()), MontoyaApi::class.java.classLoader)
                val clazz = classLoader.loadClass("$GENERATED_PACKAGE.$GENERATED_CLASS")
                val instance = clazz.getDeclaredConstructor().newInstance()
                val method = clazz.getMethod(
                    "matches",
                    ProxyHttpRequestResponse::class.java,
                    Class.forName("burp.api.montoya.utilities.Utilities", false, classLoader),
                    Class.forName("burp.api.montoya.logging.Logging", false, classLoader)
                )
                Result.success(BambdaCompiler(instance, method))
            } catch (e: ReflectiveOperationException) {
                Result.failure(e)
            }
        }
    }
}

private class InMemorySource(className: String, private val code: String) :
    javax.tools.SimpleJavaFileObject(
        java.net.URI.create("string:///" + className.replace('.', '/') + JavaFileObject.Kind.SOURCE.extension),
        JavaFileObject.Kind.SOURCE
    ) {
    override fun getCharContent(ignoreEncodingErrors: Boolean): CharSequence = code
}
