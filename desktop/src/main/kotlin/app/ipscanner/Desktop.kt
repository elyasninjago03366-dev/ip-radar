package app.ipscanner

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.io.File
import java.net.BindException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.net.URL
import java.util.concurrent.Executors
import kotlin.system.exitProcess

/** Tiny JSON reader/writer, enough for the flat objects the page sends. */
object Json {
    fun quote(s: String): String {
        val sb = StringBuilder("\"")
        for (c in s) when {
            c == '"' -> sb.append("\\\"")
            c == '\\' -> sb.append("\\\\")
            c == '\n' -> sb.append("\\n")
            c == '\r' -> sb.append("\\r")
            c == '\t' -> sb.append("\\t")
            c < ' ' -> sb.append(String.format("\\u%04x", c.code))
            else -> sb.append(c)
        }
        return sb.append('"').toString()
    }

    private class P(val s: String) {
        var i = 0
        fun ws() { while (i < s.length && s[i].isWhitespace()) i++ }
        fun value(): Any? {
            ws()
            if (i >= s.length) throw IllegalArgumentException("eof")
            return when (s[i]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> { i += 4; true }
                'f' -> { i += 5; false }
                'n' -> { i += 4; null }
                else -> num()
            }
        }
        fun obj(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            i++; ws()
            if (s[i] == '}') { i++; return m }
            while (true) {
                ws(); val k = str(); ws()
                if (s[i] != ':') throw IllegalArgumentException("colon"); i++
                m[k] = value(); ws()
                if (s[i] == ',') { i++; continue }
                if (s[i] == '}') { i++; return m }
                throw IllegalArgumentException("obj")
            }
        }
        fun arr(): List<Any?> {
            val l = ArrayList<Any?>()
            i++; ws()
            if (s[i] == ']') { i++; return l }
            while (true) {
                l.add(value()); ws()
                if (s[i] == ',') { i++; continue }
                if (s[i] == ']') { i++; return l }
                throw IllegalArgumentException("arr")
            }
        }
        fun str(): String {
            if (s[i] != '"') throw IllegalArgumentException("str")
            i++
            val sb = StringBuilder()
            while (s[i] != '"') {
                var c = s[i++]
                if (c == '\\') {
                    c = s[i++]
                    when (c) {
                        'n' -> sb.append('\n'); 'r' -> sb.append('\r'); 't' -> sb.append('\t')
                        'b' -> sb.append('\b'); 'f' -> sb.append('\u000c')
                        'u' -> { sb.append(s.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                        else -> sb.append(c)
                    }
                } else sb.append(c)
            }
            i++
            return sb.toString()
        }
        fun num(): Double {
            val st = i
            while (i < s.length && (s[i].isDigit() || s[i] in "+-.eE")) i++
            return s.substring(st, i).toDouble()
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun parseObject(s: String): Map<String, Any?> = P(s).value() as Map<String, Any?>
}

private fun Map<String, Any?>.str(k: String, d: String = ""): String = (this[k] as? String) ?: d
private fun Map<String, Any?>.int(k: String, d: Int): Int = (this[k] as? Number)?.toInt() ?: d
private fun Map<String, Any?>.bool(k: String, d: Boolean): Boolean = (this[k] as? Boolean) ?: d

private fun probeJson(p: Probe): String {
    val sb = StringBuilder("{")
    sb.append("\"ok\":").append(p.ok)
    sb.append(",\"ping\":").append(p.ping)
    sb.append(",\"delay\":").append(p.delay)
    sb.append(",\"loss\":").append(p.loss)
    if (p.loc != null) sb.append(",\"loc\":").append(Json.quote(p.loc))
    if (p.colo != null) sb.append(",\"colo\":").append(Json.quote(p.colo))
    if (p.err != null) sb.append(",\"err\":").append(Json.quote(p.err))
    return sb.append("}").toString()
}

private fun fail(e: Throwable): String {
    val code = when (e) {
        is ProbeError -> e.code
        is SocketTimeoutException -> "timeout"
        else -> e.javaClass.simpleName
    }
    return "{\"ok\":false,\"err\":" + Json.quote(code) + "}"
}

private fun dispatch(m: String, a: Map<String, Any?>): String {
    val timeout = a.int("timeout", 5000)
    val samples = a.int("samples", 2)
    return when (m) {
        "tcp" -> probeJson(Engine.tcp(a.str("host"), a.int("port", 443), samples, timeout))
        "icmp" -> probeJson(Engine.icmp(a.str("host"), samples, timeout))
        "real" -> probeJson(Engine.realIp(a.str("host"), a.str("sni", "www.cloudflare.com"), a.int("port", 443), samples, timeout))
        "socks5" -> probeJson(
            Engine.socks5(
                a.str("host"), a.int("port", 1080), a.str("user"), a.str("pass"),
                a.bool("https", true), a.str("target", Engine.DEFAULT_TARGET), samples, timeout
            )
        )
        "socks4" -> probeJson(
            Engine.socks4(
                a.str("host"), a.int("port", 1080), a.str("user"),
                a.bool("https", true), a.str("target", Engine.DEFAULT_TARGET), samples, timeout
            )
        )
        "vpn" -> "{\"ok\":true,\"reasons\":[" + Engine.vpnLocal().joinToString(",") { Json.quote(it) } + "]}"
        "http" -> probeJson(
            Engine.httpProxy(
                a.str("host"), a.int("port", 8080), a.str("user"), a.str("pass"),
                a.bool("tunnel", false), a.str("target", Engine.DEFAULT_TARGET), samples, timeout
            )
        )
        "fetch" -> "{\"ok\":true,\"text\":" + Json.quote(Engine.fetchText(a.str("url"), a.int("timeout", 15000))) + "}"
        "geo" -> {
            @Suppress("UNCHECKED_CAST")
            val ips = (a["ips"] as? List<Any?>)?.mapNotNull { it as? String } ?: emptyList()
            val map = Engine.geo(ips).entries.joinToString(",") { Json.quote(it.key) + ":" + Json.quote(it.value) }
            "{\"ok\":true,\"map\":{$map}}"
        }
        // Clipboard and file saving are handled by the browser window itself on desktop.
        "copy", "save" -> "{\"ok\":false,\"err\":\"browser\"}"
        else -> "{\"ok\":false,\"err\":\"unknown-method\"}"
    }
}

@Volatile private var lastBeat = System.currentTimeMillis()
@Volatile private var everBeat = false
@Volatile private var byeAt = 0L

private fun alive(port: Int): Boolean = try {
    val c = URL("http://127.0.0.1:$port/api/ping").openConnection() as HttpURLConnection
    c.connectTimeout = 800; c.readTimeout = 800
    c.setRequestProperty("X-IPR", "1")
    val ok = c.responseCode == 200 && c.inputStream.bufferedReader().readText().trim() == "ipradar"
    c.disconnect(); ok
} catch (_: Exception) { false }

private fun openWindow(port: Int) {
    val url = "http://127.0.0.1:$port/"
    val os = System.getProperty("os.name", "").lowercase()
    try {
        if (os.contains("win")) {
            val bases = listOfNotNull(System.getenv("ProgramFiles(x86)"), System.getenv("ProgramFiles"), System.getenv("ProgramW6432"), System.getenv("LOCALAPPDATA"))
            val rel = listOf(
                "Microsoft\\Edge\\Application\\msedge.exe",
                "Google\\Chrome\\Application\\chrome.exe",
                "BraveSoftware\\Brave-Browser\\Application\\brave.exe"
            )
            val profile = File(System.getenv("LOCALAPPDATA") ?: System.getProperty("java.io.tmpdir"), "IPRadar\\profile")
            for (r in rel) for (b in bases) {
                val f = File(b, r)
                if (f.exists()) {
                    ProcessBuilder(
                        f.path, "--app=$url", "--user-data-dir=${profile.path}", "--window-size=1100,880",
                        "--no-first-run", "--no-default-browser-check"
                    ).start()
                    return
                }
            }
            ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", url).start()
        } else if (os.contains("mac")) {
            ProcessBuilder("open", url).start()
        } else {
            ProcessBuilder("xdg-open", url).start()
        }
    } catch (_: Exception) {
    }
}

private fun send(ex: HttpExchange, code: Int, type: String, body: ByteArray) {
    ex.responseHeaders.add("Content-Type", type)
    ex.responseHeaders.add("Cache-Control", "no-store")
    ex.responseHeaders.add("X-Content-Type-Options", "nosniff")
    ex.sendResponseHeaders(code, if (body.isEmpty()) -1 else body.size.toLong())
    if (body.isNotEmpty()) ex.responseBody.use { it.write(body) } else ex.close()
}

fun main(args: Array<String>) {
    val noBrowser = "--no-browser" in args
    val keepAlive = "--keep-alive" in args
    val local = InetAddress.getByName("127.0.0.1")
    var server: HttpServer
    try {
        server = HttpServer.create(InetSocketAddress(local, 47615), 0)
    } catch (e: BindException) {
        if (alive(47615)) { if (!noBrowser) openWindow(47615); return }
        server = HttpServer.create(InetSocketAddress(local, 0), 0)
    }
    val port = server.address.port
    val allowedHosts = setOf("127.0.0.1:$port", "localhost:$port")
    val appVer = Json::class.java.`package`?.implementationVersion ?: "1.0.1"
    val bundled = Json::class.java.getResourceAsStream("/bundled.js")?.readBytes() ?: "window.BUNDLED={};".toByteArray()
    val index = (Json::class.java.getResourceAsStream("/index.html")?.readBytes() ?: ByteArray(0))
        .toString(Charsets.UTF_8)
        .replaceFirst("<script>", "<script>window.__APPVER=\"" + appVer + "\";")
        .toByteArray(Charsets.UTF_8)
    val pool = Executors.newCachedThreadPool { r -> Thread(r).also { it.isDaemon = true } }
    server.executor = pool

    server.createContext("/") { ex ->
        try {
            val host = ex.requestHeaders.getFirst("Host") ?: ""
            if (host !in allowedHosts) { send(ex, 403, "text/plain", "forbidden".toByteArray()); return@createContext }
            val path = ex.requestURI.path
            when {
                ex.requestMethod == "GET" && (path == "/" || path == "/index.html") ->
                    send(ex, 200, "text/html; charset=utf-8", index)
                ex.requestMethod == "GET" && path == "/bundled.js" ->
                    send(ex, 200, "application/javascript; charset=utf-8", bundled)
                path == "/api/ping" -> {
                    if (ex.requestHeaders.getFirst("X-IPR") != "1") { send(ex, 403, "text/plain", "forbidden".toByteArray()); return@createContext }
                    lastBeat = System.currentTimeMillis(); everBeat = true; byeAt = 0L
                    send(ex, 200, "text/plain", "ipradar".toByteArray())
                }
                path == "/api/bye" -> { byeAt = System.currentTimeMillis(); send(ex, 204, "text/plain", ByteArray(0)) }
                path == "/api" && ex.requestMethod == "POST" -> {
                    val origin = ex.requestHeaders.getFirst("Origin")
                    val okOrigin = origin == null || origin == "http://127.0.0.1:$port" || origin == "http://localhost:$port"
                    if (ex.requestHeaders.getFirst("X-IPR") != "1" || !okOrigin) {
                        send(ex, 403, "text/plain", "forbidden".toByteArray()); return@createContext
                    }
                    val res = try {
                        val body = ex.requestBody.readBytes().toString(Charsets.UTF_8)
                        val req = Json.parseObject(body)
                        @Suppress("UNCHECKED_CAST")
                        dispatch(req.str("method"), (req["args"] as? Map<String, Any?>) ?: emptyMap())
                    } catch (t: Throwable) {
                        fail(t)
                    }
                    send(ex, 200, "application/json; charset=utf-8", res.toByteArray(Charsets.UTF_8))
                }
                else -> send(ex, 404, "text/plain", "not found".toByteArray())
            }
        } catch (_: Throwable) {
            try { ex.close() } catch (_: Exception) {}
        }
    }
    server.start()
    println("IP Radar listening on http://127.0.0.1:$port/")
    if (!noBrowser) openWindow(port)

    // Exit when the window is closed (no heartbeat any more).
    val started = System.currentTimeMillis()
    while (true) {
        Thread.sleep(1000)
        if (keepAlive) continue
        val now = System.currentTimeMillis()
        if (!everBeat && now - started > 90_000) break
        if (everBeat && byeAt > 0 && now - byeAt > 6_000 && now - lastBeat > 6_000) break
        if (everBeat && now - lastBeat > 180_000) break
    }
    server.stop(0)
    exitProcess(0)
}
