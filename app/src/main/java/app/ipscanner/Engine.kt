package app.ipscanner

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Result of probing one address (several samples folded into one). */
class Probe(
    val ok: Boolean,
    val ping: Double,   // best connect / reply time in ms
    val delay: Double,  // average full round trip in ms
    val loss: Int,      // percent of failed samples
    val loc: String?,   // country code reported by Cloudflare (real mode only)
    val colo: String?,  // Cloudflare data center (real mode only)
    val err: String?
)

internal class Attempt(
    val connect: Double,
    val total: Double,
    val loc: String? = null,
    val colo: String? = null
)

class ProbeError(val code: String) : Exception(code)

/**
 * Pure JVM network engine: no Android classes, so it can be unit-tested on a normal JDK.
 * Every function blocks, so callers run it on a worker thread.
 */
object Engine {
    private const val UA =
        "Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36"
    const val DEFAULT_TARGET = "www.gstatic.com"

    // ---------------------------------------------------------------- helpers

    private fun msSince(t0: Long): Double = (System.nanoTime() - t0) / 1_000_000.0

    private fun remaining(deadline: Long): Int {
        val r = (deadline - System.nanoTime()) / 1_000_000L
        if (r <= 0L) throw SocketTimeoutException("deadline")
        return if (r > Int.MAX_VALUE) Int.MAX_VALUE else r.toInt()
    }

    private fun describe(e: Throwable): String = when (e) {
        is ProbeError -> e.code
        is SocketTimeoutException -> "timeout"
        is ConnectException -> "refused"
        is UnknownHostException -> "dns"
        is SSLException -> "tls"
        is SocketException -> "reset"
        is IOException -> "io"
        else -> e.javaClass.simpleName
    }

    private fun aggregate(samples: Int, run: () -> Attempt): Probe {
        val n = if (samples < 1) 1 else if (samples > 5) 5 else samples
        var okCount = 0
        var bestPing = Double.MAX_VALUE
        var sumDelay = 0.0
        var loc: String? = null
        var colo: String? = null
        var err: String? = null
        for (i in 0 until n) {
            try {
                val a = run()
                okCount++
                if (a.connect < bestPing) bestPing = a.connect
                sumDelay += a.total
                if (a.loc != null) loc = a.loc
                if (a.colo != null) colo = a.colo
            } catch (e: Exception) {
                err = describe(e)
                if (okCount == 0) break // first sample failed: dead address, stop early
            }
        }
        if (okCount == 0) return Probe(false, 0.0, 0.0, 100, null, null, err ?: "failed")
        val loss = Math.round((n - okCount) * 100.0 / n).toInt()
        return Probe(true, bestPing, sumDelay / okCount, loss, loc, colo, null)
    }

    private fun dial(host: String, port: Int, deadline: Long): Socket {
        val s = Socket()
        try {
            s.tcpNoDelay = true
            s.connect(InetSocketAddress(host, port), remaining(deadline))
            return s
        } catch (e: Exception) {
            try { s.close() } catch (_: Exception) {}
            throw e
        }
    }

    private fun readExact(s: Socket, n: Int, deadline: Long): ByteArray {
        val buf = ByteArray(n)
        var off = 0
        val ins = s.getInputStream()
        while (off < n) {
            s.soTimeout = remaining(deadline)
            val r = ins.read(buf, off, n - off)
            if (r < 0) throw ProbeError("closed")
            off += r
        }
        return buf
    }

    private fun readHead(s: Socket, deadline: Long): String {
        val ins = s.getInputStream()
        val sb = StringBuilder()
        while (sb.length < 16384) {
            s.soTimeout = remaining(deadline)
            val b = ins.read()
            if (b < 0) break
            sb.append(b.toChar())
            val l = sb.length
            if (l >= 4 && sb[l - 1] == '\n' && sb[l - 2] == '\r' && sb[l - 3] == '\n' && sb[l - 4] == '\r') break
        }
        if (sb.isEmpty()) throw ProbeError("closed")
        return sb.toString()
    }

    private fun readBody(s: Socket, deadline: Long, max: Int): String {
        val ins = s.getInputStream()
        val bo = ByteArrayOutputStream()
        val buf = ByteArray(1024)
        try {
            while (bo.size() < max) {
                s.soTimeout = remaining(deadline)
                val r = ins.read(buf)
                if (r < 0) break
                bo.write(buf, 0, r)
            }
        } catch (e: SocketTimeoutException) {
            if (bo.size() == 0) throw e
        }
        return String(bo.toByteArray(), Charsets.ISO_8859_1)
    }

    private fun statusOf(head: String): Int {
        val line = head.substringBefore('\n').trim()
        if (!line.startsWith("HTTP/")) throw ProbeError("not-http")
        return line.split(' ').getOrNull(1)?.toIntOrNull() ?: throw ProbeError("not-http")
    }

    private fun tls(base: Socket, sni: String, deadline: Long): SSLSocket {
        val f = SSLSocketFactory.getDefault() as SSLSocketFactory
        val ss = f.createSocket(base, sni, base.port, true) as SSLSocket
        ss.soTimeout = remaining(deadline)
        ss.startHandshake()
        return ss
    }

    private fun send(s: Socket, text: String) {
        val o = s.getOutputStream()
        o.write(text.toByteArray(Charsets.ISO_8859_1))
        o.flush()
    }

    private fun get204(s: Socket, host: String, deadline: Long) {
        send(s, "GET /generate_204 HTTP/1.1\r\nHost: $host\r\nUser-Agent: $UA\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        val code = statusOf(readHead(s, deadline))
        if (code != 204) throw ProbeError("http-$code")
    }

    private fun b64(s: String): String {
        val t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val d = s.toByteArray(Charsets.UTF_8)
        val sb = StringBuilder()
        var i = 0
        while (i < d.size) {
            val b0 = d[i].toInt() and 0xFF
            val b1 = if (i + 1 < d.size) d[i + 1].toInt() and 0xFF else -1
            val b2 = if (i + 2 < d.size) d[i + 2].toInt() and 0xFF else -1
            sb.append(t[b0 shr 2])
            sb.append(t[((b0 and 3) shl 4) or (if (b1 >= 0) b1 shr 4 else 0)])
            sb.append(if (b1 >= 0) t[((b1 and 15) shl 2) or (if (b2 >= 0) b2 shr 6 else 0)] else '=')
            sb.append(if (b2 >= 0) t[b2 and 63] else '=')
            i += 3
        }
        return sb.toString()
    }

    // ----------------------------------------------------------------- probes

    /** Plain TCP connect time. */
    fun tcp(host: String, port: Int, samples: Int, timeoutMs: Int): Probe = aggregate(samples) {
        val t0 = System.nanoTime()
        val deadline = t0 + timeoutMs * 1_000_000L
        val s = dial(host, port, deadline)
        val ms = msSince(t0)
        try { s.close() } catch (_: Exception) {}
        Attempt(ms, ms)
    }

    /** Real ICMP ping using the system ping binary (works without root on Android). */
    fun icmp(host: String, samples: Int, timeoutMs: Int): Probe {
        val n = if (samples < 1) 1 else if (samples > 5) 5 else samples
        if (!Regex("^[A-Za-z0-9.:_-]+$").matches(host)) return Probe(false, 0.0, 0.0, 100, null, null, "bad-host")
        val wait = maxOf(1, (timeoutMs + 999) / 1000)
        if (System.getProperty("os.name", "").lowercase().contains("win")) return icmpWindows(host, n, timeoutMs)
        val v6 = host.contains(':')
        val cmds = (if (v6) listOf(
            listOf("/system/bin/ping6", "-c", n.toString(), "-W", wait.toString(), host),
            listOf("ping6", "-c", n.toString(), "-W", wait.toString(), host)
        ) else emptyList()) + listOf(
            listOf("/system/bin/ping", "-c", n.toString(), "-W", wait.toString(), host),
            listOf("ping", "-c", n.toString(), "-W", wait.toString(), host),
            listOf("/system/bin/ping", "-c", n.toString(), "-w", (n * wait).toString(), host)
        )
        var lastErr = "no-ping-binary"
        for (cmd in cmds) {
            var p: Process? = null
            try {
                val proc: Process = ProcessBuilder(cmd).redirectErrorStream(true).start()
                p = proc
                val limit = n * wait * 1000L + 2000L
                val killer = Thread {
                    try { Thread.sleep(limit); proc.destroy() } catch (_: InterruptedException) {}
                }
                killer.isDaemon = true
                killer.start()
                val out = try {
                    proc.inputStream.bufferedReader().readText()
                } finally {
                    killer.interrupt()
                }
                val times = parsePing(out)
                if (times.isNotEmpty()) {
                    val loss = Math.round((n - times.size) * 100.0 / n).toInt()
                    return Probe(true, times.min(), times.average(), if (loss < 0) 0 else loss, null, null, null)
                }
                lastErr = if (out.contains("not permitted", true) || out.contains("denied", true)) "icmp-denied" else "no-reply"
            } catch (e: IOException) {
                lastErr = "no-ping-binary"
            } finally {
                try { p?.destroy() } catch (_: Exception) {}
            }
        }
        return Probe(false, 0.0, 0.0, 100, null, null, lastErr)
    }

    /** Windows: ping -n N -w ms host (replies look like "Reply from x: bytes=32 time=12ms TTL=57"). */
    private fun icmpWindows(host: String, n: Int, timeoutMs: Int): Probe {
        var p: Process? = null
        try {
            val proc: Process = ProcessBuilder(listOf("ping") + (if (host.contains(':')) listOf("-6") else emptyList()) + listOf("-n", n.toString(), "-w", timeoutMs.toString(), host))
                .redirectErrorStream(true).start()
            p = proc
            val killer = Thread {
                try { Thread.sleep(n * timeoutMs.toLong() + 3000L); proc.destroy() } catch (_: InterruptedException) {}
            }
            killer.isDaemon = true
            killer.start()
            val out = try { proc.inputStream.bufferedReader().readText() } finally { killer.interrupt() }
            val times = parsePingWindows(out)
            if (times.isEmpty()) return Probe(false, 0.0, 0.0, 100, null, null, "no-reply")
            val loss = Math.round((n - times.size) * 100.0 / n).toInt()
            return Probe(true, times.min(), times.average(), if (loss < 0) 0 else loss, null, null, null)
        } catch (e: IOException) {
            return Probe(false, 0.0, 0.0, 100, null, null, "no-ping-binary")
        } finally {
            try { p?.destroy() } catch (_: Exception) {}
        }
    }

    fun parsePingWindows(out: String): List<Double> {
        val r = Regex("([=<])\\s*([0-9]+)\\s*ms", RegexOption.IGNORE_CASE)
        val res = ArrayList<Double>()
        for (line in out.lineSequence()) {
            if (!line.contains("TTL", ignoreCase = true)) continue
            val m = r.find(line) ?: continue
            val v = m.groupValues[2].toDouble()
            res.add(if (m.groupValues[1] == "<") 0.5 else v)
        }
        return res
    }

    fun parsePing(out: String): List<Double> {
        val r = Regex("time[=<]\\s*([0-9]+(?:\\.[0-9]+)?)\\s*ms")
        return r.findAll(out).mapNotNull { it.groupValues[1].toDoubleOrNull() }.toList()
    }

    /**
     * Real delay for a Cloudflare IP: TCP connect, TLS handshake with the given SNI, then
     * GET /cdn-cgi/trace. The reply also tells the real country (loc) and data center (colo).
     */
    fun realIp(host: String, sni: String, port: Int, samples: Int, timeoutMs: Int): Probe = aggregate(samples) {
        val t0 = System.nanoTime()
        val deadline = t0 + timeoutMs * 1_000_000L
        val s = dial(host, port, deadline)
        try {
            val connect = msSince(t0)
            val ts = tls(s, sni, deadline)
            send(ts, "GET /cdn-cgi/trace HTTP/1.1\r\nHost: $sni\r\nUser-Agent: $UA\r\nAccept: */*\r\nConnection: close\r\n\r\n")
            val head = readHead(ts, deadline)
            val code = statusOf(head)
            if (code < 100 || code > 599) throw ProbeError("not-http")
            val body = try { readBody(ts, deadline, 4096) } catch (_: SocketTimeoutException) { "" }
            val total = msSince(t0)
            val loc = Regex("loc=([A-Za-z]{2})").find(body)?.groupValues?.get(1)?.uppercase()
            val colo = Regex("colo=([A-Za-z0-9]{2,5})").find(body)?.groupValues?.get(1)?.uppercase()
            Attempt(connect, total, loc, colo)
        } finally {
            try { s.close() } catch (_: Exception) {}
        }
    }

    /** Real delay through a SOCKS5 proxy: handshake, CONNECT, then an HTTP(S) request to a 204 endpoint. */
    fun socks5(
        host: String, port: Int, user: String, pass: String,
        https: Boolean, target: String, samples: Int, timeoutMs: Int
    ): Probe = aggregate(samples) {
        val reached = BooleanArray(1)
        try {
            socks5Once(host, port, user, pass, https, target, timeoutMs, reached)
        } catch (e: Exception) {
            // The proxy answered at TCP level but the main target failed: retry once with a lighter target.
            if (!reached[0] || target != DEFAULT_TARGET) throw e
            try {
                socks5Once(host, port, user, pass, false, "cp.cloudflare.com", timeoutMs, reached)
            } catch (_: Exception) {
                throw e
            }
        }
    }

    /** Real delay through a SOCKS4 / SOCKS4a proxy (no password, optional user id). */
    fun socks4(
        host: String, port: Int, user: String, https: Boolean,
        target: String, samples: Int, timeoutMs: Int
    ): Probe = aggregate(samples) {
        val reached = BooleanArray(1)
        try {
            socks4Once(host, port, user, https, target, timeoutMs, reached)
        } catch (e: Exception) {
            if (!reached[0] || target != DEFAULT_TARGET) throw e
            try {
                socks4Once(host, port, user, false, "cp.cloudflare.com", timeoutMs, reached)
            } catch (_: Exception) {
                throw e
            }
        }
    }

    private fun socks4Once(
        host: String, port: Int, user: String, https: Boolean,
        target: String, timeoutMs: Int, reached: BooleanArray
    ): Attempt {
        val t0 = System.nanoTime()
        val deadline = t0 + timeoutMs * 1_000_000L
        val s = dial(host, port, deadline)
        reached[0] = true
        try {
            val connect = msSince(t0)
            val out = s.getOutputStream()
            val dport = if (https) 443 else 80
            // SOCKS4 needs an IPv4 address; fall back to the SOCKS4a form (domain name) when it cannot be resolved here.
            val ip4 = try {
                java.net.InetAddress.getAllByName(target).firstOrNull { it is java.net.Inet4Address }?.address
            } catch (_: Exception) { null }
            val uid = user.toByteArray(Charsets.UTF_8)
            val bo = java.io.ByteArrayOutputStream()
            bo.write(4); bo.write(1)
            bo.write(dport shr 8); bo.write(dport and 0xFF)
            if (ip4 != null) bo.write(ip4) else bo.write(byteArrayOf(0, 0, 0, 1))
            bo.write(uid); bo.write(0)
            if (ip4 == null) { bo.write(target.toByteArray(Charsets.US_ASCII)); bo.write(0) }
            out.write(bo.toByteArray())
            out.flush()
            val r = readExact(s, 8, deadline)
            if (r[0].toInt() != 0) throw ProbeError("not-socks4")
            val code = r[1].toInt() and 0xFF
            if (code != 90) throw ProbeError("socks4-err-$code")
            if (https) {
                val ts = tls(s, target, deadline)
                get204(ts, target, deadline)
            } else {
                get204(s, target, deadline)
            }
            return Attempt(connect, msSince(t0))
        } finally {
            try { s.close() } catch (_: Exception) {}
        }
    }

    private fun socks5Once(
        host: String, port: Int, user: String, pass: String,
        https: Boolean, target: String, timeoutMs: Int, reached: BooleanArray
    ): Attempt {
        val t0 = System.nanoTime()
        val deadline = t0 + timeoutMs * 1_000_000L
        val s = dial(host, port, deadline)
        reached[0] = true
        try {
            val connect = msSince(t0)
            val out = s.getOutputStream()
            val useAuth = user.isNotEmpty()
            out.write(if (useAuth) byteArrayOf(5, 2, 0, 2) else byteArrayOf(5, 1, 0))
            out.flush()
            val r = readExact(s, 2, deadline)
            if (r[0].toInt() != 5) throw ProbeError("not-socks5")
            when (r[1].toInt() and 0xFF) {
                0 -> { /* no authentication */ }
                2 -> {
                    if (!useAuth) throw ProbeError("needs-auth")
                    val u = user.toByteArray(Charsets.UTF_8)
                    val p = pass.toByteArray(Charsets.UTF_8)
                    if (u.size > 255 || p.size > 255) throw ProbeError("auth-failed")
                    val m = ByteArray(3 + u.size + p.size)
                    m[0] = 1
                    m[1] = u.size.toByte()
                    System.arraycopy(u, 0, m, 2, u.size)
                    m[2 + u.size] = p.size.toByte()
                    System.arraycopy(p, 0, m, 3 + u.size, p.size)
                    out.write(m)
                    out.flush()
                    val a = readExact(s, 2, deadline)
                    if (a[1].toInt() != 0) throw ProbeError("auth-failed")
                }
                else -> throw ProbeError("needs-auth")
            }
            val dport = if (https) 443 else 80
            val tb = target.toByteArray(Charsets.US_ASCII)
            val req = ByteArray(7 + tb.size)
            req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 3
            req[4] = tb.size.toByte()
            System.arraycopy(tb, 0, req, 5, tb.size)
            req[5 + tb.size] = (dport shr 8).toByte()
            req[6 + tb.size] = (dport and 0xFF).toByte()
            out.write(req)
            out.flush()
            val h = readExact(s, 4, deadline)
            if (h[0].toInt() != 5) throw ProbeError("bad-reply")
            val rep = h[1].toInt() and 0xFF
            if (rep != 0) throw ProbeError("socks-err-$rep")
            val skip = when (h[3].toInt() and 0xFF) {
                1 -> 6
                4 -> 18
                3 -> (readExact(s, 1, deadline)[0].toInt() and 0xFF) + 2
                else -> throw ProbeError("bad-reply")
            }
            readExact(s, skip, deadline)
            if (https) {
                val ts = tls(s, target, deadline)
                get204(ts, target, deadline)
            } else {
                get204(s, target, deadline)
            }
            return Attempt(connect, msSince(t0))
        } finally {
            try { s.close() } catch (_: Exception) {}
        }
    }

    /** Real delay through an HTTP proxy: plain forwarding, or a CONNECT tunnel plus TLS. */
    fun httpProxy(
        host: String, port: Int, user: String, pass: String,
        tunnel: Boolean, target: String, samples: Int, timeoutMs: Int
    ): Probe = aggregate(samples) {
        val t0 = System.nanoTime()
        val deadline = t0 + timeoutMs * 1_000_000L
        val s = dial(host, port, deadline)
        try {
            val connect = msSince(t0)
            val auth = if (user.isNotEmpty()) "Proxy-Authorization: Basic " + b64("$user:$pass") + "\r\n" else ""
            if (tunnel) {
                send(s, "CONNECT $target:443 HTTP/1.1\r\nHost: $target:443\r\nUser-Agent: $UA\r\n$auth\r\n")
                val code = statusOf(readHead(s, deadline))
                if (code == 407) throw ProbeError("needs-auth")
                if (code < 200 || code > 299) throw ProbeError("connect-$code")
                val ts = tls(s, target, deadline)
                get204(ts, target, deadline)
            } else {
                send(
                    s,
                    "GET http://$target/generate_204 HTTP/1.1\r\nHost: $target\r\nUser-Agent: $UA\r\n" +
                        "Proxy-Connection: close\r\nConnection: close\r\n$auth\r\n"
                )
                val code = statusOf(readHead(s, deadline))
                if (code == 407) throw ProbeError("needs-auth")
                if (code != 204) throw ProbeError("http-$code")
            }
            Attempt(connect, msSince(t0))
        } finally {
            try { s.close() } catch (_: Exception) {}
        }
    }

    // --------------------------------------------------------------- web helpers

    /** Downloads a text file. Follows redirects itself (also http to https). No CORS limits. */
    fun fetchText(url: String, timeoutMs: Int, maxBytes: Int = 12_000_000): String {
        var u = url
        for (hop in 0 until 6) {
            val c = URL(u).openConnection() as HttpURLConnection
            try {
                c.connectTimeout = timeoutMs
                c.readTimeout = timeoutMs
                c.instanceFollowRedirects = false
                c.setRequestProperty("User-Agent", UA)
                val code = c.responseCode
                if (code in 300..399) {
                    val loc = c.getHeaderField("Location") ?: throw ProbeError("http-$code")
                    u = URL(URL(u), loc).toString()
                    continue
                }
                if (code != 200) throw ProbeError("http-$code")
                val bo = ByteArrayOutputStream()
                val buf = ByteArray(16384)
                c.inputStream.use { ins ->
                    while (bo.size() < maxBytes) {
                        val r = ins.read(buf)
                        if (r < 0) break
                        bo.write(buf, 0, r)
                    }
                }
                return String(bo.toByteArray(), Charsets.UTF_8)
            } finally {
                c.disconnect()
            }
        }
        throw ProbeError("too-many-redirects")
    }

    /** Country codes for IPs: one batch request per 100 IPs, then single lookups for the leftovers. */
    /** Local signs of an active VPN: tunnel-like network interfaces that are up. Works on Android and Windows. */
    fun vpnLocal(): List<String> {
        val out = ArrayList<String>()
        try {
            val en = java.net.NetworkInterface.getNetworkInterfaces() ?: return out
            while (en.hasMoreElements()) {
                val ni = en.nextElement()
                val up = try { ni.isUp && !ni.isLoopback } catch (_: Exception) { false }
                if (!up) continue
                val n = ni.name.lowercase()
                val d = (ni.displayName ?: "").lowercase()
                val tun = Regex("^(tun|tap|ppp|pptp|wg|ipsec|utun|nordlynx|proton|tailscale)[0-9]*$").matches(n) ||
                    n.startsWith("tun") || n.startsWith("ppp") || n.startsWith("wg") || n.startsWith("ipsec")
                val win = listOf(
                    "tap-windows", "openvpn", "wireguard", "wintun", "nordlynx", "vpn", "anyconnect",
                    "fortinet", "tunnelbear", "proton", "surfshark", "expressvpn", "mullvad", "tailscale"
                ).any { d.contains(it) }
                if (tun || win) out.add("iface:" + ni.name)
            }
        } catch (_: Exception) {
        }
        return out
    }

    fun geo(ips: List<String>): Map<String, String> {
        val out = HashMap<String, String>()
        val ok = Regex("^[0-9A-Fa-f:.]{3,45}$")
        val uniq = ips.filter { ok.matches(it) }.distinct()
        var i = 0
        while (i < uniq.size) {
            val chunk = uniq.subList(i, minOf(i + 100, uniq.size))
            i += 100
            try {
                val c = URL("http://ip-api.com/batch?fields=status,countryCode,query,isp").openConnection() as HttpURLConnection
                try {
                    c.requestMethod = "POST"
                    c.doOutput = true
                    c.connectTimeout = 6000
                    c.readTimeout = 9000
                    c.setRequestProperty("Content-Type", "application/json")
                    c.setRequestProperty("User-Agent", UA)
                    val body = chunk.joinToString(",", "[", "]") { "\"$it\"" }
                    c.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                    val txt = c.inputStream.bufferedReader().readText()
                    for (m in Regex("\\{[^{}]*\\}").findAll(txt)) {
                        val o = m.value
                        val q = Regex("\"query\"\\s*:\\s*\"([^\"]+)\"").find(o)?.groupValues?.get(1)
                        val cc = Regex("\"countryCode\"\\s*:\\s*\"([A-Za-z]{2})\"").find(o)?.groupValues?.get(1)
                        val isp = Regex("\"isp\"\\s*:\\s*\"([^\"]*)\"").find(o)?.groupValues?.get(1)?.replace("|", " ") ?: ""
                        if (q != null && cc != null) out[q] = cc.uppercase() + "|" + isp
                    }
                } finally {
                    c.disconnect()
                }
            } catch (_: Exception) {
            }
        }
        for (ip in uniq.filter { !out.containsKey(it) }.take(25)) {
            try {
                val txt = fetchText("https://ipwho.is/$ip?fields=success,country_code,connection", 5000, 20000)
                val cc = Regex("\"country_code\"\\s*:\\s*\"([A-Za-z]{2})\"").find(txt)?.groupValues?.get(1)
                val isp = Regex("\"isp\"\\s*:\\s*\"([^\"]*)\"").find(txt)?.groupValues?.get(1)?.replace("|", " ") ?: ""
                if (cc != null) out[ip] = cc.uppercase() + "|" + isp
            } catch (_: Exception) {
            }
        }
        return out
    }
}
