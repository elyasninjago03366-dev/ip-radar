package app.ipscanner

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.webkit.JavascriptInterface
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import org.json.JSONArray
import org.json.JSONObject
import java.net.SocketTimeoutException
import java.util.concurrent.Executors

class MainActivity : Activity() {

    lateinit var web: WebView
    private var fileCb: ValueCallback<Array<Uri>>? = null
    private var pendingSave: String? = null

    companion object {
        const val REQ_FILE = 11
        const val REQ_SAVE = 12
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val bg = Color.parseColor("#0A0F0B")
        window.statusBarColor = bg
        window.navigationBarColor = bg

        web = WebView(this)
        web.setBackgroundColor(bg)
        web.overScrollMode = View.OVER_SCROLL_NEVER
        setContentView(web)

        val s = web.settings
        s.javaScriptEnabled = true
        s.domStorageEnabled = true
        s.allowFileAccess = false            // android_asset pages still load; the app can't read other files
        s.allowContentAccess = false
        @Suppress("DEPRECATION") run {
            s.allowFileAccessFromFileURLs = false
            s.allowUniversalAccessFromFileURLs = false
        }
        s.mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
        s.setGeolocationEnabled(false)
        s.setSupportZoom(false)

        web.addJavascriptInterface(Bridge(this), "Native")

        web.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(
                view: WebView?,
                callback: ValueCallback<Array<Uri>>?,
                params: FileChooserParams?
            ): Boolean {
                fileCb?.onReceiveValue(null)
                fileCb = callback
                return try {
                    startActivityForResult(params!!.createIntent(), REQ_FILE)
                    true
                } catch (e: Exception) {
                    fileCb = null
                    callback?.onReceiveValue(null)
                    false
                }
            }
        }

        web.webViewClient = object : WebViewClient() {
            // If the WebView's render process dies (low memory), restart the screen instead of crashing the app.
            override fun onRenderProcessGone(view: WebView?, detail: android.webkit.RenderProcessGoneDetail?): Boolean {
                runOnUiThread { recreate() }
                return true
            }
            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                val u = request?.url ?: return true
                if (u.scheme == "file") return false
                try {
                    startActivity(Intent(Intent.ACTION_VIEW, u))
                } catch (e: Exception) {
                }
                return true
            }
        }

        web.loadUrl("file:///android_asset/index.html")
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_FILE) {
            fileCb?.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(resultCode, data))
            fileCb = null
        } else if (requestCode == REQ_SAVE) {
            val text = pendingSave
            pendingSave = null
            val uri = data?.data
            var ok = false
            if (resultCode == RESULT_OK && uri != null && text != null) {
                try {
                    contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray(Charsets.UTF_8)) }
                    ok = true
                } catch (e: Exception) {
                }
            }
            js("window.__saved && window.__saved($ok)")
        }
    }

    override fun onDestroy() {
        web.destroy()
        super.onDestroy()
    }

    fun js(code: String) {
        if (!isDestroyed) web.evaluateJavascript(code, null)
    }

    fun copy(text: String) {
        runOnUiThread {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("IP Scanner", text))
        }
    }

    @Suppress("DEPRECATION")
    fun save(name: String, text: String) {
        runOnUiThread {
            pendingSave = text
            val i = Intent(Intent.ACTION_CREATE_DOCUMENT)
            i.addCategory(Intent.CATEGORY_OPENABLE)
            i.type = "text/plain"
            i.putExtra(Intent.EXTRA_TITLE, name)
            try {
                startActivityForResult(i, REQ_SAVE)
            } catch (e: Exception) {
                pendingSave = null
                js("window.__saved && window.__saved(false)")
            }
        }
    }
}

/** Methods the web page can call as Native.req(id, method, jsonArgs). Results come back via window.__nat(id, json). */
class Bridge(private val act: MainActivity) {

    private val pool = Executors.newCachedThreadPool { r ->
        val t = Thread(r)
        t.isDaemon = true
        t
    }

    @JavascriptInterface
    fun version(): String = try {
        "android:" + (act.packageManager.getPackageInfo(act.packageName, 0).versionName ?: "1.0.1")
    } catch (e: Exception) { "android:1.0.1" }

    @JavascriptInterface
    fun keepOn(on: Boolean) {
        act.runOnUiThread { act.web.keepScreenOn = on }
    }

    @JavascriptInterface
    fun req(id: Int, method: String, argsJson: String) {
        pool.execute {
            val res = try {
                dispatch(method, JSONObject(argsJson))
            } catch (e: Throwable) {
                fail(e)
            }
            act.runOnUiThread { act.js("window.__nat($id,${JSONObject.quote(res)})") }
        }
    }

    private fun fail(e: Throwable): String {
        val code = when (e) {
            is ProbeError -> e.code
            is SocketTimeoutException -> "timeout"
            else -> e.javaClass.simpleName
        }
        return JSONObject().put("ok", false).put("err", code).toString()
    }

    private fun probe(p: Probe): String {
        val o = JSONObject()
        o.put("ok", p.ok)
        o.put("ping", p.ping)
        o.put("delay", p.delay)
        o.put("loss", p.loss)
        if (p.loc != null) o.put("loc", p.loc)
        if (p.colo != null) o.put("colo", p.colo)
        if (p.err != null) o.put("err", p.err)
        return o.toString()
    }

    private fun dispatch(m: String, a: JSONObject): String {
        val timeout = a.optInt("timeout", 5000)
        val samples = a.optInt("samples", 2)
        return when (m) {
            "tcp" -> probe(Engine.tcp(a.getString("host"), a.getInt("port"), samples, timeout))
            "icmp" -> probe(Engine.icmp(a.getString("host"), samples, timeout))
            "real" -> probe(
                Engine.realIp(
                    a.getString("host"), a.optString("sni", "www.cloudflare.com"),
                    a.optInt("port", 443), samples, timeout
                )
            )
            "socks5" -> probe(
                Engine.socks5(
                    a.getString("host"), a.getInt("port"), a.optString("user", ""), a.optString("pass", ""),
                    a.optBoolean("https", true), a.optString("target", Engine.DEFAULT_TARGET), samples, timeout
                )
            )
            "http" -> probe(
                Engine.httpProxy(
                    a.getString("host"), a.getInt("port"), a.optString("user", ""), a.optString("pass", ""),
                    a.optBoolean("tunnel", false), a.optString("target", Engine.DEFAULT_TARGET), samples, timeout
                )
            )
            "fetch" -> JSONObject().put("ok", true).put("text", Engine.fetchText(a.getString("url"), a.optInt("timeout", 15000))).toString()
            "geo" -> {
                val arr: JSONArray = a.getJSONArray("ips")
                val ips = ArrayList<String>()
                for (i in 0 until arr.length()) ips.add(arr.getString(i))
                val map = JSONObject()
                for ((k, v) in Engine.geo(ips)) map.put(k, v)
                JSONObject().put("ok", true).put("map", map).toString()
            }
            "copy" -> {
                act.copy(a.getString("text"))
                JSONObject().put("ok", true).toString()
            }
            "socks4" -> probe(
                Engine.socks4(
                    a.getString("host"), a.getInt("port"), a.optString("user", ""),
                    a.optBoolean("https", true), a.optString("target", Engine.DEFAULT_TARGET), samples, timeout
                )
            )
            "vpn" -> {
                val list = ArrayList<String>(Engine.vpnLocal())
                try {
                    val cm = act.getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
                    val net = cm.activeNetwork
                    val caps = if (net != null) cm.getNetworkCapabilities(net) else null
                    if (caps != null && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) list.add("transport")
                } catch (_: Exception) {
                }
                if (!System.getProperty("http.proxyHost").isNullOrEmpty()) list.add("proxy-setting")
                JSONObject().put("ok", true).put("reasons", JSONArray(list)).toString()
            }
            "paste" -> {
                var txt = ""
                val l = java.util.concurrent.CountDownLatch(1)
                act.runOnUiThread {
                    try {
                        val cm = act.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        txt = cm.primaryClip?.getItemAt(0)?.coerceToText(act)?.toString() ?: ""
                    } catch (_: Exception) {
                    }
                    l.countDown()
                }
                l.await(2, java.util.concurrent.TimeUnit.SECONDS)
                JSONObject().put("ok", true).put("text", txt).toString()
            }
            "save" -> {
                act.save(a.optString("name", "list.txt"), a.getString("text"))
                JSONObject().put("ok", true).toString()
            }
            else -> JSONObject().put("ok", false).put("err", "unknown-method").toString()
        }
    }
}
