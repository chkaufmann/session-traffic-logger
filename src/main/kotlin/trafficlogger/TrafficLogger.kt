package trafficlogger

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.extension.ExtensionUnloadingHandler
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.handler.*
import burp.api.montoya.http.message.requests.HttpRequest as MontoyaHttpRequest
import burp.api.montoya.http.message.responses.HttpResponse as MontoyaHttpResponse
import burp.api.montoya.ui.editor.EditorOptions

import javax.swing.*
import javax.swing.table.*
import java.awt.*
import java.awt.Window
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.io.File
import java.sql.*
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicLong

// ─────────────────────────────────────────────────────────────
// Storage Settings
// ─────────────────────────────────────────────────────────────

enum class StorageMode { FULL, HEADERS_ONLY, SIZE_LIMITED }

data class StorageSettings(
    val mode:      StorageMode = StorageMode.FULL,
    val maxSizeMb: Int         = 1
)

// ─────────────────────────────────────────────────────────────
// Entry Point
// ─────────────────────────────────────────────────────────────

class TrafficLogger : BurpExtension, ExtensionUnloadingHandler {

    private lateinit var api:     MontoyaApi
    private lateinit var db:      DatabaseManager
    private lateinit var ui:      TrafficLoggerUI
    private lateinit var handler: TrafficHttpHandler

    override fun initialize(api: MontoyaApi) {
        this.api = api
        api.extension().setName("Session Traffic Logger")
        api.extension().registerUnloadingHandler(this)

        val firstRun = api.persistence().preferences().getString("trafficlogger.firstrun")
        if (firstRun.isNullOrBlank()) {
            SwingUtilities.invokeAndWait {
                JOptionPane.showMessageDialog(null,
                    "⚠  Security Notice\n\n" +
                    "Session Traffic Logger stores full HTTP traffic to a local SQLite database.\n" +
                    "This may include sensitive data such as:\n" +
                    "  • Session cookies & authentication tokens\n" +
                    "  • Passwords & personal information\n" +
                    "  • API keys & credentials\n\n" +
                    "Ensure your log directory is properly secured.\n" +
                    "Do not share .db files without reviewing their contents.",
                    "Session Traffic Logger – Security Notice",
                    JOptionPane.WARNING_MESSAGE)
            }
            api.persistence().preferences().setString("trafficlogger.firstrun", "done")
        }

        val savedPath = api.persistence().preferences().getString("trafficlogger.dbpath")
        val dbPath    = if (savedPath.isNullOrBlank()) askForDirectory() else savedPath

        if (dbPath == null) {
            api.logging().logToOutput("Session Traffic Logger: No directory selected – Extension disabled.")
            return
        }
        api.persistence().preferences().setString("trafficlogger.dbpath", dbPath)

        val storageSettings = loadStorageSettings()

        val ts          = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmmss"))
        val projectName = try {
            Window.getWindows()
                .filterIsInstance<JFrame>()
                .firstOrNull { it.isVisible && it.title.contains("Burp") }
                ?.title
                ?.substringBefore(" -")
                ?.trim()
                ?.replace(Regex("[^a-zA-Z0-9_\\-]"), "_")
                ?: "unknown"
        } catch (_: Exception) { "unknown" }

        val dbFile = "$dbPath${File.separator}${projectName}_$ts.db"
        db = DatabaseManager(dbFile, api)
        db.initialize()
        api.logging().logToOutput("Session Traffic Logger: Saving to $dbFile")

        handler = TrafficHttpHandler(api, db, storageSettings)
        ui      = TrafficLoggerUI(api, db, handler)
        api.userInterface().registerSuiteTab("Session Traffic Logger", ui.panel)
        api.http().registerHttpHandler(handler)
    }

    override fun extensionUnloaded() {
        if (::db.isInitialized) db.close()
        api.logging().logToOutput("Session Traffic Logger: Extension unloaded, database closed.")
    }

    private fun askForDirectory(): String? {
        var result: String? = null
        SwingUtilities.invokeAndWait {
            val chooser = JFileChooser()
            chooser.dialogTitle       = "Session Traffic Logger – Select Log Directory"
            chooser.fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION)
                result = chooser.selectedFile.absolutePath
        }
        return result
    }

    private fun loadStorageSettings(): StorageSettings {
        val mode = when (api.persistence().preferences().getString("trafficlogger.storage.mode")) {
            "HEADERS_ONLY" -> StorageMode.HEADERS_ONLY
            "SIZE_LIMITED" -> StorageMode.SIZE_LIMITED
            else           -> StorageMode.FULL
        }
        val maxMb = api.persistence().preferences().getString("trafficlogger.storage.maxsizemb")
            ?.toIntOrNull() ?: 1
        return StorageSettings(mode, maxMb)
    }
}

// ─────────────────────────────────────────────────────────────
// HTTP Handler
// ─────────────────────────────────────────────────────────────

class TrafficHttpHandler(
    private val api:     MontoyaApi,
    private val db:      DatabaseManager,
    var storageSettings: StorageSettings
) : HttpHandler {

    override fun handleHttpRequestToBeSent(r: HttpRequestToBeSent): RequestToBeSentAction {
        return RequestToBeSentAction.continueWith(r)
        }

    override fun handleHttpResponseReceived(response: HttpResponseReceived): ResponseReceivedAction {
        try {
            if (response.toolSource().toolType() == burp.api.montoya.core.ToolType.PROXY)
                return ResponseReceivedAction.continueWith(response)

            val req     = response.initiatingRequest()
            val service = req.httpService()
            val url     = req.url()

            val contentType = response.headers()
                .firstOrNull { it.name().equals("Content-Type", ignoreCase = true) }
                ?.value() ?: ""

            val urlPath   = try { java.net.URI(url).path } catch (_: Exception) { url }
            val extension = urlPath.substringAfterLast('.', "")
                .let { if (it.length > 10 || it.contains('/')) "" else it.lowercase() }

            val reqStr  = applyStorageMode(req.toString())
            val respStr = applyStorageMode(response.toString())

            val entry = LogEntry(
                id         = 0,
                host       = service.host(),
                port       = service.port(),
                method     = req.method(),
                url        = url,
                hasParams  = req.hasParameters(),
                status     = response.statusCode().toInt(),
                length     = respStr.length,
                mimeType   = parseMimeType(contentType),
                extension  = extension,
                tls        = service.secure(),
                hasCookies = req.headers().any { it.name().equals("Cookie", ignoreCase = true) },
                time       = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                tool       = normalizeTool(response.toolSource().toolType().toolName()),
                inScope    = api.scope().isInScope(url),
                request    = reqStr,
                response   = respStr,
                isLive     = true
            )

            db.insert(entry)
            SwingUtilities.invokeLater { db.onEntryInserted?.invoke(entry) }

        } catch (e: Exception) {
            api.logging().logToError("Session Traffic Logger handler error: ${e.message}")
        }

        return ResponseReceivedAction.continueWith(response)
    }

    private fun applyStorageMode(raw: String): String {
        return when (storageSettings.mode) {
            StorageMode.FULL         -> raw
            StorageMode.HEADERS_ONLY -> extractHeaders(raw)
            StorageMode.SIZE_LIMITED -> {
                val limit = storageSettings.maxSizeMb * 1024 * 1024
                if (raw.length > limit) raw.substring(0, limit) + "\n[TRUNCATED]"
                else raw
            }
        }
    }

    private fun extractHeaders(raw: String): String {
        val blankLine = raw.indexOf("\r\n\r\n")
        return if (blankLine >= 0) raw.substring(0, blankLine) else raw
    }

    private fun parseMimeType(ct: String): String {
        val c = ct.lowercase().substringBefore(';').trim()
        return when {
            c.contains("text/html")                                   -> "HTML"
            c.contains("javascript") || c.contains("ecmascript")      -> "Script"
            c.contains("text/xml") || c.contains("application/xml")   -> "XML"
            c.contains("application/json") || c.contains("text/json") -> "JSON"
            c.startsWith("image/")                                     -> "Image"
            c.contains("text/css")                                     -> "CSS"
            c.startsWith("text/")                                      -> "Other text"
            c.isNotEmpty()                                             -> "Other binary"
            else                                                       -> ""
        }
    }

    private fun normalizeTool(tool: String): String {
    return when (tool.lowercase()) {
        "repeater"             -> "Repeater"
        "scanner"              -> "Scanner"
        "intruder"             -> "Intruder"
        "target"               -> "Target"
        "extender", "extensions" -> "Extender"
        else                   -> tool
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Data Model
// ─────────────────────────────────────────────────────────────

data class LogEntry(
    val id:         Int,
    val host:       String,
    val port:       Int,
    val method:     String,
    val url:        String,
    val hasParams:  Boolean,
    val status:     Int,
    val length:     Int,
    val mimeType:   String,
    val extension:  String,
    val tls:        Boolean,
    val hasCookies: Boolean,
    val time:       String,
    val tool:       String,
    val inScope:    Boolean,
    val request:    String,
    val response:   String,
    val isLive:     Boolean
)

// ─────────────────────────────────────────────────────────────
// Database (async writes, batch commits for performance)
// ─────────────────────────────────────────────────────────────

class DatabaseManager(var dbFile: String, private val api: MontoyaApi) {

    private lateinit var conn: Connection
    private val writeQueue = LinkedBlockingQueue<LogEntry>(10000)
    var onEntryInserted: ((LogEntry) -> Unit)? = null
    private val dropCount = AtomicLong(0)

    private val BATCH_SIZE = 50

    private val writer = Thread {
        var counter = 0
        while (!Thread.currentThread().isInterrupted) {
            try {
                val entry = writeQueue.poll(100, java.util.concurrent.TimeUnit.MILLISECONDS)
                if (entry != null) {
                    insertSync(entry)
                    counter++
                }
                if (counter >= BATCH_SIZE || (entry == null && counter > 0)) {
                    conn.commit()
                    counter = 0
                }
            } catch (_: InterruptedException) {
                try { conn.commit() } catch (_: Exception) {}
                Thread.currentThread().interrupt()
            } catch (e: Exception) {
                api.logging().logToError("Session Traffic Logger DB write error: ${e.message}")
            }
        }
    }.apply { isDaemon = true }

    fun initialize() {
        Class.forName("org.sqlite.JDBC")
        conn = DriverManager.getConnection("jdbc:sqlite:$dbFile")
        conn.createStatement().use { it.execute("""
            CREATE TABLE IF NOT EXISTS traffic (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                host        TEXT,
                port        INTEGER,
                method      TEXT,
                url         TEXT,
                has_params  INTEGER,
                status      INTEGER,
                length      INTEGER,
                mime_type   TEXT,
                extension   TEXT,
                tls         INTEGER,
                has_cookies INTEGER,
                time        TEXT,
                tool        TEXT,
                in_scope    INTEGER,
                request     TEXT,
                response    TEXT
            )
        """) }
        conn.createStatement().use { it.execute("CREATE INDEX IF NOT EXISTS idx_id ON traffic(id)") }
        conn.createStatement().use { it.execute("PRAGMA journal_mode=WAL") }
        conn.createStatement().use { it.execute("PRAGMA synchronous=NORMAL") }
        conn.autoCommit = false
        writer.start()
    }

    fun close() {
        writer.interrupt()
        writeQueue.clear()
        writer.join(2000)
        try {
            conn.commit()
            conn.close()
        } catch (_: Exception) {}
    }

    // Non-blocking insert – avoids stalling Burp HTTP handler threads
    fun insert(e: LogEntry) {
        if (!writeQueue.offer(e)) {
            val count = dropCount.incrementAndGet()
            if (count % 100 == 0L)
                api.logging().logToError("Session Traffic Logger: write queue full, $count entries dropped")
        }
    }

    private fun insertSync(e: LogEntry) {
        conn.prepareStatement("""
            INSERT INTO traffic
            (host,port,method,url,has_params,status,length,mime_type,extension,
             tls,has_cookies,time,tool,in_scope,request,response)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """).use { ps ->
            ps.setString(1,  e.host)
            ps.setInt(2,     e.port)
            ps.setString(3,  e.method)
            ps.setString(4,  e.url)
            ps.setInt(5,     if (e.hasParams)  1 else 0)
            ps.setInt(6,     e.status)
            ps.setInt(7,     e.length)
            ps.setString(8,  e.mimeType)
            ps.setString(9,  e.extension)
            ps.setInt(10,    if (e.tls)        1 else 0)
            ps.setInt(11,    if (e.hasCookies) 1 else 0)
            ps.setString(12, e.time)
            ps.setString(13, e.tool)
            ps.setInt(14,    if (e.inScope)    1 else 0)
            ps.setString(15, e.request)
            ps.setString(16, e.response)
            ps.executeUpdate()
        }
    }

    fun loadFromFile(file: String): List<LogEntry> {
        val entries = mutableListOf<LogEntry>()
        try {
            val c = DriverManager.getConnection("jdbc:sqlite:$file")
            c.createStatement().use { st ->
                st.executeQuery("SELECT * FROM traffic ORDER BY id").use { rs ->
                    while (rs.next()) entries.add(rs.toEntry())
                }
            }
            c.close()
        } catch (e: Exception) {
            api.logging().logToError("Session Traffic Logger load error: ${e.message}")
        }
        return entries
    }

    fun moveToDirectory(newDir: String): String {
        val oldFile = File(dbFile)
        val newFile = File(newDir, oldFile.name)
        try { conn.commit() } catch (_: Exception) {}
        conn.close()
        oldFile.copyTo(newFile, overwrite = true)
        oldFile.delete()
        conn = DriverManager.getConnection("jdbc:sqlite:${newFile.absolutePath}")
        conn.createStatement().use { it.execute("PRAGMA journal_mode=WAL") }
        conn.createStatement().use { it.execute("PRAGMA synchronous=NORMAL") }
        conn.autoCommit = false
        dbFile = newFile.absolutePath
        return newFile.absolutePath
    }

    private fun ResultSet.toEntry() = LogEntry(
        id         = safeInt("id"),
        host       = safeStr("host"),
        port       = safeInt("port"),
        method     = safeStr("method"),
        url        = safeStr("url"),
        hasParams  = safeInt("has_params")  == 1,
        status     = safeInt("status"),
        length     = safeInt("length"),
        mimeType   = safeStr("mime_type"),
        extension  = safeStr("extension"),
        tls        = safeInt("tls")         == 1,
        hasCookies = safeInt("has_cookies") == 1,
        time       = safeStr("time"),
        tool       = safeStr("tool"),
        inScope    = safeInt("in_scope")    == 1,
        request    = safeStr("request"),
        response   = safeStr("response"),
        isLive     = false
    )

    private fun ResultSet.safeStr(c: String) = try { getString(c) ?: "" } catch (_: Exception) { "" }
    private fun ResultSet.safeInt(c: String) = try { getInt(c) }          catch (_: Exception) { 0  }
}

// ─────────────────────────────────────────────────────────────
// Filter Settings
// ─────────────────────────────────────────────────────────────

data class FilterSettings(
    val inScopeOnly:        Boolean = false,
    val hideNoResponse:     Boolean = false,
    val show2xx:            Boolean = true,
    val show3xx:            Boolean = true,
    val show4xx:            Boolean = true,
    val show5xx:            Boolean = true,
    val searchTerm:         String  = "",
    val searchRegex:        Boolean = false,
    val searchCaseSens:     Boolean = false,
    val searchNegative:     Boolean = false,
    val showHtml:           Boolean = true,
    val showScript:         Boolean = true,
    val showXml:            Boolean = true,
    val showJson:           Boolean = true,
    val showImage:          Boolean = false,
    val showCss:            Boolean = false,
    val showOtherText:      Boolean = true,
    val showOtherBinary:    Boolean = true,
    val extShowOnly:        String  = "",
    val extShowOnlyEnabled: Boolean = false,
    val extHide:            String  = "js,gif,jpg,png,ico,css,woff,woff2,ttf,svg",
    val extHideEnabled:     Boolean = true,
    val showRepeater:       Boolean = true,
    val showScanner:        Boolean = true,
    val showIntruder:       Boolean = true,
    val showTarget:         Boolean = true,
    val showExtender:       Boolean = true
)

// ─────────────────────────────────────────────────────────────
// Filter Dialog
// ─────────────────────────────────────────────────────────────

class FilterDialog(parent: Window?, cur: FilterSettings) : JDialog(parent) {

    var result: FilterSettings? = null

    private val cbInScope     = JCheckBox("Show only in-scope items",     cur.inScopeOnly)
    private val cbHideNoResp  = JCheckBox("Hide items without responses",  cur.hideNoResponse)
    private val cb2xx         = JCheckBox("2xx [success]",                cur.show2xx)
    private val cb3xx         = JCheckBox("3xx [redirection]",            cur.show3xx)
    private val cb4xx         = JCheckBox("4xx [request error]",          cur.show4xx)
    private val cb5xx         = JCheckBox("5xx [server error]",           cur.show5xx)
    private val tfSearch      = JTextField(cur.searchTerm, 22)
    private val cbRegex       = JCheckBox("Regex",                        cur.searchRegex)
    private val cbCase        = JCheckBox("Case sensitive",               cur.searchCaseSens)
    private val cbNegative    = JCheckBox("Negative search",              cur.searchNegative)
    private val cbHtml        = JCheckBox("HTML",                         cur.showHtml)
    private val cbScript      = JCheckBox("Script",                       cur.showScript)
    private val cbXml         = JCheckBox("XML",                          cur.showXml)
    private val cbJson        = JCheckBox("JSON",                         cur.showJson)
    private val cbImage       = JCheckBox("Images",                       cur.showImage)
    private val cbCss         = JCheckBox("CSS",                          cur.showCss)
    private val cbOtherText   = JCheckBox("Other text",                   cur.showOtherText)
    private val cbOtherBinary = JCheckBox("Other binary",                 cur.showOtherBinary)
    private val cbExtShowOnly = JCheckBox("Show only:", cur.extShowOnlyEnabled)
    private val cbExtHide     = JCheckBox("Hide:",      cur.extHideEnabled)
    private val tfExtShowOnly = JTextField(cur.extShowOnly, 18)
    private val tfExtHide     = JTextField(cur.extHide,     18)
    private val cbRepeater    = JCheckBox("Repeater", cur.showRepeater)
    private val cbScanner     = JCheckBox("Scanner",  cur.showScanner)
    private val cbIntruder    = JCheckBox("Intruder", cur.showIntruder)
    private val cbTarget      = JCheckBox("Target",   cur.showTarget)
    private val cbExtender    = JCheckBox("Extender", cur.showExtender)

    init {
        title   = "HTTP Traffic Filter"
        isModal = true
        defaultCloseOperation = JDialog.DISPOSE_ON_CLOSE
        layout  = BorderLayout(8, 8)

        val top = JPanel(GridLayout(1, 3, 8, 8))
        top.border = BorderFactory.createEmptyBorder(8, 8, 0, 8)
        top.add(vSection("Filter by request type", cbInScope, cbHideNoResp))
        top.add(vSection("Filter by status code", cb2xx, cb3xx, cb4xx, cb5xx))
        top.add(vSection("Filter by tool (Proxy always shown)",
            cbRepeater, cbScanner, cbIntruder, cbTarget, cbExtender))

        val bot = JPanel(GridLayout(1, 3, 8, 8))
        bot.border = BorderFactory.createEmptyBorder(0, 8, 8, 8)

        val searchPanel = JPanel(BorderLayout(4, 4))
        searchPanel.border = BorderFactory.createTitledBorder("Filter by search term")
        searchPanel.add(tfSearch, BorderLayout.NORTH)
        val searchOpts = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        searchOpts.add(cbRegex); searchOpts.add(cbCase); searchOpts.add(cbNegative)
        searchPanel.add(searchOpts, BorderLayout.CENTER)
        bot.add(searchPanel)

        val mimePanel = JPanel(GridLayout(4, 2, 2, 2))
        mimePanel.border = BorderFactory.createTitledBorder("Filter by MIME type")
        listOf(cbHtml, cbScript, cbXml, cbJson, cbImage, cbCss, cbOtherText, cbOtherBinary)
            .forEach { mimePanel.add(it) }
        bot.add(mimePanel)

        val extPanel = JPanel()
        extPanel.layout = BoxLayout(extPanel, BoxLayout.Y_AXIS)
        extPanel.border = BorderFactory.createTitledBorder("Filter by file extension")
        extPanel.add(row(cbExtShowOnly, tfExtShowOnly))
        extPanel.add(row(cbExtHide,     tfExtHide))
        bot.add(extPanel)

        val center = JPanel(GridLayout(2, 1, 8, 8))
        center.add(top); center.add(bot)
        add(center, BorderLayout.CENTER)

        val btnRow  = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 6))
        val showAll = JButton("Show all")
        val hideAll = JButton("Hide all")
        val cancel  = JButton("Cancel")
        val apply   = JButton("Apply & close")
        apply.background     = Color(0xE8, 0x5C, 0x1E)
        apply.foreground     = Color.WHITE
        apply.isFocusPainted = false

        showAll.addActionListener { setAll(true)  }
        hideAll.addActionListener { setAll(false) }
        cancel .addActionListener { dispose() }
        apply  .addActionListener { applyAndClose() }

        listOf(showAll, hideAll, cancel, apply).forEach { btnRow.add(it) }
        add(btnRow, BorderLayout.SOUTH)
        pack()
        setLocationRelativeTo(parent)
    }

    private fun vSection(title: String, vararg c: JComponent) = JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        border = BorderFactory.createTitledBorder(title)
        c.forEach { add(it) }
    }

    private fun row(vararg c: JComponent) = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2)).apply {
        c.forEach { add(it) }
    }

    private fun setAll(on: Boolean) {
        listOf(cb2xx, cb3xx, cb4xx, cb5xx,
               cbHtml, cbScript, cbXml, cbJson, cbImage, cbCss, cbOtherText, cbOtherBinary,
               cbRepeater, cbScanner, cbIntruder, cbTarget, cbExtender)
            .forEach { it.isSelected = on }
        cbExtHide.isSelected     = !on
        cbExtShowOnly.isSelected = false
    }

    private fun applyAndClose() {
        result = FilterSettings(
            inScopeOnly        = cbInScope.isSelected,
            hideNoResponse     = cbHideNoResp.isSelected,
            show2xx            = cb2xx.isSelected,
            show3xx            = cb3xx.isSelected,
            show4xx            = cb4xx.isSelected,
            show5xx            = cb5xx.isSelected,
            searchTerm         = tfSearch.text.trim(),
            searchRegex        = cbRegex.isSelected,
            searchCaseSens     = cbCase.isSelected,
            searchNegative     = cbNegative.isSelected,
            showHtml           = cbHtml.isSelected,
            showScript         = cbScript.isSelected,
            showXml            = cbXml.isSelected,
            showJson           = cbJson.isSelected,
            showImage          = cbImage.isSelected,
            showCss            = cbCss.isSelected,
            showOtherText      = cbOtherText.isSelected,
            showOtherBinary    = cbOtherBinary.isSelected,
            extShowOnly        = tfExtShowOnly.text.trim(),
            extShowOnlyEnabled = cbExtShowOnly.isSelected,
            extHide            = tfExtHide.text.trim(),
            extHideEnabled     = cbExtHide.isSelected,
            showRepeater       = cbRepeater.isSelected,
            showScanner        = cbScanner.isSelected,
            showIntruder       = cbIntruder.isSelected,
            showTarget         = cbTarget.isSelected,
            showExtender       = cbExtender.isSelected
        )
        dispose()
    }
}

// ─────────────────────────────────────────────────────────────
// Settings Dialog
// ─────────────────────────────────────────────────────────────

class SettingsDialog(
    parent:  Window?,
    private val api: MontoyaApi,
    private val db:  DatabaseManager
) : JDialog(parent) {

    var onSettingsChanged: ((StorageSettings) -> Unit)? = null

    private val dirField    = JTextField(
        api.persistence().preferences().getString("trafficlogger.dbpath") ?: "", 30)
    private val rbFull      = JRadioButton("Full request + response (Headers + Body)")
    private val rbHeaders   = JRadioButton("Headers only (no body)")
    private val rbSizeLimit = JRadioButton("Limit body size to:")
    private val spinnerMb   = JSpinner(SpinnerNumberModel(1, 1, 500, 1))

    init {
        val cur = when (api.persistence().preferences().getString("trafficlogger.storage.mode")) {
            "HEADERS_ONLY" -> StorageMode.HEADERS_ONLY
            "SIZE_LIMITED" -> StorageMode.SIZE_LIMITED
            else           -> StorageMode.FULL
        }
        val curMb = api.persistence().preferences().getString("trafficlogger.storage.maxsizemb")
            ?.toIntOrNull() ?: 1
        spinnerMb.value = curMb

        when (cur) {
            StorageMode.FULL         -> rbFull.isSelected      = true
            StorageMode.HEADERS_ONLY -> rbHeaders.isSelected   = true
            StorageMode.SIZE_LIMITED -> rbSizeLimit.isSelected = true
        }

        spinnerMb.isEnabled = cur == StorageMode.SIZE_LIMITED
        rbFull    .addActionListener { spinnerMb.isEnabled = false }
        rbHeaders .addActionListener { spinnerMb.isEnabled = false }
        rbSizeLimit.addActionListener { spinnerMb.isEnabled = true }

        val group = ButtonGroup()
        group.add(rbFull); group.add(rbHeaders); group.add(rbSizeLimit)

        title   = "Session Traffic Logger Settings"
        isModal = true
        defaultCloseOperation = JDialog.DISPOSE_ON_CLOSE
        layout  = BorderLayout(10, 10)

        val content = JPanel()
        content.layout = BoxLayout(content, BoxLayout.Y_AXIS)
        content.border = BorderFactory.createEmptyBorder(10, 10, 10, 10)

        val dirPanel = JPanel(BorderLayout(6, 0))
        dirPanel.border = BorderFactory.createTitledBorder("Log Directory")
        val browseBtn = JButton("Browse...")
        browseBtn.addActionListener {
            val savedPath = dirField.text.trim()
            val chooser = if (savedPath.isNotBlank()) JFileChooser(File(savedPath)) else JFileChooser()
            chooser.dialogTitle       = "Select Log Directory"
            chooser.fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
                dirField.text = chooser.selectedFile.absolutePath
        }
        dirPanel.add(dirField,  BorderLayout.CENTER)
        dirPanel.add(browseBtn, BorderLayout.EAST)
        content.add(dirPanel)
        content.add(Box.createVerticalStrut(10))

        val storagePanel = JPanel()
        storagePanel.layout = BoxLayout(storagePanel, BoxLayout.Y_AXIS)
        storagePanel.border = BorderFactory.createTitledBorder("Storage")

        rbFull.alignmentX    = Component.LEFT_ALIGNMENT
        rbHeaders.alignmentX = Component.LEFT_ALIGNMENT

        val sizePanel = Box.createHorizontalBox()
        sizePanel.add(rbSizeLimit)
        sizePanel.add(Box.createHorizontalStrut(5))
        spinnerMb.preferredSize = Dimension(60, 24)
        sizePanel.add(spinnerMb)
        sizePanel.add(Box.createHorizontalStrut(5))
        sizePanel.add(JLabel("MB per request/response"))
        sizePanel.alignmentX = Component.LEFT_ALIGNMENT

        storagePanel.add(rbFull)
        storagePanel.add(Box.createVerticalStrut(4))
        storagePanel.add(rbHeaders)
        storagePanel.add(Box.createVerticalStrut(4))
        storagePanel.add(sizePanel)

        content.add(storagePanel)
        content.add(Box.createVerticalStrut(10))

        val notice = JTextArea(
            "⚠  This extension stores full HTTP traffic including sensitive data\n" +
            "such as cookies, tokens and credentials. Secure your log directory.")
        notice.isEditable    = false
        notice.lineWrap      = true
        notice.wrapStyleWord = true
        notice.background    = Color(0xFF, 0xF0, 0xC0)
        notice.border        = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(0xCC, 0xAA, 0x00)),
            BorderFactory.createEmptyBorder(6, 6, 6, 6))
        content.add(notice)

        dirPanel.alignmentX     = Component.LEFT_ALIGNMENT
        storagePanel.alignmentX = Component.LEFT_ALIGNMENT
        notice.alignmentX       = Component.LEFT_ALIGNMENT

        dirPanel.maximumSize     = Dimension(Int.MAX_VALUE, dirPanel.preferredSize.height)
        storagePanel.maximumSize = Dimension(Int.MAX_VALUE, storagePanel.preferredSize.height)
        notice.maximumSize       = Dimension(Int.MAX_VALUE, notice.preferredSize.height)
        add(content, BorderLayout.CENTER)

        val btnRow  = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 6))
        val cancel  = JButton("Cancel")
        val save    = JButton("Save")
        save.background     = Color(0xE8, 0x5C, 0x1E)
        save.foreground     = Color.WHITE
        save.isFocusPainted = false

        cancel.addActionListener { dispose() }
        save  .addActionListener { saveAndClose() }

        btnRow.add(cancel); btnRow.add(save)
        add(btnRow, BorderLayout.SOUTH)
        pack()
        setLocationRelativeTo(parent)
    }

    private fun saveAndClose() {
        val newPath = dirField.text.trim()
        val oldPath = api.persistence().preferences().getString("trafficlogger.dbpath") ?: ""
        if (newPath.isNotBlank() && newPath != oldPath) {
            try {
                val newDbPath = db.moveToDirectory(newPath)
                api.persistence().preferences().setString("trafficlogger.dbpath", newPath)
                api.logging().logToOutput("Session Traffic Logger: Moved to $newDbPath")
            } catch (e: Exception) {
                JOptionPane.showMessageDialog(this, "Failed to move database:\n${e.message}",
                    "Error", JOptionPane.ERROR_MESSAGE)
                return
            }
        }

        val mode = when {
            rbHeaders  .isSelected -> StorageMode.HEADERS_ONLY
            rbSizeLimit.isSelected -> StorageMode.SIZE_LIMITED
            else                   -> StorageMode.FULL
        }
        val maxMb = spinnerMb.value as Int

        api.persistence().preferences().setString("trafficlogger.storage.mode",      mode.name)
        api.persistence().preferences().setString("trafficlogger.storage.maxsizemb", maxMb.toString())

        onSettingsChanged?.invoke(StorageSettings(mode, maxMb))

        if (newPath.isNotBlank() && newPath != oldPath) {
            JOptionPane.showMessageDialog(this,
                "Database successfully moved to:\n${db.dbFile}",
                "Directory changed", JOptionPane.INFORMATION_MESSAGE)
        }

        dispose()
    }
}

// ─────────────────────────────────────────────────────────────
// Log Panel – one per tab
// ─────────────────────────────────────────────────────────────

class LogPanel(private val api: MontoyaApi) {

    val panel   = JPanel(BorderLayout(0, 2))
    val entries = mutableListOf<LogEntry>()
    val visibleEntries = mutableListOf<LogEntry>()
    var filter  = FilterSettings()
    var onCountChanged: ((Int) -> Unit)? = null

    private val reqEditor  = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
    private val respEditor = api.userInterface().createHttpResponseEditor()

    companion object {
        const val COL_NUM     = 0
        const val COL_HOST    = 1
        const val COL_METHOD  = 2
        const val COL_URL     = 3
        const val COL_PARAMS  = 4
        const val COL_STATUS  = 5
        const val COL_LENGTH  = 6
        const val COL_MIME    = 7
        const val COL_EXT     = 8
        const val COL_TLS     = 9
        const val COL_COOKIES = 10
        const val COL_TIME    = 11
        const val COL_TOOL    = 12

        val COLS = arrayOf(
            "#", "Host", "Method", "URL", "Params",
            "Status", "Length", "MIME type", "Extension",
            "TLS", "Cookies", "Time", "Tool"
        )
    }

    val model = object : DefaultTableModel(COLS, 0) {
        override fun isCellEditable(row: Int, column: Int) = false
    }
    val table  = JTable(model)
    val sorter = TableRowSorter(model)

    init { buildUI() }

    private fun buildUI() {
        table.autoResizeMode              = JTable.AUTO_RESIZE_OFF
        table.rowHeight                   = 18
        table.rowSorter                   = sorter
        sorter.setComparator(COL_NUM, Comparator<Any> { a, b ->
            (a as Int).compareTo(b as Int)
        })
        sorter.setComparator(COL_STATUS, Comparator<Any> { a, b ->
            (a as Int).compareTo(b as Int)
        })
        sorter.setComparator(COL_LENGTH, Comparator<Any> { a, b ->
            (a as Int).compareTo(b as Int)
        })
        table.tableHeader.reorderingAllowed = true

        val cm = table.columnModel
        cm.getColumn(COL_NUM)    .preferredWidth = 50
        cm.getColumn(COL_HOST)   .preferredWidth = 180
        cm.getColumn(COL_METHOD) .preferredWidth = 70
        cm.getColumn(COL_URL)    .preferredWidth = 600
        cm.getColumn(COL_PARAMS) .preferredWidth = 60
        cm.getColumn(COL_STATUS) .preferredWidth = 60
        cm.getColumn(COL_LENGTH) .preferredWidth = 80
        cm.getColumn(COL_MIME)   .preferredWidth = 100
        cm.getColumn(COL_EXT)    .preferredWidth = 80
        cm.getColumn(COL_TLS)    .preferredWidth = 50
        cm.getColumn(COL_COOKIES).preferredWidth = 70
        cm.getColumn(COL_TIME)   .preferredWidth = 160
        cm.getColumn(COL_TOOL)   .preferredWidth = 100

        cm.getColumn(COL_STATUS).cellRenderer = object : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(
            table: JTable, value: Any?, isSelected: Boolean,
            hasFocus: Boolean, row: Int, column: Int
        ): Component {
            val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
            if (!isSelected) {
                foreground = when ((value as? Int ?: 0) / 100) {
                    2    -> Color(0, 150, 0)
                    3    -> Color(200, 120, 0)
                    4, 5 -> Color(200, 0, 0)
                    else -> foreground
                }
            }
            return c
            }
        }
        table.selectionModel.addListSelectionListener {
            if (!it.valueIsAdjusting) onRowSelect()
        }

        val popup        = JPopupMenu()
        val sendRepeater = JMenuItem("Send to Repeater")
        val sendIntruder = JMenuItem("Send to Intruder")
        popup.add(sendRepeater)
        popup.add(sendIntruder)

        sendRepeater.addActionListener { sendSelected { req -> api.repeater().sendToRepeater(req) } }
        sendIntruder.addActionListener { sendSelected { req -> api.intruder().sendToIntruder(req) } }

        table.addMouseListener(object : MouseAdapter() {
            override fun mousePressed(e: MouseEvent) {
                if (e.isPopupTrigger) { selectRowAt(e); popup.show(table, e.x, e.y) }
            }
            override fun mouseReleased(e: MouseEvent) {
                if (e.isPopupTrigger) { selectRowAt(e); popup.show(table, e.x, e.y) }
            }
        })

        val tableScroll = JScrollPane(table)
        tableScroll.preferredSize = Dimension(900, 280)

        val rrSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            reqEditor.uiComponent(), respEditor.uiComponent())
        rrSplit.resizeWeight       = 0.5
        rrSplit.isContinuousLayout = true

        val mainSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, rrSplit)
        mainSplit.resizeWeight       = 0.45
        mainSplit.isContinuousLayout = true

        panel.add(mainSplit, BorderLayout.CENTER)
    }

    private fun selectRowAt(e: MouseEvent) {
        val row = table.rowAtPoint(e.point)
        if (row >= 0) table.setRowSelectionInterval(row, row)
    }

    private fun sendSelected(action: (MontoyaHttpRequest) -> Unit) {
        val view = table.selectedRow.takeIf { it >= 0 } ?: return
        val row  = table.convertRowIndexToModel(view)
        if (row >= entries.size) return
        val entry = visibleEntries[row]
        try {
            val service = HttpService.httpService(
                entry.host,
                if (entry.port > 0) entry.port else if (entry.tls) 443 else 80,
                entry.tls
            )
            action(MontoyaHttpRequest.httpRequest(service, entry.request))
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(panel, "Failed to send request:\n${e.message}",
                "Error", JOptionPane.ERROR_MESSAGE)
        }
    }

    // Check single entry against current filter – avoids full table rebuild on each add
    private fun matchesFilter(entry: LogEntry): Boolean {
        val f = filter
        if (f.inScopeOnly && !entry.inScope) return false
        if (!f.showRepeater && entry.tool == "Repeater") return false
        if (!f.showScanner  && entry.tool == "Scanner")  return false
        if (!f.showIntruder && entry.tool == "Intruder") return false
        if (!f.showTarget   && entry.tool == "Target")   return false
        if (!f.showExtender && entry.tool == "Extender") return false
        val statusPrefix = entry.status.toString().firstOrNull()?.toString() ?: ""
        if (statusPrefix == "2" && !f.show2xx) return false
        if (statusPrefix == "3" && !f.show3xx) return false
        if (statusPrefix == "4" && !f.show4xx) return false
        if (statusPrefix == "5" && !f.show5xx) return false
        if (!f.showHtml        && entry.mimeType == "HTML")         return false
        if (!f.showScript      && entry.mimeType == "Script")       return false
        if (!f.showXml         && entry.mimeType == "XML")          return false
        if (!f.showJson        && entry.mimeType == "JSON")         return false
        if (!f.showImage       && entry.mimeType == "Image")        return false
        if (!f.showCss         && entry.mimeType == "CSS")          return false
        if (!f.showOtherText   && entry.mimeType == "Other text")   return false
        if (!f.showOtherBinary && entry.mimeType == "Other binary") return false
        if (f.extHideEnabled && f.extHide.isNotEmpty()) {
            val exts = f.extHide.split(",").map { it.trim().lowercase() }
            if (entry.extension.lowercase() in exts) return false
        }
        if (f.extShowOnlyEnabled && f.extShowOnly.isNotEmpty()) {
            val exts = f.extShowOnly.split(",").map { it.trim().lowercase() }
            if (entry.extension.lowercase() !in exts) return false
        }
        if (f.searchTerm.isNotEmpty()) {
            val haystack = "${entry.host} ${entry.url} ${entry.method} ${entry.status} ${entry.tool}"
            val matches = if (f.searchRegex) {
                try {
                    Regex(f.searchTerm, if (f.searchCaseSens) setOf() else setOf(RegexOption.IGNORE_CASE))
                        .containsMatchIn(haystack)
                } catch (_: Exception) { false }
            } else {
                haystack.contains(f.searchTerm, ignoreCase = !f.searchCaseSens)
            }
            if (f.searchNegative && matches)   return false
            if (!f.searchNegative && !matches) return false
        }
        return true
    }

    fun addEntry(entry: LogEntry) {
        entries.add(entry)
        if (matchesFilter(entry)) {
            visibleEntries.add(entry)
            model.addRow(entry.toRow(visibleEntries.size))
        }
        onCountChanged?.invoke(model.rowCount)
    }

    fun loadEntries(list: List<LogEntry>) {
        entries.clear()
        visibleEntries.clear()
        entries.addAll(list)
        model.setRowCount(0)
        list.forEach { e ->
            if (matchesFilter(e)) {
                visibleEntries.add(e)
                model.addRow(e.toRow(visibleEntries.size))
            }
        }
        onCountChanged?.invoke(model.rowCount)
    }

    fun clear() {
        entries.clear()
        visibleEntries.clear()
        model.setRowCount(0)
        onCountChanged?.invoke(0)
    }

    fun exportCsv(savedPath: String?, parent: Component) {
        val chooser = if (!savedPath.isNullOrBlank()) JFileChooser(File(savedPath)) else JFileChooser()
        chooser.dialogTitle  = "Export to CSV"
        chooser.selectedFile = File("traffic_export.csv")
        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return
        try {
            chooser.selectedFile.bufferedWriter().use { w ->
                w.write("\"#\",\"Host\",\"Method\",\"URL\",\"Params\",\"Status\",\"Length\"," +
                        "\"MIME type\",\"Extension\",\"TLS\",\"Cookies\",\"Time\",\"Tool\"\n")
                visibleEntries.forEachIndexed { i, e ->
                    fun q(s: String) = "\"${s.replace("\"", "\"\"")}\""
                    w.write("${i+1},${q(e.host)},${q(e.method)},${q(e.url)},${e.hasParams}," +
                            "${e.status},${e.length},${q(e.mimeType)},${q(e.extension)}," +
                            "${e.tls},${e.hasCookies},${q(e.time)},${q(e.tool)}\n")
                }
            }
            JOptionPane.showMessageDialog(parent,
                "Exported ${visibleEntries.size} entries to:\n${chooser.selectedFile.absolutePath}",
                "Export successful", JOptionPane.INFORMATION_MESSAGE)
        } catch (e: Exception) {
            JOptionPane.showMessageDialog(parent, "Export failed:\n${e.message}",
                "Error", JOptionPane.ERROR_MESSAGE)
        }
    }

    private fun onRowSelect() {
        val view = table.selectedRow.takeIf { it >= 0 } ?: return
        val row  = table.convertRowIndexToModel(view)
        if (row >= entries.size) return
        val entry = visibleEntries[row] 
        try {
            val service = HttpService.httpService(
                entry.host,
                if (entry.port > 0) entry.port else if (entry.tls) 443 else 80,
                entry.tls
            )
            reqEditor.setRequest(MontoyaHttpRequest.httpRequest(service, entry.request))
            respEditor.setResponse(MontoyaHttpResponse.httpResponse(entry.response))
        } catch (e: Exception) {
            api.logging().logToError("Session Traffic Logger display error: ${e.message}")
        }
    }

    // Rebuilds table from entries – called only when filter changes
    fun applyFilter() {
        visibleEntries.clear()
        model.setRowCount(0)
        entries.forEach { e ->
            if (matchesFilter(e)) {
                visibleEntries.add(e)
                model.addRow(e.toRow(visibleEntries.size))
            }
        }
        onCountChanged?.invoke(model.rowCount)
    }

    private fun LogEntry.toRow(idx: Int) = arrayOf(
        idx, host, method, url,
        if (hasParams)  "✓" else "",
        status, length, mimeType, extension,
        if (tls)        "✓" else "",
        if (hasCookies) "✓" else "",
        time, tool
    )
}

// ─────────────────────────────────────────────────────────────
// Closeable Tab Header
// ─────────────────────────────────────────────────────────────

class CloseableTab(initialTitle: String, onClose: () -> Unit) : JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)) {

    private val lbl = JLabel(initialTitle).apply {
        border = BorderFactory.createEmptyBorder(0, 0, 0, 6)
    }

    init {
        isOpaque = false
        add(lbl)
        add(JButton("✕").apply {
            preferredSize       = Dimension(16, 16)
            isFocusPainted      = false
            isBorderPainted     = false
            isContentAreaFilled = false
            font                = font.deriveFont(9f)
            toolTipText         = "Close tab"
            addActionListener { onClose() }
        })
    }

    fun updateTitle(newTitle: String) {
        lbl.text = newTitle
        revalidate(); repaint()
    }
}

// ─────────────────────────────────────────────────────────────
// Main UI
// ─────────────────────────────────────────────────────────────

class TrafficLoggerUI(
    private val api:     MontoyaApi,
    private val db:      DatabaseManager,
    private val handler: TrafficHttpHandler
) {
    val panel = JPanel(BorderLayout(0, 2))

    private val livePanel  = LogPanel(api)
    private val tabs       = JTabbedPane()

    data class LoadedTab(val logPanel: LogPanel, val tabComponent: CloseableTab, val baseTitle: String)
    private val loadedTabs   = mutableMapOf<Component, LoadedTab>()
    private var globalFilter = FilterSettings()

    init {
        buildUI()
        livePanel.filter = globalFilter
        livePanel.onCountChanged = { count -> tabs.setTitleAt(0, "● Live ($count)") }
        db.onEntryInserted = { entry -> livePanel.addEntry(entry) }
    }

    private fun buildUI() {
        val toolbar     = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        val filterBtn   = JButton("Filter...")
        val clearBtn    = JButton("Clear Live")
        val loadBtn     = JButton("⊙ Load old DB...")
        val exportBtn   = JButton("Export CSV")
        val settingsBtn = JButton("⚙ Settings")
        val helpBtn     = JButton("Help")

        filterBtn  .addActionListener { openFilterDialog() }
        clearBtn   .addActionListener { livePanel.clear() }
        loadBtn    .addActionListener { loadOldDb() }
        exportBtn  .addActionListener {
            getCurrentLogPanel().exportCsv(
                api.persistence().preferences().getString("trafficlogger.dbpath"), panel)
        }
        settingsBtn.addActionListener { openSettings() }
        helpBtn    .addActionListener { showHelp() }

        listOf(filterBtn, clearBtn, loadBtn, exportBtn, settingsBtn, helpBtn)
            .forEach { toolbar.add(it) }
        panel.add(toolbar, BorderLayout.NORTH)

        tabs.addTab("● Live (0)", livePanel.panel)
        tabs.setForegroundAt(0, Color(0x00, 0xAA, 0x00))
        panel.add(tabs, BorderLayout.CENTER)
    }

    private fun getCurrentLogPanel(): LogPanel {
        val selectedComp = tabs.getComponentAt(tabs.selectedIndex)
        return if (selectedComp == livePanel.panel) livePanel
        else loadedTabs[selectedComp]?.logPanel ?: livePanel
    }

    private fun openSettings() {
        val owner = SwingUtilities.getWindowAncestor(panel) ?: JFrame()
        val dlg = SettingsDialog(owner, api, db)
        dlg.onSettingsChanged = { newSettings ->
            handler.storageSettings = newSettings
            api.logging().logToOutput("Session Traffic Logger: Storage mode changed to ${newSettings.mode}")
        }
        dlg.isVisible = true  // blockiert bis Dialog geschlossen
    }

    private fun openFilterDialog() {
        val owner = SwingUtilities.getWindowAncestor(panel) ?: JFrame()
        val dlg = FilterDialog(owner, globalFilter)
        dlg.isVisible = true  // blockiert bis Dialog geschlossen
        dlg.result?.let { newFilter ->
            globalFilter     = newFilter
            livePanel.filter = newFilter
            livePanel.applyFilter()
            loadedTabs.values.forEach { it.logPanel.filter = newFilter; it.logPanel.applyFilter() }
        }
    }

    private fun loadOldDb() {
        val savedPath = api.persistence().preferences().getString("trafficlogger.dbpath")
        val chooser   = if (!savedPath.isNullOrBlank()) JFileChooser(File(savedPath)) else JFileChooser()
        chooser.dialogTitle       = "Load old Traffic DB"
        chooser.fileSelectionMode = JFileChooser.FILES_ONLY
        if (chooser.showOpenDialog(panel) != JFileChooser.APPROVE_OPTION) return

        val file     = chooser.selectedFile
        val logPanel = LogPanel(api)
        logPanel.filter = globalFilter
        logPanel.loadEntries(db.loadFromFile(file.absolutePath))

        val baseTitle = file.nameWithoutExtension.take(25)
        val tabTitle  = "$baseTitle (${logPanel.entries.size})"
        val tabIdx    = tabs.tabCount

        tabs.addTab(tabTitle, logPanel.panel)

        val tabComp = CloseableTab(tabTitle) {
            val idx = tabs.indexOfComponent(logPanel.panel)
            if (idx >= 0) {
                tabs.removeTabAt(idx)
                loadedTabs.remove(logPanel.panel)
            }
        }

        loadedTabs[logPanel.panel] = LoadedTab(logPanel, tabComp, baseTitle)
        tabs.setTabComponentAt(tabIdx, tabComp)

        logPanel.onCountChanged = { count ->
            val lt = loadedTabs[logPanel.panel]
            if (lt != null) lt.tabComponent.updateTitle("${lt.baseTitle} ($count)")
        }

        tabs.selectedIndex = tabIdx
    }

    private fun showHelp() {
        val help = """
            Session Traffic Logger

            Logs HTTP traffic from all Burp tools except Proxy into a local SQLite database.

            Note:
            Proxy traffic is NOT logged.
            Use Burp's built-in Proxy tab to inspect Proxy requests.

            Key features:
            • Live logging with filtering
            • Save and reload previous sessions
            • Export to CSV
            • Configurable storage (full, headers only, size-limited)

            Important:
            This extension may store sensitive data such as cookies, tokens, and credentials.
            Ensure your log directory is secured and do not share database files without review.

            Tips:
            • Use filters to reduce noise
            • Use "Headers only" for large scans
            • Use size limits to avoid large database files

            Right-click any entry:
            • Send to Repeater
            • Send to Intruder

            Known issues:
            • Render tab not supported in read-only editors
            • First Repeater send may not appear in log
        """.trimIndent()

        JOptionPane.showMessageDialog(panel, help, "Session Traffic Logger – Help",
            JOptionPane.INFORMATION_MESSAGE)
    }
}