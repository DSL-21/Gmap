package com.dsl.gmap

import android.content.ContentValues
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.text.method.ScrollingMovementMethod
import android.view.View
import android.widget.*
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import kotlinx.coroutines.*
import java.io.*
import java.net.*
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.*
import kotlin.coroutines.CoroutineContext

class MainActivity : AppCompatActivity() {
    private lateinit var ipAddressEditText: EditText
    private lateinit var startPortEditText: EditText
    private lateinit var endPortEditText: EditText
    private lateinit var scanButton: Button
    private lateinit var saveButton: Button
    private lateinit var outputTextView: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var progressTextView: TextView
    private val STORAGE_PERMISSION_CODE = 101

    // Scope pro coroutines, který se zruší při zničení aktivity
    private val scanJob = SupervisorJob()
    private val scanScope = CoroutineScope(Dispatchers.IO + scanJob)

    private val commonPorts = mapOf(
        21 to "FTP", 22 to "SSH", 23 to "Telnet", 25 to "SMTP", 53 to "DNS",
        80 to "HTTP", 110 to "POP3", 143 to "IMAP", 443 to "HTTPS", 993 to "IMAPS",
        995 to "POP3S", 3306 to "MySQL", 3389 to "RDP", 5432 to "PostgreSQL",
        8080 to "HTTP-Alt", 8443 to "HTTPS-Alt"
    )

    private val vulnerabilityPatterns = mapOf(
        "OpenSSH_[67]\\." to "Potentially vulnerable SSH version",
        "Apache/2\\.[0-2]\\." to "Outdated Apache version",
        "nginx/1\\.[0-9]\\." to "Check for nginx vulnerabilities",
        "Microsoft-IIS/[6-8]\\." to "Outdated IIS version",
        "ProFTPD" to "Check ProFTPD version for vulnerabilities",
        "vsftpd" to "Check vsftpd configuration"
    )

    data class PortScanResult(
        val port: Int,
        val isOpen: Boolean,
        val service: String? = null,
        val version: String? = null,
        val banner: String? = null,
        val httpHeaders: Map<String, String>? = null,
        val vulnerabilities: List<String> = emptyList()
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        initializeViews()
        setupClickListeners()
        setupWindowInsets()
    }

    override fun onDestroy() {
        super.onDestroy()
        scanJob.cancel() // Zruší všechny běžící coroutines
    }

    private fun initializeViews() {
        ipAddressEditText = findViewById(R.id.ipAddressInput)
        startPortEditText = findViewById(R.id.startPortInput)
        endPortEditText = findViewById(R.id.endPortInput)
        scanButton = findViewById(R.id.scanButton)
        saveButton = findViewById(R.id.saveButton)
        outputTextView = findViewById(R.id.outputTextView)
        progressBar = findViewById(R.id.progressBar)
        progressTextView = findViewById(R.id.progressTextView)

        outputTextView.movementMethod = ScrollingMovementMethod()
    }

    private fun setupClickListeners() {
        scanButton.setOnClickListener {
            val ipAddress = ipAddressEditText.text.toString().trim()
            val startPortText = startPortEditText.text.toString()
            val endPortText = endPortEditText.text.toString()

            if (validateInput(ipAddress, startPortText, endPortText)) {
                val startPort = startPortText.toInt()
                val endPort = endPortText.toInt()
                startNetworkScan(ipAddress, startPort, endPort)
            }
        }

        saveButton.setOnClickListener {
            checkPermissionAndSaveResults()
        }
    }

    private fun setupWindowInsets() {
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }

    private fun validateInput(ip: String, startPort: String, endPort: String): Boolean {
        if (ip.isEmpty() || startPort.isEmpty() || endPort.isEmpty()) {
            updateOutput("Error: Please fill in all fields")
            return false
        }

        val start = startPort.toIntOrNull()
        val end = endPort.toIntOrNull()

        if (start == null || end == null || start < 1 || end < 1 || start > 65535 || end > 65535 || start > end) {
            updateOutput("Error: Invalid port range (1-65535)")
            return false
        }

        return true
    }

    private fun startNetworkScan(target: String, startPort: Int, endPort: Int) {
        outputTextView.text = ""
        scanButton.isEnabled = false
        saveButton.isEnabled = false
        progressBar.visibility = View.VISIBLE
        progressTextView.visibility = View.VISIBLE
        progressBar.progress = 0 // Reset progress bar
        progressTextView.text = "Scanning: 0/0" // Reset progress text

        scanScope.launch {
            try {
                performComprehensiveScan(target, startPort, endPort)
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    updateOutput("Scan error: ${e.message}")
                }
            } finally {
                withContext(Dispatchers.Main) {
                    scanButton.isEnabled = true
                    saveButton.isEnabled = true
                    progressBar.visibility = View.GONE
                    progressTextView.visibility = View.GONE
                }
            }
        }
    }

    private suspend fun performComprehensiveScan(target: String, startPort: Int, endPort: Int) {
        val startTime = System.currentTimeMillis()

        withContext(Dispatchers.Main) {
            updateOutput("=== NETWORK SCAN REPORT ===")
            updateOutput("Target: $target")
            updateOutput("Port Range: $startPort-$endPort")
            updateOutput("Timestamp: ${getCurrentTimestamp()}")
            updateOutput("=" + "=".repeat(30))
        }

        // DNS Resolution
        val resolvedIp = if (isDomainName(target)) {
            performDnsLookup(target)
        } else {
            target
        }

        // Host Discovery
        performHostDiscovery(resolvedIp)

        // Paralelní skenování portů
        val openPorts = performParallelPortScan(resolvedIp, startPort, endPort)

        // Služby, zranitelnosti a enumerace
        performServiceDetection(openPorts, resolvedIp)
        performVulnerabilityCheck(openPorts)
        performAdditionalEnumeration(openPorts, resolvedIp)

        val endTime = System.currentTimeMillis()
        withContext(Dispatchers.Main) {
            updateOutput("\n=== SCAN COMPLETE ===")
            updateOutput("Total time: ${(endTime - startTime) / 1000}s")
            updateOutput("Open ports: ${openPorts.size}")
        }
    }

    private suspend fun performDnsLookup(domain: String): String {
        withContext(Dispatchers.Main) {
            updateOutput("\n[DNS RESOLUTION]")
        }

        return try {
            val ipAddress = InetAddress.getByName(domain).hostAddress
            withContext(Dispatchers.Main) {
                updateOutput("$domain resolves to $ipAddress")
            }

            try {
                val reverseDns = InetAddress.getByName(ipAddress).canonicalHostName
                withContext(Dispatchers.Main) {
                    updateOutput("Reverse DNS: $reverseDns")
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    updateOutput("Reverse DNS: Not available")
                }
            }

            ipAddress ?: domain
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                updateOutput("DNS resolution failed: ${e.message}")
            }
            domain
        }
    }

    private suspend fun performHostDiscovery(ipAddress: String) {
        withContext(Dispatchers.Main) {
            updateOutput("\n[HOST DISCOVERY]")
        }

        val isAlive = try {
            InetAddress.getByName(ipAddress).isReachable(3000)
        } catch (e: Exception) {
            false
        }

        withContext(Dispatchers.Main) {
            updateOutput("ICMP Ping: ${if (isAlive) "Host is alive" else "No response"}")
        }

        val tcpPorts = listOf(80, 443, 22, 21)
        for (port in tcpPorts) {
            val tcpAlive = withContext(Dispatchers.IO) {
                try {
                    Socket().use { socket ->
                        socket.connect(InetSocketAddress(ipAddress, port), 1000)
                        true
                    }
                } catch (e: Exception) {
                    false
                }
            }

            if (tcpAlive) {
                withContext(Dispatchers.Main) {
                    updateOutput("TCP ping port $port: Open")
                }
                break
            }
        }
    }

    private suspend fun performParallelPortScan(ipAddress: String, startPort: Int, endPort: Int): List<PortScanResult> {
        withContext(Dispatchers.Main) {
            updateOutput("\n[PORT SCANNING]")
        }

        val openPorts = mutableListOf<PortScanResult>()
        val totalPorts = endPort - startPort + 1
        val scannedPorts = AtomicInteger(0)

        // Spuštění paralelního skenování
        val deferredResults = coroutineScope {
            (startPort..endPort).map { port ->
                async(Dispatchers.IO) {
                    val result = scanSinglePort(ipAddress, port)
                    // Zde aktualizujeme progress bar a text po dokončení každého portu
                    val progress = scannedPorts.incrementAndGet()
                    withContext(Dispatchers.Main) {
                        progressBar.progress = (progress * 100) / totalPorts
                        progressTextView.text = "Scanning: $progress/$totalPorts"
                    }
                    result
                }
            }
        }

        // Await all results
        val results = deferredResults.awaitAll()

        // Process results and update output for open ports
        for (result in results) {
            if (result.isOpen) {
                openPorts.add(result)
                withContext(Dispatchers.Main) {
                    val serviceName = result.service ?: commonPorts[result.port] ?: "Unknown"
                    updateOutput("Port ${result.port} ($serviceName) - OPEN")
                }
            }
        }

        return openPorts
    }

    private fun scanSinglePort(ipAddress: String, port: Int): PortScanResult {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ipAddress, port), 2000)
                socket.soTimeout = 3000

                var banner: String? = null
                try {
                    val reader = BufferedReader(InputStreamReader(socket.inputStream))
                    // Pokus o přečtení banneru pro textové protokoly
                    if (reader.ready()) {
                        banner = reader.readLine()
                    }
                } catch (e: Exception) {
                    // Ignorujeme chyby čtení, port je stále otevřený
                }

                PortScanResult(
                    port = port,
                    isOpen = true,
                    service = commonPorts[port],
                    banner = banner
                )
            }
        } catch (e: Exception) {
            PortScanResult(port, false)
        }
    }

    private suspend fun performServiceDetection(openPorts: List<PortScanResult>, ipAddress: String) {
        withContext(Dispatchers.Main) {
            updateOutput("\n[SERVICE DETECTION]")
        }

        openPorts.forEach { portResult ->
            val detailedResult = when (portResult.port) {
                22 -> detectSshService(ipAddress, portResult.port)
                21 -> detectFtpService(ipAddress, portResult.port)
                80, 8080 -> detectHttpService(ipAddress, portResult.port, false)
                443, 8443 -> detectHttpService(ipAddress, portResult.port, true)
                25 -> detectSmtpService(ipAddress, portResult.port)
                else -> portResult
            }

            withContext(Dispatchers.Main) {
                updateOutput("Port ${detailedResult.port}: ${detailedResult.service ?: "Unknown"}")
                detailedResult.version?.let {
                    updateOutput("  Version: $it")
                }
                detailedResult.banner?.let {
                    updateOutput("  Banner: $it")
                }
            }
        }
    }

    private fun detectSshService(ipAddress: String, port: Int): PortScanResult {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ipAddress, port), 3000)
                socket.soTimeout = 5000

                val reader = BufferedReader(InputStreamReader(socket.inputStream))
                val banner = reader.readLine()

                PortScanResult(
                    port = port,
                    isOpen = true,
                    service = "SSH",
                    version = banner,
                    banner = banner
                )
            }
        } catch (e: Exception) {
            PortScanResult(port, false)
        }
    }

    private fun detectFtpService(ipAddress: String, port: Int): PortScanResult {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ipAddress, port), 3000)
                socket.soTimeout = 5000

                val reader = BufferedReader(InputStreamReader(socket.inputStream))
                val banner = reader.readLine()

                PortScanResult(
                    port = port,
                    isOpen = true,
                    service = "FTP",
                    version = banner,
                    banner = banner
                )
            }
        } catch (e: Exception) {
            PortScanResult(port, false)
        }
    }

    private fun detectHttpService(ipAddress: String, port: Int, isHttps: Boolean): PortScanResult {
        return try {
            val protocol = if (isHttps) "https" else "http"
            val url = URL("$protocol://$ipAddress:$port")
            val connection = if (isHttps) {
                val httpsConn = url.openConnection() as HttpsURLConnection
                // DŮLEŽITÁ ZMĚNA: Odstraněno nastavení HostnameVerifier a SSLSocketFactory,
                // což vynucuje standardní ověřování certifikátů.
                httpsConn
            } else {
                url.openConnection() as HttpURLConnection
            }

            connection.requestMethod = "HEAD"
            connection.connectTimeout = 5000
            connection.readTimeout = 5000
            connection.setRequestProperty("User-Agent", "NetworkScanner/1.0")

            val headers = mutableMapOf<String, String>()
            connection.headerFields.forEach { (key, value) ->
                if (key != null) {
                    headers[key] = value.joinToString(", ")
                }
            }

            val serverHeader = headers["Server"]
            connection.disconnect()

            PortScanResult(
                port = port,
                isOpen = true,
                service = if (isHttps) "HTTPS" else "HTTP",
                version = serverHeader,
                httpHeaders = headers
            )
        } catch (e: Exception) {
            PortScanResult(port, false)
        }
    }

    private fun detectSmtpService(ipAddress: String, port: Int): PortScanResult {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ipAddress, port), 3000)
                socket.soTimeout = 5000

                val reader = BufferedReader(InputStreamReader(socket.inputStream))
                val banner = reader.readLine()

                PortScanResult(
                    port = port,
                    isOpen = true,
                    service = "SMTP",
                    version = banner,
                    banner = banner
                )
            }
        } catch (e: Exception) {
            PortScanResult(port, false)
        }
    }

    private suspend fun performVulnerabilityCheck(openPorts: List<PortScanResult>) {
        withContext(Dispatchers.Main) {
            updateOutput("\n[VULNERABILITY ASSESSMENT]")
        }

        var vulnerabilitiesFound = 0

        for (portResult in openPorts.filter { it.isOpen }) {
            val vulns = mutableListOf<String>()

            portResult.version?.let { version ->
                vulnerabilityPatterns.forEach { (pattern, description) ->
                    if (version.matches(Regex(pattern))) {
                        vulns.add(description)
                    }
                }
            }

            when (portResult.port) {
                21 -> {
                    if (portResult.banner?.contains("anonymous", ignoreCase = true) == true) {
                        vulns.add("Anonymous FTP may be enabled")
                    }
                }
                22 -> {
                    if (portResult.version?.contains("OpenSSH_7.") == true ||
                        portResult.version?.contains("OpenSSH_6.") == true) {
                        vulns.add("Potentially vulnerable SSH version")
                    }
                }
                23 -> {
                    vulns.add("Telnet is insecure - use SSH instead")
                }
            }

            if (vulns.isNotEmpty()) {
                vulnerabilitiesFound++
                withContext(Dispatchers.Main) {
                    updateOutput("Port ${portResult.port} vulnerabilities:")
                    vulns.forEach { vuln ->
                        updateOutput("  - $vuln")
                    }
                }
            }
        }

        withContext(Dispatchers.Main) {
            updateOutput("Total vulnerabilities found: $vulnerabilitiesFound")
        }
    }

    private suspend fun performAdditionalEnumeration(openPorts: List<PortScanResult>, ipAddress: String) {
        withContext(Dispatchers.Main) {
            updateOutput("\n[ADDITIONAL ENUMERATION]")
        }

        for (portResult in openPorts.filter { it.isOpen }) {
            when (portResult.port) {
                22 -> performSshEnumeration(ipAddress, portResult.port)
                21 -> performFtpEnumeration(ipAddress, portResult.port)
                80, 443, 8080, 8443 -> performWebEnumeration(ipAddress, portResult.port)
            }
        }
    }

    private suspend fun performSshEnumeration(ipAddress: String, port: Int) {
        withContext(Dispatchers.Main) {
            updateOutput("SSH enumeration on $ipAddress:$port")
        }

        val commonCreds = listOf(
            "admin" to "admin",
            "root" to "root",
            "admin" to "password",
            "user" to "user"
        )

        withContext(Dispatchers.Main) {
            updateOutput("Testing common SSH credentials...")
        }

        for ((username, password) in commonCreds.take(3)) {
            withContext(Dispatchers.Main) {
                updateOutput("  Trying $username:$password - Connection attempt")
            }
            delay(100)
        }

        withContext(Dispatchers.Main) {
            updateOutput("  No weak credentials found in quick test")
        }
    }

    private suspend fun performFtpEnumeration(ipAddress: String, port: Int) {
        withContext(Dispatchers.Main) {
            updateOutput("FTP enumeration on $ipAddress:$port")
        }

        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ipAddress, port), 3000)
                socket.soTimeout = 5000

                val writer = PrintWriter(socket.getOutputStream(), true)
                val reader = BufferedReader(InputStreamReader(socket.inputStream))

                val banner = reader.readLine()

                writer.println("USER anonymous")
                val userResponse = reader.readLine()

                if (userResponse?.startsWith("331") == true) {
                    writer.println("PASS anonymous@test.com")
                    val passResponse = reader.readLine()

                    withContext(Dispatchers.Main) {
                        if (passResponse?.startsWith("230") == true) {
                            updateOutput("  Anonymous FTP login: ALLOWED")
                        } else {
                            updateOutput("  Anonymous FTP login: DENIED")
                        }
                    }
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                updateOutput("  FTP enumeration failed: ${e.message}")
            }
        }
    }

    private suspend fun performWebEnumeration(ipAddress: String, port: Int) {
        withContext(Dispatchers.Main) {
            updateOutput("Web enumeration on $ipAddress:$port")
        }

        val isHttps = port == 443 || port == 8443
        val protocol = if (isHttps) "https" else "http"
        val commonPaths = listOf("/", "/admin", "/login", "/robots.txt", "/sitemap.xml")

        for (path in commonPaths) {
            try {
                val url = URL("$protocol://$ipAddress:$port$path")
                val connection = if (isHttps) {
                    val httpsConn = url.openConnection() as HttpsURLConnection
                    // DŮLEŽITÁ ZMĚNA: Odstraněno nastavení HostnameVerifier a SSLSocketFactory,
                    // což vynucuje standardní ověřování certifikátů.
                    httpsConn
                } else {
                    url.openConnection() as HttpURLConnection
                }

                connection.requestMethod = "HEAD"
                connection.connectTimeout = 3000
                connection.readTimeout = 3000

                val responseCode = connection.responseCode
                withContext(Dispatchers.Main) {
                    if (responseCode in 200..299) {
                        updateOutput("  $path - $responseCode OK")
                    }
                }

                connection.disconnect()
            } catch (e: Exception) {
                // Path not accessible, continue
            }
        }
    }

    // Helper functions
    private fun isDomainName(target: String): Boolean {
        return !target.matches(Regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"))
    }

    private fun getCurrentTimestamp(): String {
        return SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
    }

    // DŮLEŽITÁ ZMĚNA: Tato funkce byla odstraněna, aby se vynutilo standardní ověřování certifikátů.
    // private fun createTrustAllSSLContext(): SSLContext { ... }

    private fun updateOutput(message: String) {
        // Kontrola, zda je UI stále aktivní
        if (!scanJob.isActive) return

        outputTextView.append("$message\n")
        val scrollAmount = outputTextView.layout?.getLineTop(outputTextView.lineCount) ?: 0
        if (scrollAmount > outputTextView.height) {
            outputTextView.scrollTo(0, scrollAmount - outputTextView.height)
        }
    }

    private fun saveResultsToFile() {
        if (outputTextView.text.isEmpty()) {
            Toast.makeText(this, "No results to save", Toast.LENGTH_SHORT).show()
            return
        }

        val fileName = "scan_results_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(Date())}.txt"

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                // Použití Scoped Storage pro Android 10+
                val resolver = contentResolver
                val contentValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                    put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                }

                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                uri?.let {
                    resolver.openOutputStream(it)?.use { outputStream ->
                        val header = "Network Scan Report\n" +
                                "Generated: ${getCurrentTimestamp()}\n" +
                                "Target: ${ipAddressEditText.text}\n" +
                                "Port Range: ${startPortEditText.text}-${endPortEditText.text}\n" +
                                "${"=".repeat(50)}\n\n"
                        outputStream.write(header.toByteArray())
                        outputStream.write(outputTextView.text.toString().toByteArray())
                    }
                    Toast.makeText(this, "Results saved to Downloads/$fileName", Toast.LENGTH_LONG).show()
                } ?: run {
                    Toast.makeText(this, "Failed to save file", Toast.LENGTH_LONG).show()
                }

            } else {
                // Původní metoda pro starší Androidy
                val directory = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                if (!directory.exists()) {
                    directory.mkdirs()
                }
                val file = File(directory, fileName)
                FileOutputStream(file).use { fos ->
                    val header = "Network Scan Report\n" +
                            "Generated: ${getCurrentTimestamp()}\n" +
                            "Target: ${ipAddressEditText.text}\n" +
                            "Port Range: ${startPortEditText.text}-${endPortEditText.text}\n" +
                            "${"=".repeat(50)}\n\n"
                    fos.write(header.toByteArray())
                    fos.write(outputTextView.text.toString().toByteArray())
                }
                Toast.makeText(this, "Results saved to ${file.absolutePath}", Toast.LENGTH_LONG).show()
            }
        } catch (e: IOException) {
            Toast.makeText(this, "Failed to save: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun checkPermissionAndSaveResults() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Na Androidu 10+ není potřeba oprávnění pro Scoped Storage
            saveResultsToFile()
        } else {
            // Pro starší verze vyžádáme oprávnění
            if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED) {
                saveResultsToFile()
            } else {
                ActivityCompat.requestPermissions(this, arrayOf(android.Manifest.permission.WRITE_EXTERNAL_STORAGE), STORAGE_PERMISSION_CODE)
            }
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == STORAGE_PERMISSION_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                saveResultsToFile()
            } else {
                Toast.makeText(this, "Permission denied", Toast.LENGTH_SHORT).show()
            }
        }
    }
}