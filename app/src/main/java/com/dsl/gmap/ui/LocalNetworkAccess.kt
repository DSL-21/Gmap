package com.dsl.gmap.ui

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import java.net.Inet6Address
import java.net.InetAddress

object LocalNetworkAccess {
    const val PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"

    fun isPermissionRequired(): Boolean = Build.VERSION.SDK_INT >= 37

    fun isGranted(context: Context): Boolean =
        !isPermissionRequired() ||
            ContextCompat.checkSelfPermission(context, PERMISSION) == PackageManager.PERMISSION_GRANTED

    fun targetRequiresPermission(target: String): Boolean {
        val raw = target.trim()
        if (raw.isEmpty()) return false

        // Accept both bare hostnames/IPs and complete HTTP(S) URLs.
        val candidate = if (raw.contains("://")) raw else "https://$raw"
        val parsedHost = runCatching { java.net.URI(candidate).host }.getOrNull()
        val fallbackHost = raw.substringBefore('/').let { part ->
            if (part.startsWith("[")) part.substringAfter('[').substringBefore(']')
            else if (part.count { it == ':' } == 1) part.substringBefore(':')
            else part
        }
        val value = (parsedHost ?: fallbackHost)
            .removePrefix("[").removeSuffix("]").substringBefore('%')
        if (value.equals("localhost", ignoreCase = true) ||
            value.endsWith(".local", ignoreCase = true) ||
            value.endsWith(".lan", ignoreCase = true) ||
            value.endsWith(".home", ignoreCase = true) ||
            value.endsWith(".internal", ignoreCase = true) ||
            (!value.contains('.') && !value.contains(':'))
        ) return true

        val ipv4Literal = IPV4_PATTERN.matches(value)
        val ipv6Literal = value.contains(':') && IPV6_PATTERN.matches(value)
        if (!ipv4Literal && !ipv6Literal) return false

        val address = runCatching { InetAddress.getByName(value) }.getOrNull() ?: return false
        if (address.isAnyLocalAddress || address.isLoopbackAddress ||
            address.isLinkLocalAddress || address.isSiteLocalAddress
        ) return true

        val ipv6 = address as? Inet6Address
        return ipv6?.address?.firstOrNull()?.let { (it.toInt() and 0xfe) == 0xfc } == true
    }

    private val IPV4_PATTERN = Regex("""^\d{1,3}(?:\.\d{1,3}){3}$""")
    private val IPV6_PATTERN = Regex("""^[0-9a-fA-F:.%]+$""")
}

@Composable
fun rememberLocalNetworkPermissionGate(): (onGranted: () -> Unit, onDenied: () -> Unit) -> Unit {
    val context = LocalContext.current
    val grantedAction = remember { mutableStateOf<(() -> Unit)?>(null) }
    val deniedAction = remember { mutableStateOf<(() -> Unit)?>(null) }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        val action = if (granted) grantedAction.value else deniedAction.value
        grantedAction.value = null
        deniedAction.value = null
        action?.invoke()
    }

    return remember(context, launcher) {
        { onGranted: () -> Unit, onDenied: () -> Unit ->
            if (LocalNetworkAccess.isGranted(context)) {
                onGranted()
            } else {
                grantedAction.value = onGranted
                deniedAction.value = onDenied
                launcher.launch(LocalNetworkAccess.PERMISSION)
            }
        }
    }
}
