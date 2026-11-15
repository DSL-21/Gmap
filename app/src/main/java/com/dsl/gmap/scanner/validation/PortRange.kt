package com.dsl.gmap.scanner.validation

data class PortRange(val start: Int, val end: Int) {
    val size: Int get() = end - start + 1
}

object PortRangeParser {
    fun parse(startValue: String, endValue: String): PortRange? {
        val start = startValue.trim().toIntOrNull() ?: return null
        val end = endValue.trim().toIntOrNull() ?: return null
        if (start !in 1..65535 || end !in 1..65535 || start > end) return null
        return PortRange(start, end)
    }
}
