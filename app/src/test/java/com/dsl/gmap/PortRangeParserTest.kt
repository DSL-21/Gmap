package com.dsl.gmap

import com.dsl.gmap.scanner.validation.PortRangeParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PortRangeParserTest {
    @Test
    fun acceptsValidRange() {
        val range = PortRangeParser.parse("1", "1024")
        assertEquals(1, range?.start)
        assertEquals(1024, range?.end)
        assertEquals(1024, range?.size)
    }

    @Test
    fun trimsWhitespace() {
        val range = PortRangeParser.parse(" 80 ", " 443 ")
        assertEquals(80, range?.start)
        assertEquals(443, range?.end)
    }

    @Test
    fun rejectsOutOfRangeValues() {
        assertNull(PortRangeParser.parse("0", "80"))
        assertNull(PortRangeParser.parse("1", "65536"))
    }

    @Test
    fun rejectsReversedRange() {
        assertNull(PortRangeParser.parse("1000", "100"))
    }

    @Test
    fun rejectsNonNumericValues() {
        assertNull(PortRangeParser.parse("http", "443"))
    }
}
