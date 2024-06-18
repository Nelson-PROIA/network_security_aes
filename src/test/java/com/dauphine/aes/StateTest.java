package com.dauphine.aes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

public class StateTest {

    @Test
    public void testSubstitute() {
        int[][] sBoxExample = new int[][]{{0x52}};
        SBox sBox = new SBox(sBoxExample);
        State state = new State(new int[][]{{0x63}});
        
        State substituted = state.substitute(sBox);
        assertEquals("52", substituted.toStringH());
    }

    @Test
    public void testShiftRows() {
        State state = new State(new int[][]{
            {0x00, 0x01, 0x02, 0x03},
            {0x10, 0x11, 0x12, 0x13},
            {0x20, 0x21, 0x22, 0x23},
            {0x30, 0x31, 0x32, 0x33}
        });

        State shifted = state.shift();
        // Verif -> première ligne n'a pas changé
        assertEquals("00 01 02 03", shifted.toStringRow(0));
        // Verif -> les autres lignes ont été correctement décalées
        assertEquals("11 12 13 10", shifted.toStringRow(1));
        assertEquals("22 23 20 21", shifted.toStringRow(2));
        assertEquals("33 30 31 32", shifted.toStringRow(3));
    }
}
