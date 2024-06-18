package com.dauphine.aes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

public class BlockTest {

    @Test
    public void testBlockInitializationFromString() {
        Block fromString = new Block("10101010");
        assertEquals("10101010", fromString.toString());
    }

    @Test
    public void testBlockInitializationFromInt() {
        Block fromInt = new Block(8, 170); // 170 en binaire est 10101010
        assertEquals("10101010", fromInt.toString());
    }

    @Test
    public void testBlockInitializationFromBooleanArray() {
        boolean[] boolArray = new boolean[]{true, false, true, false, true, false, true, false};
        Block fromBooleanArray = new Block(boolArray);
        assertEquals("10101010", fromBooleanArray.toString());
    }

    @Test
    public void testXorOperation() {
        Block block1 = new Block("1100");
        Block block2 = new Block("1010");
        Block result = block1.xOr(block2);
        assertEquals("0110", result.toString());
    }

    @Test
    public void testLeftShift() {
        Block block = new Block("1101");
        Block shifted = block.leftShift();
        assertEquals("1010", shifted.toString());
    }

    @Test
    public void testModularMultiplicationByX() {
        Block block = new Block(8, 0x57);
        Block result = block.modularMultByX();
        assertEquals("AE", result.toStringH());
    }
}
