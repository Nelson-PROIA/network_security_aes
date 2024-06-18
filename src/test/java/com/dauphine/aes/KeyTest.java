package com.dauphine.aes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class KeyTest {

    @Test
    public void testBlockConstructor() {
        Block block = new Block("00000001001000110100010101100111100010011000000010010001101000101011001111000100110101011110011011110111101010111100110111101111"); // 64 bits
        Key key = new Key(block);

        assertEquals("00000001", key.elmnt(0, 0).toString());
        assertEquals("10001001", key.elmnt(1, 0).toString());
        // ....
    }


    @Test
    public void testCopyConstructor() {
        Key original = new Key();
        Key copy = new Key(original);
        for (int i = 0; i < AES.NUMBER_BLOCKS; i++) {
            assertEquals(original.elmnt(i, 0).toString(), copy.elmnt(i, 0).toString());
        }
    }

    //@Test
    //public void testGenSubKeys() {
    //    Block dummyBlock = new Block("00000001");
    //    SBox dummySBox = new SBox(new int[][]{{0x63}});
    //    Key key = new Key(new Block[]{dummyBlock, dummyBlock, dummyBlock, dummyBlock});
    //    Key[] subKeys = key.genSubKeys(dummySBox);

    //    assertEquals(11, subKeys.length);
    //}

}
