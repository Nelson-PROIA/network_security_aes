package com.dauphine.aes;

import java.util.Arrays;
import java.util.Locale;

/**
 * <p>
 * Implementation of a simplified AES encryption algorithm.
 * This class provides methods for encryption (ciphering) and decryption (deciphering) using AES.
 * </p>
 *
 * <p>
 * It includes definitions for the S-box, inverse S-box, mix matrix, and inverse mix matrix.
 * </p>
 *
 * @author Ricardo BOKA {@literal <ricardo.boka@dauphine.eu>}
 * @see Block
 * @see Key
 * @see SBox
 * @see State
 */
public class AES {

    /**
     * The number of rounds in the AES encryption process.
     */
    public final static int NUMBER_ROUNDS = 11;

    /**
     * The number of blocks in the key.
     */
    public final static int NUMBER_BLOCKS = 4;

    /**
     * The S-box for byte substitution during encryption.
     */
    private static final int[][] sBoxValues = {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
    };

    /**
     * The inverse S-box for byte substitution during decryption.
     */
    private static final int[][] sBoxInvertValues = {
            {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
            {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
            {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
            {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
            {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
            {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
            {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
            {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
            {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
            {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
            {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
            {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
            {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
            {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
            {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
    };

    /**
     * The matrix used for the mix columns step during encryption.
     */
    private static final int[][] stateValues = {
            {2, 3, 1, 1},
            {1, 2, 3, 1},
            {1, 1, 2, 3},
            {3, 1, 1, 2}
    };

    /**
     * The matrix used for the mix columns step during decryption.
     */
    private static final int[][] stateInvertValues = {
            {14, 11, 13, 9},
            {9, 14, 11, 13},
            {13, 9, 14, 11},
            {11, 13, 9, 14}
    };

    /**
     * The array of round keys derived from the original key.
     *
     * @see Key
     */
    private final Key[] keys;

    /**
     * The S-box used for substitution during encryption.
     *
     * @see SBox
     */
    private final SBox sBox;

    /**
     * The inverse S-box used for substitution during decryption.
     *
     * @see SBox
     */
    private final SBox sBoxInvert;

    /**
     * The state for the mix columns step during encryption.
     *
     * @see State
     */
    private final State state;

    /**
     * The state for the mix columns step during decryption.
     *
     * @see State
     */
    private final State stateInvert;

    /**
     * Constructs an AES instance with the given key.
     * Initializes the S-boxes, mix states, and generates the round keys.
     *
     * @param key The Block representing the key.
     * @see Block
     * @see Key
     * @see SBox
     * @see State
     */
    AES(Block key) {
        sBox = new SBox(sBoxValues);
        sBoxInvert = new SBox(sBoxInvertValues);

        state = new State(stateValues);
        stateInvert = new State(stateInvertValues);

        Key temp = new Key(key);
        keys = temp.genSubKeys(sBox);
    }

    /**
     * Ciphers the given plain text block.
     *
     * @param plain The Block representing the plain block.
     * @return The encrypted Block.
     * @see Block
     * @see Key
     * @see State
     */
    Block cypher(Block plain) {
        State cipher = new State(plain);

        int round = 0;
        cipher = cipher.xOr(keys[round]);

        for (round = 1; round < NUMBER_ROUNDS - 1; ++round) {
            cipher = cipher.substitute(sBox);
            cipher = cipher.shift();
            cipher = cipher.mult(state);
            cipher = cipher.xOr(keys[round]);
        }

        cipher = cipher.substitute(sBox);
        cipher = cipher.shift();
        cipher = cipher.xOr(keys[round]);

        return cipher.block();
    }

    /**
     * Deciphers the given cipher text block.
     *
     * @param cipher The Block representing the cipher text.
     * @return The decrypted Block.
     * @see Block
     * @see Key
     * @see State
     */
    Block deCypher(Block cipher) {
        State decipher = new State(cipher);

        int round = NUMBER_ROUNDS - 1;
        decipher = decipher.xOr(keys[round]);

        for (round = NUMBER_ROUNDS - 2; round > 0; --round) {
            decipher = decipher.shiftInv();
            decipher = decipher.substitute(sBoxInvert);
            decipher = decipher.xOr(keys[round]);
            decipher = decipher.mult(stateInvert);
        }

        decipher = decipher.shiftInv();
        decipher = decipher.substitute(sBoxInvert);
        decipher = decipher.xOr(keys[round]);

        return decipher.block();
    }

    /**
     * The main method to test the AES implementation.
     * Encrypts and decrypts a sample plain text and compares the result.
     *
     * @param args Command-line arguments (not used).
     * @see Block
     */
    public static void main(String[] args) {
        String plain = "00000001001000110100010101100111100010011010101111001101111011111111111011011100101110101001100001110110010101000011001000010000";
        String key = "00001111000101010111000111001001010001111101100111101000010110010000110010110111101011011101011010101111011111110110011110011000";

        Block plainBlock = new Block(plain);
        Block keyBlock = new Block(key);

        AES aes = new AES(keyBlock);

        Block cipherBlock = aes.cypher(plainBlock);
        Block decipherBlock = aes.deCypher(cipherBlock);

        System.out.println("SBox : \n" + aes.sBox);
        System.out.println("SBoxInvert : \n" + aes.sBoxInvert);
        System.out.println("State : \n" + aes.state);
        System.out.println("StateInvert : \n" + aes.stateInvert);

        System.out.println("Plain : " + plainBlock);
        System.out.println("Key : " + key);
        System.out.println();

        System.out.println("Cipher block : " + cipherBlock);
        System.out.println("Decipher block : " + decipherBlock);
        System.out.println();

        System.out.println("[TEST] Decipher block and plain are" + (decipherBlock.toString().compareTo(plain) == 0 ? " " : " not ") + "equal!");
    }

}

/**
 * <p>
 * Represents a block of binary data. This class provides methods for creating,
 * manipulating, and converting binary data blocks.
 * </p>
 *
 * <p>
 * This implementation supports various operations like XOR, left shift,
 * modular multiplication, and segment extraction.
 * </p>
 *
 * @author Sébastien GIRET-IHMAUS {@literal <sebastien.giret-ihmaus@dauphine.eu>}
 * @author Nelson PROIA {@literal <nelson.proia@dauphine.eu>}
 * @see AES
 * @see Key
 * @see SBox
 */
class Block implements Cloneable {

    /**
     * Represents the generator polynomial used in AES key expansion.
     * This polynomial is used in certain key expansion operations.
     */
    public final static Block GENERATOR_POLYNOMIAL = new Block("00011011");

    /**
     * The array of bits representing the binary data.
     */
    public boolean[] bits;

    /**
     * Constructs a block of binary data with the specified size.
     *
     * @param size The size of the block.
     */
    public Block(int size) {
        bits = new boolean[size];
    }

    /**
     * Constructs a block of binary data with the specified size and value.
     *
     * @param size  The size of the block.
     * @param value The value to initialize the block with.
     */
    public Block(int size, int value) {
        this(size);

        for (int i = size - 1; i >= 0; --i) {
            bits[i] = (value % 2) == 1;
            value /= 2;
        }
    }

    /**
     * Constructs a block of binary data from a binary string.
     *
     * @param bits The binary string representing the block.
     */
    public Block(String bits) {
        this(bits.length());

        for (int i = 0; i < bits.length(); ++i) {
            this.bits[i] = bits.charAt(i) == '1';
        }
    }

    /**
     * Constructs a block of binary data from a boolean array.
     *
     * @param bits The boolean array representing the block.
     */
    public Block(boolean[] bits) {
        this.bits = bits.clone();
    }

    /**
     * Constructs a block of binary data from an array of blocks.
     *
     * @param blocks The array of blocks to construct the block from.
     */
    public Block(Block[] blocks) {
        int size = Arrays.stream(blocks).mapToInt(block -> block.bits.length).sum();
        bits = new boolean[size];

        int index = 0;

        for (Block block : blocks) {
            System.arraycopy(block.bits, 0, bits, index, block.bits.length);
            index += block.bits.length;
        }
    }

    /**
     * {@inheritDoc}
     * <p>
     * Creates a deep copy of the block.
     */
    @Override
    public Block clone() {
        try {
            Block clone = (Block) super.clone();
            clone.bits = bits.clone();

            return clone;
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Gets a segment of the block.
     *
     * @param numberSegments The number of segments.
     * @param index          The index of the segment.
     * @return The segment block.
     */
    public Block portion(int numberSegments, int index) {
        int segmentLength = bits.length / numberSegments;
        boolean[] segment = new boolean[segmentLength];

        System.arraycopy(bits, index * segmentLength, segment, 0, segmentLength);

        return new Block(segment);
    }

    /**
     * Retrieves the decimal value of the row index from the block.
     * The row index is obtained from the first segment of the block.
     *
     * @return The decimal value of the row index.
     */
    public int rowValue() {
        return portion(2, 0).toDecimal();
    }

    /**
     * Retrieves the decimal value of the column index from the block.
     * The column index is obtained from the second segment of the block.
     *
     * @return The decimal value of the column index.
     */
    public int columnValue() {
        return portion(2, 1).toDecimal();
    }

    /**
     * Performs an exclusive OR (XOR) operation between two blocks.
     *
     * @param other The other block to perform XOR with.
     * @return The resulting block.
     */
    public Block xOr(Block other) {
        boolean[] resultBits = new boolean[bits.length];

        for (int i = 0; i < bits.length; ++i) {
            resultBits[i] = bits[i] ^ other.bits[i];
        }

        return new Block(resultBits);
    }

    /**
     * Performs a left shift operation on the block.
     *
     * @return The resulting block after left shift.
     */
    public Block leftShift() {
        boolean[] shiftedBits = new boolean[bits.length];

        System.arraycopy(bits, 1, shiftedBits, 0, bits.length - 1);
        shiftedBits[bits.length - 1] = false;

        return new Block(shiftedBits);
    }

    /**
     * Performs modular multiplication by X on the block.
     *
     * @return The resulting block after modular multiplication.
     */
    public Block modularMultByX() {
        return bits[0] ? leftShift().xOr(GENERATOR_POLYNOMIAL) : leftShift();
    }

    /**
     * Performs modular multiplication operation between two blocks.
     *
     * @param other The other block to perform multiplication with.
     * @return The resulting block after multiplication.
     */
    public Block modularMult(Block other) {
        Block result = new Block(bits.length);
        Block multiplier = clone();

        for (int i = other.bits.length - 1; i >= 0; --i) {
            if (other.bits[i]) {
                result = result.xOr(multiplier);
            }

            multiplier = multiplier.modularMultByX();
        }

        return result;
    }

    /**
     * Performs the 'g' operation on the block.
     *
     * @param sbox          The S-box used in the operation.
     * @param roundConstant The round constant used in the operation.
     * @return The resulting block after the 'g' operation.
     * @see AES
     * @see SBox
     */
    public Block g(SBox sbox, Block roundConstant) {
        Block[] subBlocks = new Block[AES.NUMBER_BLOCKS];

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            subBlocks[i] = sbox.cypher(portion(AES.NUMBER_BLOCKS, (i + 1) % AES.NUMBER_BLOCKS));
        }

        Block newBlock = new Block(subBlocks);
        roundConstant = new Block(roundConstant.toString() + "0".repeat(AES.NUMBER_BLOCKS * 6));

        return newBlock.xOr(roundConstant);
    }

    /**
     * Converts a string to an array of blocks with the specified block size.
     *
     * @param string    The string to convert.
     * @param blockSize The size of each block.
     * @return An array of blocks.
     * @see AES
     */
    public static Block[] stringToBlock(String string, int blockSize) {
        int numberBlocks = string.length() / blockSize;
        Block[] result = new Block[numberBlocks];

        for (int i = 0; i < numberBlocks; ++i) {
            Block[] temp = new Block[blockSize];

            for (int j = 0; j < blockSize; ++j) {
                Block byteBlock = new Block(AES.NUMBER_BLOCKS * 2);
                char ch = string.charAt(i * blockSize + j);

                for (int k = 0; k < AES.NUMBER_BLOCKS * 2; ++k) {
                    byteBlock.bits[(AES.NUMBER_BLOCKS * 2 - 1) - k] = (ch & (1 << k)) != 0;
                }

                temp[j] = byteBlock;
            }

            result[i] = new Block(temp);
        }

        return result;
    }

    /**
     * Converts an array of blocks to a string.
     *
     * @param blocks The array of blocks to convert.
     * @return The resulting string.
     * @see AES
     */
    public static String blockToString(Block[] blocks) {
        StringBuilder result = new StringBuilder();

        for (Block block : blocks) {
            int numberBytes = block.bits.length / (AES.NUMBER_BLOCKS * 2);

            for (int i = 0; i < numberBytes; ++i) {
                char value = 0;

                for (int j = 0; j < (AES.NUMBER_BLOCKS * 2); ++j) {
                    if (block.bits[i * (AES.NUMBER_BLOCKS * 2) + j]) {
                        value |= (char) (1 << j);
                    }
                }

                result.append(value);
            }
        }

        return result.toString();
    }

    /**
     * Converts the block to its decimal representation.
     *
     * @return The decimal representation of the block.
     */
    public int toDecimal() {
        int decimalValue = 0;

        for (boolean bit : bits) {
            decimalValue = (decimalValue << 1) | (bit ? 1 : 0);
        }

        return decimalValue;
    }

    /**
     * Converts the block to a hexadecimal string.
     *
     * @return The hexadecimal string representation of the block.
     */
    public String toStringH() {
        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < this.bits.length; i += 4) {
            int val = (this.bits[i] ? 8 : 0) + (this.bits[i + 1] ? 4 : 0) + (this.bits[i + 2] ? 2 : 0) + (this.bits[i + 3] ? 1 : 0);

            stringBuilder.append(Integer.toHexString(val).toUpperCase(Locale.ROOT));
        }

        return stringBuilder.toString();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Converts the block to a string of '0's and '1's representing its bits.
     */
    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(bits.length);

        for (boolean bit : bits) {
            stringBuilder.append(bit ? '1' : '0');
        }

        return stringBuilder.toString();
    }

}

/**
 * <p>
 * Represents a cryptographic key for AES encryption.
 * This class provides methods for generating and manipulating AES keys.
 * </p>
 *
 * <p>
 * This implementation supports key expansion using the provided S-box and
 * can generate sub-keys for AES rounds.
 * </p>
 *
 * @author Sébastien GIRET-IHMAUS {@literal <sebastien.giret-ihmaus@dauphine.eu>}
 * @author Nelson PROIA {@literal <nelson.proia@dauphine.eu>}
 * @see AES
 * @see Block
 * @see Key
 * @see SBox
 */
class Key {

    /**
     * Array of blocks representing the key.
     *
     * @see Block
     */
    private final Block[] bytes;

    /**
     * Constructs a Key object with default block values.
     * Initializes the array of blocks and fills it with new blocks
     * of a size determined by {@code BIT * 8}.
     *
     * @see AES
     * @see Block
     */
    public Key() {
        bytes = new Block[AES.NUMBER_BLOCKS];

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            bytes[i] = new Block(AES.NUMBER_BLOCKS * 8);
        }
    }

    /**
     * Constructs a Key object from a single block.
     * Splits the block into segments to form the key.
     *
     * @param block The block to construct the Key from.
     * @see AES
     * @see Block
     */
    public Key(Block block) {
        bytes = new Block[AES.NUMBER_BLOCKS];

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            bytes[i] = block.portion(AES.NUMBER_BLOCKS, i);
        }
    }

    /**
     * Constructs a Key object from an array of blocks.
     * Clones each block from the provided array.
     *
     * @param blocks The array of blocks to construct the Key from.
     * @see AES
     * @see Block
     */
    public Key(Block[] blocks) {
        bytes = new Block[AES.NUMBER_BLOCKS];

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            bytes[i] = blocks[i].clone();
        }
    }

    /**
     * Constructs a Key object from another Key object (copy constructor).
     *
     * @param key The Key object to copy.
     * @see Block
     */
    public Key(Key key) {
        this(key.bytes);
    }

    /**
     * Gets a specific block element from the key.
     *
     * @param i The row index of the block.
     * @param j The column index of the block.
     * @return The block element at the specified indices.
     * @see AES
     * @see Block
     */
    public Block elmnt(int i, int j) {
        return bytes[i].portion(AES.NUMBER_BLOCKS, j);
    }

    /**
     * Generates sub-keys using the key and the provided S-box.
     *
     * @param sBox The S-box used in key expansion.
     * @return An array of sub-keys.
     * @see AES
     * @see Block
     * @see Key
     * @see SBox
     */
    public Key[] genSubKeys(SBox sBox) {
        Block roundConstant = new Block(AES.NUMBER_BLOCKS * 2, (int) Math.pow(2, ((AES.NUMBER_BLOCKS * 2) - 1)));
        Key[] subKeys = new Key[AES.NUMBER_ROUNDS];
        subKeys[0] = new Key(this);

        for (int i = 1; i <= (AES.NUMBER_ROUNDS - 1); ++i) {
            Block[] nextKeyBlocks = new Block[AES.NUMBER_BLOCKS];
            Block gApplied = subKeys[i - 1].bytes[bytes.length - 1].g(sBox, roundConstant);

            nextKeyBlocks[0] = subKeys[i - 1].bytes[0].xOr(gApplied);

            for (int j = 1; j < AES.NUMBER_BLOCKS; ++j) {
                nextKeyBlocks[j] = subKeys[i - 1].bytes[j].xOr(nextKeyBlocks[j - 1]);
            }

            subKeys[i] = new Key(nextKeyBlocks);
            roundConstant = roundConstant.modularMultByX();
        }

        return subKeys;
    }

    /**
     * Returns a hexadecimal string representation of the key.
     *
     * @return The hexadecimal string representation of the key.
     * @see Block
     */
    public String toStringH() {
        StringBuilder stringBuilder = new StringBuilder();

        for (Block block : bytes) {
            stringBuilder.append(block.toStringH()).append(" ");
        }

        return stringBuilder.toString();
    }

    /**
     * {@inheritDoc}
     *
     * @return The string representation of the key.
     * @see Block
     */
    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        for (Block block : bytes) {
            stringBuilder.append(block.toString()).append(" ");
        }

        return stringBuilder.toString();
    }

}

/**
 * <p>
 * Represents an S-box (Substitution-box) used in AES encryption.
 * The S-box is used to perform a substitution step during encryption.
 * This class provides a method to apply the S-box transformation to a block.
 * </p>
 *
 * @author Mathieu ANDRIN {@literal <mathieu.andrin@dauphine.eu>}
 * @see Block
 */
class SBox {

    /**
     * The S-box matrix containing the substitution values.
     */
    private final int[][] matrix;

    /**
     * Constructs an SBox with the specified substitution matrix.
     *
     * @param matrix The substitution matrix to be used by this SBox.
     */
    public SBox(int[][] matrix) {
        this.matrix = new int[matrix.length][];

        for (int i = 0; i < matrix.length; ++i) {
            this.matrix[i] = matrix[i].clone();
        }
    }

    /**
     * Applies the S-box transformation to the specified block.
     *
     * @param block The block to be transformed.
     * @return A new Block that is the result of applying the S-box transformation.
     * @see Block
     */
    public Block cypher(Block block) {
        int value = matrix[block.rowValue()][block.columnValue()];

        return new Block(block.bits.length, value);
    }

    /**
     * {@inheritDoc}
     *
     * @return The string representation of the SBox.
     */
    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        for (int[] row : matrix) {
            for (int value : row) {
                stringBuilder.append(value).append(" ");
            }

            stringBuilder.append("\n");
        }

        return stringBuilder.toString();
    }

}

/**
 * <p>
 * Represents the state in the AES encryption process.
 * This class provides methods for creating, manipulating, and converting the state.
 * </p>
 *
 * <p>
 * The state is represented as a 2D array of Blocks.
 * Each block contains binary data and operations for AES transformations.
 * </p>
 *
 * @author Mathieu ANDRIN {@literal <mathieu.andrin@dauphine.eu>}
 * @see AES
 * @see Block
 * @see Key
 * @see SBox
 */
class State {

    /**
     * The 2D array of blocks representing the state.
     *
     * @see Block
     */
    private final Block[][] bytes;

    /**
     * Constructs a new State with empty blocks.
     *
     * @see AES
     * @see Block
     */
    public State() {
        bytes = new Block[AES.NUMBER_BLOCKS][AES.NUMBER_BLOCKS];

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            for (int j = 0; j < AES.NUMBER_BLOCKS; ++j) {
                bytes[i][j] = new Block(AES.NUMBER_BLOCKS * 2);
            }
        }
    }

    /**
     * Constructs a new State from a single Block.
     *
     * @param block The Block to initialize the State.
     * @see AES
     * @see Block
     */
    public State(Block block) {
        bytes = new Block[AES.NUMBER_BLOCKS][AES.NUMBER_BLOCKS];

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            for (int j = 0; j < AES.NUMBER_BLOCKS; ++j) {
                bytes[i][j] = block.portion((int) Math.pow(2, AES.NUMBER_BLOCKS), i + j * AES.NUMBER_BLOCKS);
            }
        }
    }

    /**
     * Constructs a new State from a 2D integer array.
     *
     * @param values The 2D integer array to initialize the State.
     * @see AES
     * @see Block
     */
    public State(int[][] values) {
        bytes = new Block[AES.NUMBER_BLOCKS][AES.NUMBER_BLOCKS];

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            for (int j = 0; j < AES.NUMBER_BLOCKS; ++j) {
                bytes[i][j] = new Block(AES.NUMBER_BLOCKS * 2, values[i][j]);
            }
        }
    }

    /**
     * Constructs a new State by copying another State.
     *
     * @param other The State to copy.
     * @see AES
     * @see Block
     */
    public State(State other) {
        bytes = new Block[AES.NUMBER_BLOCKS][AES.NUMBER_BLOCKS];

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            for (int j = 0; j < AES.NUMBER_BLOCKS; ++j) {
                bytes[i][j] = other.bytes[i][j].clone();
            }
        }
    }

    /**
     * Performs an XOR operation between this State and a Key.
     *
     * @param key The Key to XOR with.
     * @return A new State resulting from the XOR operation.
     * @see AES
     * @see Block
     * @see Key
     */
    public State xOr(Key key) {
        State newState = new State();

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            for (int j = 0; j < AES.NUMBER_BLOCKS; ++j) {
                newState.bytes[i][j] = bytes[i][j].xOr(key.elmnt(j, i));
            }
        }

        return newState;
    }

    /**
     * Substitutes bytes in the State using the given S-box.
     *
     * @param sbox The S-box to use for substitution.
     * @return A new State with substituted bytes.
     * @see AES
     * @see Block
     * @see SBox
     */
    public State substitute(SBox sbox) {
        State newState = new State();

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            for (int j = 0; j < AES.NUMBER_BLOCKS; ++j) {
                newState.bytes[i][j] = sbox.cypher(bytes[i][j]);
            }
        }

        return newState;
    }

    /**
     * Shifts rows in the State.
     *
     * @return A new State with shifted rows.
     * @see AES
     * @see Block
     */
    public State shift() {
        State newState = new State();

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            for (int j = 0; j < AES.NUMBER_BLOCKS; ++j) {
                newState.bytes[i][(j + i) % AES.NUMBER_BLOCKS] = bytes[i][j];
            }
        }

        return newState;
    }

    /**
     * Inversely shifts rows in the State.
     *
     * @return A new State with inversely shifted rows.
     * @see AES
     * @see Block
     */
    public State shiftInv() {
        State newState = new State();

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            for (int j = 0; j < AES.NUMBER_BLOCKS; ++j) {
                newState.bytes[i][(j - i + AES.NUMBER_BLOCKS) % AES.NUMBER_BLOCKS] = bytes[i][j];
            }
        }

        return newState;
    }

    /**
     * Multiplies this State with another State.
     *
     * @param other The other State to multiply with.
     * @return A new State resulting from the multiplication.
     * @see AES
     * @see Block
     */
    public State mult(State other) {
        State newState = new State();

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            for (int j = 0; j < AES.NUMBER_BLOCKS; ++j) {
                Block sum = new Block(AES.NUMBER_BLOCKS * 2);

                for (int k = 0; k < AES.NUMBER_BLOCKS; ++k) {
                    sum = sum.xOr(other.bytes[i][k].modularMult(bytes[k][j]));
                }

                newState.bytes[i][j] = sum;
            }
        }

        return newState;
    }

    /**
     * Converts the State to a single Block.
     *
     * @return The resulting Block.
     * @see AES
     * @see Block
     */
    public Block block() {
        Block[] blocks = new Block[(int) Math.pow(2, AES.NUMBER_BLOCKS)];

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            for (int j = 0; j < AES.NUMBER_BLOCKS; ++j) {
                blocks[AES.NUMBER_BLOCKS * j + i] = bytes[i][j];
            }
        }

        return new Block(blocks);
    }

    /**
     * {@inheritDoc}
     *
     * @see AES
     * @see Block
     */
    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < AES.NUMBER_BLOCKS; ++i) {
            for (int j = 0; j < AES.NUMBER_BLOCKS; ++j) {
                stringBuilder.append(bytes[i][j]).append(" ");
            }

            stringBuilder.append("\n");
        }

        return stringBuilder.toString();
    }

    // Convertit l'état entier en une chaîne hexadécimale.
    public String toStringH() {
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < bytes[i].length; j++) {
                hexString.append(bytes[i][j].toStringH()).append(" ");
            }
            hexString.append("\n"); // Nouvelle ligne pour chaque rangée pour une meilleure lisibilité
        }
        return hexString.toString();
    }

    // Méthode pour obtenir une représentation sous forme de chaîne d'une ligne spécifique
    public String toStringRow(int row) {
        if (row < 0 || row >= bytes.length) {
            throw new IllegalArgumentException("Row index out of bounds");
        }
        StringBuilder rowString = new StringBuilder();
        for (int j = 0; j < bytes[row].length; j++) {
            rowString.append(bytes[row][j].toString()).append(" ");  // Utiliser toStringH() pour hexadécimal si nécessaire
        }
        return rowString.toString().trim();  // Retire l'espace supplémentaire à la fin
    }
}
