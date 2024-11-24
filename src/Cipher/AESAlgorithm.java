package Cipher;
import java.util.Arrays;
import java.util.Base64;

public class AESAlgorithm implements EncryptionAlgorithm {
	// AES 128
    private static final int Nb = 4; // 列数（固定为 4）
    private static final int Nk = 4; // 密钥长度（128 位密钥 -> 4 个 32 位字）
    private static final int Nr = 10; // 轮数（128 位密钥使用 10 轮）
    private byte[] key;
    
    public AESAlgorithm(byte[] key) {
        this.key = key;
    }

    
    // round function
    // 1. byte substitution using S-box
    // 2. shift rows of the State array
    // 3. mix data with each column of the State array
    // 4. add a Round Key to the State

    public static final int[] S_BOX = {
	    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	};
    
    public static final int[] InvSBox = {
	    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
	};
    
    // Rcon[i] = [x^(i-1), {00}, {00}, {00}]  x = {02} 
    // i starts at 1
    private static final byte[] R_CON = { 
	    (byte) 0x00, // RCON[0] 未使用
	    (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08,
	    (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80,
	    (byte) 0x1B, (byte) 0x36, (byte) 0x6C, (byte) 0xD8,
	    (byte) 0xAB, (byte) 0x4D, (byte) 0x9A
	};

    private byte[][] roundKeys; // 轮密钥

    // 密钥扩展
    // input key => key schedule
    public void keyExpansion() {
    	byte[] key = this.key;
        roundKeys = new byte[Nb * (Nr + 1)][4];
        for (int i = 0; i < Nk; i++) {
            roundKeys[i] = Arrays.copyOfRange(key, i * 4, (i + 1) * 4);
        }

        byte[] temp = new byte[4];
        for (int i = Nk; i < Nb * (Nr + 1); i++) {
        	// 不能直接使用 temp = roundKeys[i-1] 
        	// 引用会修改原有密钥的值
        	System.arraycopy(roundKeys[i - 1], 0, temp, 0, 4);  
            if (i % Nk == 0) {
                temp = subWord(rotWord(temp));
                temp[0] ^= R_CON[i / Nk];  // 后三位为00，实际只有第一位发挥作用
            }
            // else if (Nk > 6 && (i % Nk == 4)) {
            // 	 temp = subWord(temp);            
            // }
            for (int j = 0; j < 4; j++) {
                roundKeys[i][j] = (byte) (roundKeys[i - Nk][j] ^ temp[j]);
            }
        }
    }

    // SubBytes 非线性变化，每个字节独立
    private void subBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = (byte) S_BOX[state[i][j] & 0xFF];
            }
        }
    }
    
    public void invSubBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = (byte) InvSBox[state[i][j] & 0xFF];
            }
        }
    }

    // ShiftRows
    private void shiftRows(byte[][] state) {
        byte temp;
        // 第 2 行左移 1 字节
        temp = state[1][0];
        System.arraycopy(state[1], 1, state[1], 0, Nb - 1);
        state[1][Nb - 1] = temp;

        // 第 3 行左移 2 字节
        temp = state[2][0];
        byte temp2 = state[2][1];
        state[2][0] = state[2][2];
        state[2][1] = state[2][3];
        state[2][2] = temp;
        state[2][3] = temp2;

        // 第 4 行左移 3 字节
        temp = state[3][0];
        state[3][0] = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = temp;
    }
    
    public void invShiftRows(byte[][] state) {
        // 第 2 行右移 1 字节
        byte temp = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp;

        // 第 3 行右移 2 字节
        byte temp1 = state[2][0];
        byte temp2 = state[2][1];
        state[2][0] = state[2][2];
        state[2][1] = state[2][3];
        state[2][2] = temp1;
        state[2][3] = temp2;

        // 第 4 行右移 3 字节（等于左移 1 字节）
        temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;
    }

    private static void mixColumns(byte[][] state) {
        for (int c = 0; c < 4; c++) {
            byte s0 = state[0][c];
            byte s1 = state[1][c];
            byte s2 = state[2][c];
            byte s3 = state[3][c];

            state[0][c] = (byte) (gmul(s0, (byte) 0x02) ^ gmul(s1, (byte) 0x03) ^ s2 ^ s3);
            state[1][c] = (byte) (s0 ^ gmul(s1, (byte) 0x02) ^ gmul(s2, (byte) 0x03) ^ s3);
            state[2][c] = (byte) (s0 ^ s1 ^ gmul(s2, (byte) 0x02) ^ gmul(s3, (byte) 0x03));
            state[3][c] = (byte) (gmul(s0, (byte) 0x03) ^ s1 ^ s2 ^ gmul(s3, (byte) 0x02));
        }
    }
    
    public void invMixColumns(byte[][] state) {
        for (int c = 0; c < Nb; c++) {
            byte s0 = state[0][c];
            byte s1 = state[1][c];
            byte s2 = state[2][c];
            byte s3 = state[3][c];

            state[0][c] = (byte) (gmul(s0, (byte) 0x0e) ^ gmul(s1, (byte) 0x0b) ^ gmul(s2, (byte) 0x0d) ^ gmul(s3, (byte) 0x09));
            state[1][c] = (byte) (gmul(s0, (byte) 0x09) ^ gmul(s1, (byte) 0x0e) ^ gmul(s2, (byte) 0x0b) ^ gmul(s3, (byte) 0x0d));
            state[2][c] = (byte) (gmul(s0, (byte) 0x0d) ^ gmul(s1, (byte) 0x09) ^ gmul(s2, (byte) 0x0e) ^ gmul(s3, (byte) 0x0b));
            state[3][c] = (byte) (gmul(s0, (byte) 0x0b) ^ gmul(s1, (byte) 0x0d) ^ gmul(s2, (byte) 0x09) ^ gmul(s3, (byte) 0x0e));
        }
    }
    
    // 有限域乘法
    private static byte gmul(byte a, byte b) {
        byte p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                p ^= a;
            }
            boolean highBitSet = (a & 0x80) != 0;
            a <<= 1;
            if (highBitSet) {
                a ^= 0x1B; // 在 GF(2^8) 上模多项式 x^8 + x^4 + x^3 + x + 1
            }
            b >>= 1;
        }
        return p;
    }
    
    // AddRoundKey
    private void addRoundKey(byte[][] state, int round) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] ^= roundKeys[round * Nb + j][i];
            }
        }
    }
    
    // 调试输出state
    public static void printState(byte[][] state) {
        for (int i = 0; i < state.length; i++) {
            for (int j = 0; j < state[i].length; j++) {
                // 输出每个字节为两位的 16 进制表示
                System.out.printf("%02X ", state[i][j]);
            }
            System.out.println();
        }
        System.out.println();
    }
    
    public static void printCipher(byte[] cipher) {
        for (int i = 0; i < cipher.length; i++) {
            // 输出每个字节为两位的 16 进制表示
            System.out.printf("%02X ", cipher[i]);
        }
        System.out.println();
    }

    // 加密过程
    public byte[] encrypt(byte[] plaintext) {
        byte[][] state = new byte[4][Nb];
        for (int i = 0; i < 4 * Nb; i++) {  // state = in
            state[i % 4][i / 4] = plaintext[i];
        }
        
        keyExpansion();  // √
        addRoundKey(state, 0);  // √
        
        for (int round = 1; round < Nr; round++) {  // √
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
        }
        
        // √
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, Nr); 
        
        byte[] ciphertext = new byte[4 * Nb];
        for (int i = 0; i < 4 * Nb; i++) {
            ciphertext[i] = state[i % 4][i / 4];
        }
        
        return ciphertext;  // √
    }

    // 辅助方法：字代换和字循环
    private byte[] subWord(byte[] word) {
        for (int i = 0; i < 4; i++) {
            word[i] = (byte) S_BOX[word[i] & 0xFF];
        }
        return word;
    }

    private byte[] rotWord(byte[] word) {
        byte temp = word[0];
        System.arraycopy(word, 1, word, 0, 3);
        word[3] = temp;
        return word;
    }  
    
    // 解密过程
    public byte[] decrypt(byte[] ciphertext) {
        byte[][] state = new byte[4][Nb];
        for (int i = 0; i < 4 * Nb; i++) {  // state = in
            state[i % 4][i / 4] = ciphertext[i];
        }
        
        keyExpansion();  // √
        // 初始轮：添加轮密钥
        addRoundKey(state, Nr);

        // 主循环：Nr - 1 轮
        for (int round = Nr - 1; round > 0; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumns(state);
        }

        // 最后一轮：不包含 invMixColumns
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);
        
        byte[] plaintext = new byte[4 * Nb];
        for (int i = 0; i < 4 * Nb; i++) {
            plaintext[i] = state[i % 4][i / 4];
        }
        
        return plaintext;  // √
    }
    
    public static boolean unitTestEncrypt() {
	    byte[] input = {
	  	    (byte) 0x32, (byte) 0x43, (byte) 0xf6, (byte) 0xa8,
	  	    (byte) 0x88, (byte) 0x5a, (byte) 0x30, (byte) 0x8d,
	  	    (byte) 0x31, (byte) 0x31, (byte) 0x98, (byte) 0xa2,
	  	    (byte) 0xe0, (byte) 0x37, (byte) 0x07, (byte) 0x34
	  	};
	    byte[] key = {
	  	    (byte) 0x2b, (byte) 0x7e, (byte) 0x15, (byte) 0x16,
	  	    (byte) 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
	  	    (byte) 0xab, (byte) 0xf7, (byte) 0x15, (byte) 0x88,
	  	    (byte) 0x09, (byte) 0xcf, (byte) 0x4f, (byte) 0x3c
	  	};
	    byte[] correctRes = {
    		(byte) 0x39, (byte) 0x25, (byte) 0x84, (byte) 0x1d,
		    (byte) 0x02, (byte) 0xdc, (byte) 0x09, (byte) 0xfb,
		    (byte) 0xdc, (byte) 0x11, (byte) 0x85, (byte) 0x97,
		    (byte) 0x19, (byte) 0x6a, (byte) 0x0b, (byte) 0x32
	    };
	    
	    AESAlgorithm aes = new AESAlgorithm(key);
	    byte[] ciphertext = aes.encrypt(input);
	    boolean isEqual = Arrays.equals(correctRes, ciphertext);
	    if (isEqual) {
	    	System.out.println("Congratulation! AES Encryption is correct!");
	    }
	    else {
	    	System.out.println("Oops, there are some mistakes in the AES Encryption!");
	    }
	    return isEqual;
    }
    
    public static boolean unitTestDecrypt() {
	    byte[] input = {
    		(byte) 0x39, (byte) 0x25, (byte) 0x84, (byte) 0x1d,
		    (byte) 0x02, (byte) 0xdc, (byte) 0x09, (byte) 0xfb,
		    (byte) 0xdc, (byte) 0x11, (byte) 0x85, (byte) 0x97,
		    (byte) 0x19, (byte) 0x6a, (byte) 0x0b, (byte) 0x32
	  	};
	    byte[] key = {
	  	    (byte) 0x2b, (byte) 0x7e, (byte) 0x15, (byte) 0x16,
	  	    (byte) 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
	  	    (byte) 0xab, (byte) 0xf7, (byte) 0x15, (byte) 0x88,
	  	    (byte) 0x09, (byte) 0xcf, (byte) 0x4f, (byte) 0x3c
	  	};
	    byte[] correctRes = {
    		(byte) 0x32, (byte) 0x43, (byte) 0xf6, (byte) 0xa8,
	  	    (byte) 0x88, (byte) 0x5a, (byte) 0x30, (byte) 0x8d,
	  	    (byte) 0x31, (byte) 0x31, (byte) 0x98, (byte) 0xa2,
	  	    (byte) 0xe0, (byte) 0x37, (byte) 0x07, (byte) 0x34
	    };
	    AESAlgorithm aes = new AESAlgorithm(key);
	    byte[] plaintext = aes.decrypt(input);
	    boolean isEqual = Arrays.equals(correctRes, plaintext);
	    if (isEqual) {
	    	System.out.println("Congratulation! AES Decryption is correct!");
	    }
	    else {
	    	System.out.println("Oops, there are some mistakes in the AES Decryption!");
	    }
	    return isEqual;
    }

    public static void main(String[] args) {
    	unitTestEncrypt();
    	unitTestDecrypt();
    	/*
        AESAlgorithm aes = new AESAlgorithm();
        byte[] key = "1234567890abcdef".getBytes();
        byte[] plaintext = "Hello, AES!".getBytes();

        // 填充明文到 16 字节
        plaintext = Arrays.copyOf(plaintext, 16);

        byte[] ciphertext = aes.encrypt(plaintext, key);

		String ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertext);
		System.out.println("Ciphertext (Base64): " + ciphertextBase64);
		*/
		
    }
}