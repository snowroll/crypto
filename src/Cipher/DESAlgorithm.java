package cipher;
import java.awt.image.Kernel;
import java.util.Arrays;
import java.util.Base64;

import javax.print.attribute.Size2DSyntax;
import javax.security.auth.Refreshable;

import utils.Utils;

// Data Encryption Standard 
public class DESAlgorithm implements EncryptionAlgorithm {
	public DESAlgorithm(byte[] key) {
		byte[] desKey = generateDESKey(key);
    	subKeys = DESKeyGenerator.generateSubKeys(desKey);
    }
	
	public byte[] encrypt(byte[] plaintext) {  // √
        byte[] block = initialPermutation(plaintext);
        int left = getLeftHalf(block);
        int right = getRightHalf(block);

        for (int i = 0; i < 16; i++) {
            int temp = right;
            right = left ^ feistelFunction(right, subKeys[i]);
            left = temp;
        }

        byte[] result = combineHalves(right, left);
        return finalPermutation(result);
    }
	
	public byte[] decrypt(byte[] ciphertext) {
    	byte[] block = initialPermutation(ciphertext);
    	int right = getLeftHalf(block);
    	int left  = getRightHalf(block);  // encrypt output: R16L16
    	
    	// Utils.printIntBin(left);
    	for (int i = 15; i >= 0; i--) {
            int temp = left;
            left = right ^ feistelFunction(left, subKeys[i]);
            right = temp;
        }
    	
    	
    	byte[] result = combineHalves(left, right);
    	return finalPermutation(result);
    }

	public static byte[] generateDESKey(byte[] keyBytes) {
        // 如果密钥长度不足 8 字节，则进行补齐
        if (keyBytes.length < 8) {
            byte[] paddedKey = new byte[8];
            System.arraycopy(keyBytes, 0, paddedKey, 0, keyBytes.length);
            // 使用 0x00 补齐剩余部分
            Arrays.fill(paddedKey, keyBytes.length, 8, (byte) 0x00);
            return paddedKey;
        }

        // 如果密钥长度超过 8 字节，则截断
        return Arrays.copyOf(keyBytes, 8);
    }
	
	// 初始置换表 IP
    private static final int[] IP = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    // 逆初始置换表 FP
    private static final int[] FP = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41,  9, 49, 17, 57, 25
    };

    // 扩展置换表 E
    // 32bit => 64biy
    private static final int[] E = {
        32,  1,  2,  3,  4,  5, 
         4,  5,  6,  7,  8,  9, 
         8,  9, 10, 11, 12, 13, 
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 
        20, 21, 22, 23, 24, 25, 
        24, 25, 26, 27, 28, 29, 
        28, 29, 30, 31, 32,  1
    };

    // S 盒替换表
    // selection function
    // B-6bit  B1B6 = 2^i   B2B3B4B5 = 2^j
    // 查表确认i行j列的数字，即为S1(B)的输出
    // 011011 i=01=1 j=1101=13 所以输出为5，即0101
    private static final int[][][] S_BOX = {
        { // S1
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        { // S2
        	{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        	{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        	{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        	{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        {  // S3
        	{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        	{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        	{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        	{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },
        {  // S4
        	{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        	{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        	{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        	{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },
        {  // S5
        	{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        	{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        	{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        	{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },
        {  // S6
        	{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        	{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        	{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        	{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },
        {  // S7
        	{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        	{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        	{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        	{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },
        {  // S8
        	{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        	{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        	{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        	{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
    };
    
    // P 置换表
    // input: 32bit  output: 32bit
    // S盒之后的置换
    private static final int[] P = {
        16,  7, 20, 21, 
        29, 12, 28, 17,
         1, 15, 23, 26, 
         5, 18, 31, 10,
         2,  8, 24, 14, 
        32, 27,  3,  9,
        19, 13, 30,  6, 
        22, 11,  4, 25
    };

    // 16 轮子密钥
    private long[] subKeys = new long[16];
    
    private byte[] initialPermutation(byte[] data) {
        byte[] output = new byte[8];  // 64 位分布在 8 个字节中

        for (int i = 0; i < 64; i++) {
            int bitPosition = IP[i] - 1;  // IP 表从 1 开始，转换为 0 索引

            // 计算 bitPosition 对应的字节和位
            int byteIndex = bitPosition / 8;
            int bitIndex = 7 - (bitPosition % 8);

            // 获取该位并将其放入 output
            int bit = (data[byteIndex] >> bitIndex) & 0x01;
            output[i / 8] |= (bit << (7 - (i % 8)));
        }

        return output;
    }
    
    private int selectionPermutation(int data) {
    	int output = 0;  

        for (int i = 0; i < 32; i++) {
            int bitPosition = P[i] - 1;  // 置换表是从 1 开始，需要减 1
            int bit = (data >> (31 - bitPosition)) & 0x01;  // 获取输入的该位
            
            // 将 bit 设置到 output 的相应位置
            output |= (bit << (31 - i));
        }
        
        return output;
    }
    

    private byte[] finalPermutation(byte[] data) {
        // 根据 FP 表进行最终置换
    	byte[] output = new byte[8];  // 64 位分布在 8 个字节中

        for (int i = 0; i < 64; i++) {
            int bitPosition = FP[i] - 1;  // IP 表从 1 开始，转换为 0 索引

            // 计算 bitPosition 对应的字节和位
            int byteIndex = bitPosition / 8;
            int bitIndex = 7 - (bitPosition % 8);

            // 获取该位并将其放入 output
            int bit = (data[byteIndex] >> bitIndex) & 0x01;
            output[i / 8] |= (bit << (7 - (i % 8)));
        }

        return output;
    }
    
    // 根据S盒进行替换
    private int selectionFunction(int i, byte data) {
    	int row = ((data >> 5) & 0x01) << 1 | (data & 0x01);
    	int col = (data >> 1) & 0x0F;
    	return S_BOX[i][row][col];
    }

    private int feistelFunction(int half, long subKey) {
        // 扩展置换、密钥混合、S 盒替换、P 置换
    	
    	long expand_temp = 0L;
    	expand_temp = (subKey ^ expand(half)) & 0xFFFFFFFFFFFFL;
    	byte[] blocks = new byte[8];
    	blocks = splitInto6BitBlocks(expand_temp);
    	
    	int SRes = 0;
    	for (int i = 0; i < 8; i++) {
    		int temp = selectionFunction(i, blocks[i]);
    		SRes |= temp << ((7 - i) * 4);
    	}
    	
    	int fRes = selectionPermutation(SRes);
    	
		return fRes;
    }

    private int getLeftHalf(byte[] block) {
        // 取前 32 位
    	int left = ((block[0] & 0xFF) << 24) | 
    			   ((block[1] & 0xFF) << 16) |
    			   ((block[2] & 0xFF) << 8)  |
    				(block[3] & 0xFF);
    	return left;
    }

    private int getRightHalf(byte[] block) {
        // 取后 32 位
    	int right = ((block[4] & 0xFF) << 24) | 
					((block[5] & 0xFF) << 16) |
					((block[6] & 0xFF) << 8)  |
					 (block[7] & 0xFF);
    	return right;
    }

    private byte[] combineHalves(int left, int right) {
        // 合并左右部分
    	byte[] result = new byte[8];
    	for (int i = 3; i >= 0; i--) {
    		result[i] = (byte) (left & 0xFF);
    		left >>= 8;
			result[i + 4] = (byte) (right & 0xFF);
			right >>= 8;
    	}
    	return result;
    }
    
    // 扩展置换方法
    public static long expand(int input) {
        byte[] output = new byte[6];  // 48 位即 6 字节

        for (int i = 0; i < 48; i++) {
            int bitPosition = E[i] - 1;  // 置换表是从 1 开始，需要减 1
            int bit = (input >> (31 - bitPosition)) & 0x01;  // 获取输入的该位
            
            // 设置到 output 的相应位
            output[i / 8] |= (bit << (7 - (i % 8)));
        }
        
        long res = 0x0L;
        for (int i = 0; i < 6; i++) {
        	res |= (output[i] & 0xFFL) << (40 - i *8);
        }
        return res;
    }
    
    // 将扩展后的48位结果，再分为8个bit的块，进行S盒运算
    public static byte[] splitInto6BitBlocks(long expandedInput) {
        byte[] blocks = new byte[8];

        for (int i = 0; i < 8; i++) {
            // 右移并提取 6 位，并确保范围在 0 到 63 之间
            blocks[i] = (byte) ((expandedInput >> (42 - i * 6)) & 0x3F);
        }

        return blocks;
    }
    
    
    public static boolean unitTestEncrypt() {
	    byte[] input = {
    		(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
	  	};
	    byte[] key = {
    		(byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
            (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
	  	};
	    byte[] correctRes = {
    		(byte) 0x85, (byte) 0xE8, (byte) 0x13, (byte) 0x54,
	  	    (byte) 0x0F, (byte) 0x0A, (byte) 0xB4, (byte) 0x05,
	    };
	    DESAlgorithm des = new DESAlgorithm(key);
	    byte[] ciphertext = des.encrypt(input);
	    boolean isEqual = Arrays.equals(correctRes, ciphertext);
	    if (isEqual) {
	    	System.out.println("Congratulation! DES Encryption is correct!");
	    }
	    else {
	    	System.out.println("Oops, there are some mistakes in the AES Decryption!");
	    }
	    return isEqual;
    } 
    
    public static boolean unitTestDecrypt() {
	    byte[] input = {
    		(byte) 0x85, (byte) 0xE8, (byte) 0x13, (byte) 0x54,
	  	    (byte) 0x0F, (byte) 0x0A, (byte) 0xB4, (byte) 0x05,
	  	};
	    byte[] key = {
    		(byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
            (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
	  	};
	    byte[] correctRes = {
    		(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
	    };
	    DESAlgorithm des = new DESAlgorithm(key);
	    byte[] plaintext = des.decrypt(input);
	    boolean isEqual = Arrays.equals(correctRes, plaintext);
	    if (isEqual) {
	    	System.out.println("Congratulation! DES Decryption is correct!");
	    }
	    else {
	    	System.out.println("Oops, there are some mistakes in the AES Decryption!");
	    }
	    return isEqual;
    }


    public static void main(String[] args) {
    	byte[] key = {
            (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
            (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
        };
        byte[] plaintext = {
    		(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
        };
        		
        String key0 = "123";
        String input = "helloworld";
        
        DESAlgorithm des = new DESAlgorithm(key0.getBytes());
        byte[] ciphertext = des.encrypt(input.getBytes());
        
        // des.unitTestEncrypt();
        // des.unitTestDecrypt();
        // byte[] ciphertext = des.encrypt(plaintext);
        // byte[] detext     = des.decrypt(ciphertext);
        
        
        String ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertext);
		System.out.println("Ciphertext (Base64): " + ciphertextBase64);
    }
    
    public static void print(String text) {
    	System.out.print(text);
    }
}