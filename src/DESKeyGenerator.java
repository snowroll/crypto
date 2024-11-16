// ref url: https://www.cnblogs.com/LoganChen/p/11432092.html

public class DESKeyGenerator { // √
	/* PC-1 表置换定义 */
    private static final int[] PC1 = {
		57, 49, 41, 33, 25, 17,  9,
		 1, 58, 50, 42, 34, 26, 18,
		10,  2, 59, 51, 43, 35, 27,
		19, 11,  3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		 7, 62, 54, 46, 38, 30, 22,
		14,  6, 61, 53, 45, 37, 29,
		21, 13,  5, 28, 20, 12,  4};
    /* PC-2 表置换定义 */
    private static final int[] PC2 = {
		14, 17, 11, 24,  1,  5,
		 3, 28, 15,  6, 21, 10,
		23, 19, 12,  4, 26,  8,
		16,  7, 27, 20, 13,  2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32
    };
    private static final int[] SHIFTS = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    public static long[] generateSubKeys(byte[] key) {
        long[] subKeys = new long[16];
        int[] C = new int[28];
        int[] D = new int[28];

        // 初始 PC-1 置换
        int[] Kp = permutePC1(key);
        // Utils.printInt(Kp);

        // 将 56 位密钥分为 C 和 D 两个 28 位部分
        System.arraycopy(Kp, 0, C, 0, 28);
        System.arraycopy(Kp, 28, D, 0, 28);
        //Utils.printInt(D);

        // 16 轮生成子密钥
        for (int i = 0; i < 16; i++) {
            // 左移 C 和 D
            C = leftShift(C, SHIFTS[i]);
            D = leftShift(D, SHIFTS[i]);

            // 合并 C 和 D，并进行 PC-2 置换
            int[] CD = new int[56];
            System.arraycopy(C, 0, CD, 0, 28);
            System.arraycopy(D, 0, CD, 28, 28);

            subKeys[i] = permutePC2(CD);
        }
        return subKeys;
    }

    private static int[] permutePC1(byte[] key) {
        int[] Kp = new int[56];
        for (int i = 0; i < 56; i++) {
            int bit = (key[(PC1[i]-1) / 8] >> (7 - ((PC1[i]-1) % 8))) & 0x01;
            Kp[i] = bit;
        }
        return Kp;
    }

    private static int[] leftShift(int[] bits, int n) {
        int[] shifted = new int[28];
        System.arraycopy(bits, n, shifted, 0, 28 - n);
        System.arraycopy(bits, 0, shifted, 28 - n, n);
        return shifted;
    }

    private static long permutePC2(int[] CD) {
        long subKey = 0;
        for (int i = 0; i < 48; i++) {
            subKey <<= 1;
            subKey |= CD[PC2[i] - 1];
        }
        return subKey;
    }
    
    public static boolean unitTestKeyGen() {
	    byte[] key = {
    		(byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
            (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
	  	};
	    long key16 = 0b110010110011110110001011000011100001011111110101L;
	    long[] subkeys = DESKeyGenerator.generateSubKeys(key);
	    boolean isEqual = subkeys[15] == key16;
	    if (isEqual) {
	    	System.out.println("Congratulation! DES KeyGenerator is correct!");
	    }
	    else {
	    	System.out.println("Oops, there are some mistakes in the DES KeyGenerator!");
	    }
	    return isEqual;
    }
    
    public static void main(String[] args) {
    	byte[] key = {
            (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
            (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
        };
    	long[] subkeys = generateSubKeys(key);
    	
    	unitTestKeyGen();
    }
}