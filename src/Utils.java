public class Utils {
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
    
    public static void printBytesHex(byte[] cipher) {
        for (int i = 0; i < cipher.length; i++) {  // 以16进制表示字节数组
            System.out.printf("%02X ", cipher[i]);
        }
        System.out.println();
    }
    
    public static void printBytesBin(byte[] array) {
	    // 输出字节数组的二进制表示
	    for (byte b : array) {
	        // 使用 String.format 格式化输出 8 位二进制，不足位数前补 0
	        System.out.print(String.format("%8s ", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
	    }
    }
    
    public static void printIntsBin(int[] array) {
    	for (int i : array) {
    		System.out.print(String.format("%8s ", Integer.toBinaryString(i & 0xFFFF)).replace(' ', '0'));
    	}
    }
    
    public static void printLongBin(long[] array) {
    	for (long i : array) {
    		System.out.println(String.format("%8s ", Long.toBinaryString(i & 0xFFFFFFFFL)).replace(' ', '0'));
    	}
    }
}