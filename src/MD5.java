import java.nio.charset.StandardCharsets;

// https://www.ietf.org/rfc/rfc1321.txt
public class MD5 {
    private static final int A = 0x67452301;
    private static final int B = 0xefcdab89;
    private static final int C = 0x98badcfe;
    private static final int D = 0x10325476;
    
    public static int F(int x, int y, int z) {
    	return (x & y) | (~x & z);
    }
    
    public static int G(int x, int y, int z) {
    	return (x & z) | (y & ~z);
    }
    
    public static int H(int x, int y, int z) {
    	return (x ^ y ^ z);
    }
    
    public static int I(int x, int y, int z) {
    	return y ^ (x | ~z);
    }
    
    // 每轮使用的常量表（64个常量） √
    private static final int[] T = new int[64];
    static {
        for (int i = 0; i < 64; i++) {
        	long value = (long) (4294967296L * Math.abs(Math.sin(i + 1))); // 避免int类型出错
            T[i] = (int) (value & 0xFFFFFFFFL);
        }
    }
  
    // 每轮的移位值表
    private static final int[] S = {
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    };
    
    
    private static String toHex(int value) {
        StringBuilder hex = new StringBuilder(8);
        for (int i = 0; i < 4; i++) {
            hex.append(String.format("%02x", (value >>> (i * 8)) & 0xff));
        }
        return hex.toString();
    }
    
    
    public static String computeMd5(String msg) {
    	byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
    	byte[] M = padMessage(msgBytes);
    	int N = M.length;
    	
    	int a = A, b = B, c = C, d = D;
    	// process each 16-word block;  
    	// word - 32bit quantity; byte - 8bit
    	for (int idx = 0; idx < N / (16 * 4); idx++) {
    		int X[] = new int[16];
    		for (int j = 0; j < 16; j++) {
    			int offset = idx * 64 + j * 4;
    			X[j] = (M[offset] & 0xFF)                // 第1字节 (低位)
   	                 | ((M[offset + 1] & 0xFF) << 8)     // 第2字节
   	                 | ((M[offset + 2] & 0xFF) << 16)   // 第3字节
   	                 | ((M[offset + 3] & 0xFF) << 24);  // 第4字节 (高位)
    		}
    		
	    	int aa = a, bb = b, cc = c, dd = d;
	    	
	    	// 64轮主循环
	    	// [abcd k s i] => a = b + ((a + Function(b,c,d) + X[k] + T[i]) <<< s)
	    	// 每一轮实际是Function不同
	        for (int i = 0; i < 64; i++) {
	            int func_value, k;
	            if (i < 16) {
	            	func_value = F(b, c, d);
	                k = i;
	            } else if (i < 32) {
	                func_value = G(b, c, d);
	                k = (5 * i + 1) % 16;
	            } else if (i < 48) {
	            	func_value = H(b, c, d);
	            	k = (3 * i + 5) % 16;
	            } else {
	            	func_value = I(b, c, d);
	            	k = (7 * i) % 16;
	            }
	            
	            int tmp = (int)((a & 0xFFFFFFFFL) + func_value + X[k] + T[i]);
	            tmp = circuitShift(tmp, S[i]);
	            
	            // 每一轮后，ABCD逆时针换位，即 ABCD => DABC => CDAB => BCDA
	            int temp = d;
	            d = c;
	            c = b;
	            b = b + tmp;
	            a = temp;
	        }
	        
	        a = a + aa;
	        b = b + bb;
	        c = c + cc;
	        d = d + dd;
    	}

    	return toHex(a) + toHex(b) + toHex(c) + toHex(d);
    }
    
    public static int circuitShift(int value, int s) {
        return (value << s) | (value >>> (32 - s));
    }
    	
    // 对消息进行填充 √
    private static byte[] padMessage(byte[] message) {
        int originalLength = message.length;
        // 信息末尾补1，之后需要保证填充完成后，长度 % 512 = 448
        int paddingLength = (56 - (originalLength + 1) % 64) % 64; 
        byte[] paddedMessage = new byte[originalLength + 1 + paddingLength + 8];

        // 复制原始消息
        System.arraycopy(message, 0, paddedMessage, 0, originalLength);

        // 添加单个1位（0x80 = 10000000）
        paddedMessage[originalLength] = (byte) 0x80;

        // 添加原始消息长度（以位为单位，存储为64位小端序） 低位字节存入低地址，内存地址先低后高。数字先高后低
        long bitLength = (long) originalLength * 8;
        for (int i = 0; i < 8; i++) {
            paddedMessage[paddedMessage.length - 8 + i] = (byte) (bitLength >>> (8 * i));
        }
        return paddedMessage;
    }

    // 测试函数
    public static void main(String[] args) {
        String message = "hello";
        byte[] msgBytes = message.getBytes(StandardCharsets.UTF_8);
    	byte[] M = padMessage(msgBytes);
        
        System.out.println("MD5(\"" + message + "\") = " + computeMd5(message));
    }
}

