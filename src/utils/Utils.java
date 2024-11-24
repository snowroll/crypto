package utils;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

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
	        System.out.printf("%08d ", Integer.parseInt(Integer.toBinaryString(b & 0xFF)));
	    }
	    System.out.println();
    }
    
    public static void printIntsBin(int[] array) {
    	for (int i : array) {
    		printIntBin(i);
    	}
    	System.out.println();
    }
    
    public static void printIntBin(int i) {
    	// System.out.printf("%32s%n", Integer.toBinaryString(i & 0xFFFFFFFF));
    	// 获取 32 位二进制字符串并填充 '0'
        String binaryString = String.format("%32s", Integer.toBinaryString(i & 0xFFFFFFFF)).replace(' ', '0');

        // 使用正则表达式，每 4 位插入一个空格
        String formattedString = binaryString.replaceAll("(.{4})", "$1 ");

        // 打印格式化后的字符串
        System.out.println(formattedString.trim());
    }
    
    public static void printLongBin(long[] array) {
    	for (long i : array) {
    		System.out.printf("%64s%n", Long.toBinaryString(i & 0xFFFFFFFFL));
    	}
    	System.out.println();
    }
    
    public static void printInt(int[] array) {
    	for (int i = 0; i < array.length; i++) {
    		if (i % 7 == 0 && i != 0) {
    			System.out.print(' ');
    		}
    		System.out.print(array[i]);
    	}
    	System.out.println();
    }
    
    public static void printLong(long num) {
    	String binaryString = String.format("%64s", Long.toBinaryString(num)).replace(' ', '0');
    	System.out.printf("%48s%n", Long.toBinaryString(num));
    	System.out.println();
    }
    
    // 写入密钥到文件
    public static void writeRSAKeyToFile(String filePath, BigInteger e, BigInteger n, String keyType) throws IOException {
        File file = new File(filePath);
        try (FileWriter writer = new FileWriter(file)) {
        	String base64E = Base64.getEncoder().encodeToString(e.toByteArray());
            String base64N = Base64.getEncoder().encodeToString(n.toByteArray());
            
            writer.write("-----BEGIN " + keyType + "-----\n");
            writer.write(base64E + "\n");
            writer.write(base64N + "\n");
            writer.write("-----END "   + keyType + "-----");
        }
    }
    
    // 从 Base64 文件读取 BigInteger 密钥
    public static String loadRSAKey(String filePath) throws IOException {
    	String RSAkeys = new String(Files.readAllBytes(Paths.get(filePath)))
    								.replace("-----BEGIN PRIVATE KEY-----\n", "")
					                .replace("-----END PRIVATE KEY-----", "")
					                .replace("-----BEGIN PUBLIC KEY-----\n", "")
					                .replace("-----END PUBLIC KEY-----", "")
					                .trim().replace("\n", " ");
        return RSAkeys;
    }
    
    // BigInteger 转 Base64 字符串
    public static String bigIntegerToBase64(BigInteger bigInteger) {
        byte[] bytes = bigInteger.toByteArray(); // 转换为字节数组
        return Base64.getEncoder().encodeToString(bytes); // 编码为 Base64 字符串
    }

    // Base64 字符串 转 BigInteger
    public static BigInteger base64ToBigInteger(String base64String) {
        byte[] bytes = Base64.getDecoder().decode(base64String); // 解码 Base64 字符串为字节数组
        return new BigInteger(bytes); // 从字节数组还原 BigInteger
    }
    
    // 字符串转 Base64 字符串
    public static String stringToBase64(String input) {
        byte[] bytes = input.getBytes(); // 将字符串转换为字节数组
        return Base64.getEncoder().encodeToString(bytes); // 编码为 Base64 字符串
    }

    // Base64 字符串转普通字符串
    public static String base64ToString(String base64String) {
        byte[] bytes = Base64.getDecoder().decode(base64String); // 解码 Base64 字符串为字节数组
        return new String(bytes); // 将字节数组转换为字符串
    }
    
    // Base64 字符串 转 byte[]
    public static byte[] base64ToByteArray(String base64String) {
        byte[] bytes = Base64.getDecoder().decode(base64String); // 解码 Base64 字符串为字节数组
        return bytes; 
    }
    
    // 字节数组转 Base64 字符串
    public static String byteArrayToBase64(byte[] byteArray) {
        return Base64.getEncoder().encodeToString(byteArray); // 使用 Base64 编码字节数组
    }
}