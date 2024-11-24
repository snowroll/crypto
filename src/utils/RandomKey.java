package utils;
import java.security.SecureRandom;
import java.util.Base64;

public class RandomKey {
	
	// 生成 DES 密钥 (56-bit, 8 bytes)，支持自定义随机种子
    public static String generateDESKey(long seed) {
        byte[] key = new byte[8]; // DES 密钥长度为 8 字节
        SecureRandom random = new SecureRandom();
        random.setSeed(seed);
        random.nextBytes(key);
        String desKey = Base64.getEncoder().encodeToString(key);
        return desKey;
    }

    // 生成 AES 密钥 (128-bit, 16 bytes)，支持自定义随机种子
    public static String generateAESKey(long seed) {
        byte[] key = new byte[16]; // AES-128 密钥长度为 16 字节
        SecureRandom random = new SecureRandom();
        random.setSeed(seed);
        random.nextBytes(key);
        String aesKey = Base64.getEncoder().encodeToString(key);
        return aesKey;
    }

    public static void main(String[] args) {
        // 示例：使用种子 123456 来生成密钥
        long seed = 123456L;
    }

    // 辅助方法：将字节数组转换为十六进制字符串
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
	
}

