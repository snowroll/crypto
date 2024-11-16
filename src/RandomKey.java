import java.security.SecureRandom;

public class RandomKey {
	
	// 生成 DES 密钥 (56-bit, 8 bytes)，支持自定义随机种子
    public static byte[] generateDESKey(long seed) {
        byte[] key = new byte[8]; // DES 密钥长度为 8 字节
        SecureRandom random = new SecureRandom();
        random.setSeed(seed);
        random.nextBytes(key);
        return key;
    }

    // 生成 AES 密钥 (128-bit, 16 bytes)，支持自定义随机种子
    public static byte[] generateAESKey(long seed) {
        byte[] key = new byte[16]; // AES-128 密钥长度为 16 字节
        SecureRandom random = new SecureRandom();
        random.setSeed(seed);
        random.nextBytes(key);
        return key;
    }

    public static void main(String[] args) {
        // 示例：使用种子 123456 来生成密钥
        long seed = 123456L;

        // 生成并打印 DES 密钥
        byte[] desKey = generateDESKey(seed);
        System.out.println("Generated DES Key: " + bytesToHex(desKey));

        // 生成并打印 AES 密钥
        byte[] aesKey = generateAESKey(seed);
        System.out.println("Generated AES Key: " + bytesToHex(aesKey));
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

