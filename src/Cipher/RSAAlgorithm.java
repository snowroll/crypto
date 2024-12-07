package cipher;
import java.awt.print.Printable;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class RSAAlgorithm implements EncryptionAlgorithm {
//    private BigInteger n;      // n = p * q
//    private BigInteger e;      // Public exponent     
//    private BigInteger d;      // Private exponent
	private BigInteger rk;  // base64 of exponent:module
	private BigInteger rn;
	private int chunkSize; // 块大小
	
	public RSAAlgorithm(byte[] key) {  // base64("e n").getbytes()
    	String base64EspaceN = new String(key);
    	String[] keyParts = base64EspaceN.split(" ");
    	rk = utils.Utils.base64ToBigInteger(keyParts[0]);  // 这里e 和 d 统一表示为rk
    	rn = utils.Utils.base64ToBigInteger(keyParts[1]);
    	// System.out.println(rk + " " + rn);
    	chunkSize = rn.bitLength() / 8 - 1; // 默认加密块大
	}
    
    // 单块加密
    public byte[] encryptSingleChunk(byte[] data) {  // 加密
    	BigInteger inputMessage = new BigInteger(1, data);  // 防止负数处理
    	BigInteger outputResult = inputMessage.modPow(rk, rn);
    	return outputResult.toByteArray();
    }
    
    // 单块解密
    public byte[] decryptSingleChunk(byte[] data) {  // 解密
    	BigInteger inputMessage = new BigInteger(1, data);
    	BigInteger outputResult = inputMessage.modPow(rk, rn);
    	return outputResult.toByteArray();
    }
    
    // 分块加密
    public byte[] encrypt(byte[] data) {
        int maxChunkSize = chunkSize; // 最大块大小（根据密钥位数计算）
        List<byte[]> encryptedChunks = new ArrayList<>();

        for (int offset = 0; offset < data.length; offset += maxChunkSize) {
            int chunkLength = Math.min(maxChunkSize, data.length - offset);
            byte[] chunk = new byte[chunkLength];
            System.arraycopy(data, offset, chunk, 0, chunkLength);

            // 加密每个块
            byte[] encryptedChunk = encryptSingleChunk(chunk);

            // 在块前添加长度前缀
            byte[] prefixedChunk = new byte[4 + encryptedChunk.length];
            System.arraycopy(intToBytes(encryptedChunk.length), 0, prefixedChunk, 0, 4);
            System.arraycopy(encryptedChunk, 0, prefixedChunk, 4, encryptedChunk.length);

            encryptedChunks.add(prefixedChunk);
        }

        return mergeChunks(encryptedChunks);
    }
    
    
    // 分块解密
    public byte[] decrypt(byte[] encryptedData) {
        List<byte[]> decryptedChunks = new ArrayList<>();
        int offset = 0;

        while (offset < encryptedData.length) {
            // 读取长度前缀（4 字节）
            int encryptedChunkLength = bytesToInt(encryptedData, offset);
            offset += 4;

            // 提取当前块的密文
            byte[] encryptedChunk = new byte[encryptedChunkLength];
            System.arraycopy(encryptedData, offset, encryptedChunk, 0, encryptedChunkLength);
            offset += encryptedChunkLength;

            // 解密块
            byte[] decryptedChunk = decryptSingleChunk(encryptedChunk);
            decryptedChunks.add(decryptedChunk);
        }

        return mergeChunks(decryptedChunks);
    }
    
    // 整数转为字节数组（4 字节）
    private byte[] intToBytes(int value) {
        return new byte[] {
            (byte) (value >>> 24),
            (byte) (value >>> 16),
            (byte) (value >>> 8),
            (byte) value
        };
    }

    // 从字节数组读取整数（4 字节）
    private int bytesToInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24) |
               ((data[offset + 1] & 0xFF) << 16) |
               ((data[offset + 2] & 0xFF) << 8) |
               (data[offset + 3] & 0xFF);
    }
    
    
    // 辅助方法：合并多个字节数组
    private byte[] mergeChunks(List<byte[]> chunks) {
        int totalLength = chunks.stream().mapToInt(chunk -> chunk.length).sum();
        byte[] result = new byte[totalLength];
        int offset = 0;

        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, result, offset, chunk.length);
            offset += chunk.length;
        }

        return result;
    }

    
    // 加密方法
    public static BigInteger encrypt(BigInteger plaintext, BigInteger e, BigInteger n) {
        return plaintext.modPow(e, n);
    }

    // 解密方法
    public static BigInteger decrypt(BigInteger ciphertext, BigInteger d, BigInteger n) {
        return ciphertext.modPow(d, n);
    }
    

    // 辅助方法：添加填充字节，确保块大小固定
    private static void addPaddedBytes(List<Byte> target, byte[] chunk, int blockSize) {
        int paddingSize = blockSize - chunk.length;
        for (int i = 0; i < paddingSize; i++) {
            target.add((byte) 0x00);
        }
        for (byte b : chunk) {
            target.add(b);
        }
    }

    // 辅助方法：去除填充字节
    private static List<Byte> removePadding(byte[] chunk) {
        List<Byte> result = new ArrayList<>();
        boolean started = false;
        for (byte b : chunk) {
            if (b != 0 || started) {
                started = true;
                result.add(b);
            }
        }
        return result;
    }
    
 // 密钥生成
    public static BigInteger[] RSAKeyGenerate(int bitLength) {
        SecureRandom random = new SecureRandom();

        // 生成两个大质数 p 和 q
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);

        // 计算 n = p * q,RSA算法中n为公钥
        BigInteger n = p.multiply(q);

        // 计算 φ(n) = (p-1) * (q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // 公开指数 e，使得 gcd(e, φ(n)) = 1，为了快速加密，常使用65537
        BigInteger e = BigInteger.valueOf(65537); // 常用的公钥指数

        // 计算私钥 d，使得 d * e ≡ 1 (mod φ(n))
        BigInteger d = e.modInverse(phi);
        BigInteger[] rsaKeys = new BigInteger[]{e, d, n};
        return rsaKeys;
    }

    public static void main(String[] args) {
        // 创建 RSA 实例，密钥长度为 2048 位
//    	BigInteger[] rsaKeys = RSAAlgorithm.RSAKeyGenerate(2048);
//    	BigInteger e = rsaKeys[0];
//    	BigInteger d = rsaKeys[1];
//    	BigInteger n = rsaKeys[2];
//
//
//        // 原始消息
//        String message = "Hello, RSA!";
//        BigInteger plaintext = new BigInteger(message.getBytes());
//
//        // 加密
//        BigInteger ciphertext = RSAAlgorithm.encrypt(plaintext, e, n);
//        System.out.println("Encrypted message: " + ciphertext);
//
//        // 解密
//        BigInteger decrypted = RSAAlgorithm.decrypt(ciphertext, d, n);
//        String decryptedMessage = new String(decrypted.toByteArray());
//        System.out.println("Decrypted message: " + decryptedMessage);
    	unitTest();

    }
    
    public static String repeatString(String str, int count) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < count; i++) {
            builder.append(str);
        }
        return builder.toString();
    }
    
    // 测试代码
    public static void unitTest() {
        // 创建 RSA 实例，密钥长度为 2048 位
        BigInteger[] rsaKeys = RSAAlgorithm.RSAKeyGenerate(2048);
        BigInteger e = rsaKeys[0];
        BigInteger d = rsaKeys[1];
        BigInteger n = rsaKeys[2];
        System.out.print("e:" + e + "\nd:" + d + "\nn:" + n + "\n");
        String ek = utils.Utils.bigIntegerToBase64(e);
        String nk = utils.Utils.bigIntegerToBase64(n);
        String dk = utils.Utils.bigIntegerToBase64(d);

        // 原始大数据
        String largeMessage = repeatString("This is a very large message!", 100); // 模拟大数据
        // String largeMessage = "Hello RSA!";
        byte[] largeData = largeMessage.getBytes();
        System.out.println("Original data length: " + largeData.length);
        
        // 构造 RSAAlgorithm 实例
        RSAAlgorithm rsaAlgorithm = new RSAAlgorithm((ek + " " + nk).getBytes());
        // 分块加密
        byte[] encryptedData = rsaAlgorithm.encrypt(largeData);
        System.out.println("Encrypted data length: " + encryptedData.length);

        // 分块解密
        RSAAlgorithm rsaDecryptor = new RSAAlgorithm((dk + " " + nk).getBytes());
        byte[] decryptedData = rsaDecryptor.decrypt(encryptedData);
        System.out.println("Decrypted data length: " + decryptedData.length);

        // 验证解密结果
        String decryptedMessage = new String(decryptedData);
        System.out.println("Decryption success: " + decryptedMessage.equals(largeMessage));
    }
}