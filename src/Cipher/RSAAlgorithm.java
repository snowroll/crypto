package cipher;
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
    
    public RSAAlgorithm(byte[] key) {  // base64("e n").getbytes()
    	String base64EspaceN = new String(key);
    	String[] keyParts = base64EspaceN.split(" ");
    	System.out.println(keyParts[0]);
    	System.out.println(keyParts[1]);
    	rk = utils.Utils.base64ToBigInteger(keyParts[0]);  // 这里e 和 d 统一表示为rk
    	rn = utils.Utils.base64ToBigInteger(keyParts[1]);
    	chunkSize = 2048;
    }
    
    // 做统一适配
    public byte[] encrypt(byte[] data) {  // 加密
    	BigInteger inputMessage = new BigInteger(data);
    	BigInteger outputResult = inputMessage.modPow(rk, rn);
    	return outputResult.toByteArray();
    }
    
    
    public byte[] decrypt(byte[] data) {  // 解密
    	BigInteger inputMessage = new BigInteger(data);
    	BigInteger outputResult = inputMessage.modPow(rk, rn);
    	return outputResult.toByteArray();
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

    public static void main(String[] args) {
        // 创建 RSA 实例，密钥长度为 2048 位
    	BigInteger[] rsaKeys = RSAAlgorithm.RSAKeyGenerate(2048);
    	BigInteger e = rsaKeys[0];
    	BigInteger d = rsaKeys[1];
    	BigInteger n = rsaKeys[2];


        // 原始消息
        String message = "Hello, RSA!";
        BigInteger plaintext = new BigInteger(message.getBytes());

        // 加密
        BigInteger ciphertext = RSAAlgorithm.encrypt(plaintext, e, n);
        System.out.println("Encrypted message: " + ciphertext);

        // 解密
        BigInteger decrypted = RSAAlgorithm.decrypt(ciphertext, d, n);
        String decryptedMessage = new String(decrypted.toByteArray());
        System.out.println("Decrypted message: " + decryptedMessage);

    }
}