package cipher;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAAlgorithm {
//    private BigInteger n;      // n = p * q
//    private BigInteger e;      // Public exponent     
//    private BigInteger d;      // Private exponent

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
    
//    public RSAAlgorithm() {
//    	BigInteger[] keyPair = RSAKeyGenerate(2048);
//    	n = keyPair[0];
//    	d = keyPair[1];
//    }

    // 加密方法
    public BigInteger encrypt(BigInteger plaintext, BigInteger e, BigInteger n) {
        return plaintext.modPow(e, n);
    }

    // 解密方法
    public BigInteger decrypt(BigInteger ciphertext, BigInteger d, BigInteger n) {
        return ciphertext.modPow(d, n);
    }


    public static void main(String[] args) {
        // 创建 RSA 实例，密钥长度为 2048 位
    	BigInteger[] rsaKeys = RSAAlgorithm.RSAKeyGenerate(2048);
    	BigInteger e = rsaKeys[0];
    	BigInteger d = rsaKeys[1];
    	BigInteger n = rsaKeys[2];
        RSAAlgorithm rsa = new RSAAlgorithm();


        // 原始消息
        String message = "Hello, RSA!";
        BigInteger plaintext = new BigInteger(message.getBytes());

        // 加密
        BigInteger ciphertext = rsa.encrypt(plaintext, e, n);
        System.out.println("Encrypted message: " + ciphertext);

        // 解密
        BigInteger decrypted = rsa.decrypt(ciphertext, d, n);
        String decryptedMessage = new String(decrypted.toByteArray());
        System.out.println("Decrypted message: " + decryptedMessage);
    }
}