import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAAlgorithm {
    private BigInteger n;      // n = p * q
    private BigInteger e;      // Public exponent
    private BigInteger d;      // Private exponent

    // 密钥生成
    public RSAAlgorithm(int bitLength) {
        SecureRandom random = new SecureRandom();

        // 生成两个大质数 p 和 q
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);

        // 计算 n = p * q
        n = p.multiply(q);

        // 计算 φ(n) = (p-1) * (q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // 选择公钥 e，使得 gcd(e, φ(n)) = 1
        e = BigInteger.valueOf(65537); // 常用的公钥指数

        // 计算私钥 d，使得 d * e ≡ 1 (mod φ(n))
        d = e.modInverse(phi);
    }

    // 加密方法
    public BigInteger encrypt(BigInteger plaintext) {
        return plaintext.modPow(e, n);
    }

    // 解密方法
    public BigInteger decrypt(BigInteger ciphertext) {
        return ciphertext.modPow(d, n);
    }

    // 获取公钥
    public BigInteger getPublicKey() {
        return e;
    }

    // 获取模数 n
    public BigInteger getModulus() {
        return n;
    }

    public static void main(String[] args) {
        // 创建 RSA 实例，密钥长度为 2048 位
        RSAAlgorithm rsa = new RSAAlgorithm(2048);

        // 打印公钥和模数
        System.out.println("Public Key (e): " + rsa.getPublicKey());
        System.out.println("Modulus (n): " + rsa.getModulus());

        // 原始消息
        String message = "Hello, RSA!";
        BigInteger plaintext = new BigInteger(message.getBytes());

        // 加密
        BigInteger ciphertext = rsa.encrypt(plaintext);
        System.out.println("Encrypted message: " + ciphertext);

        // 解密
        BigInteger decrypted = rsa.decrypt(ciphertext);
        String decryptedMessage = new String(decrypted.toByteArray());
        System.out.println("Decrypted message: " + decryptedMessage);
    }
}