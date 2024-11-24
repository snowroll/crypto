package Cipher;
public interface EncryptionAlgorithm {
    // 加密方法
    byte[] encrypt(byte[] data) ;

    // 解密方法
    byte[] decrypt(byte[] data);
}