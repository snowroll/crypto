import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import Cipher.CBC;

import java.util.Arrays;
import java.util.Base64;

public class UnitTest {
	/*
    public static void main(String[] args) {
        // 测试数据
        byte[] key = "abcdef1234567890".getBytes();
        byte[] iv = "abcdef1234567890".getBytes();
        byte[] plaintext = "Hello World!".getBytes();

        // 使用自定义 CBC 类进行加密
        CBC aesCbc = new CBC(key, iv);
        byte[] encryptedCustom = aesCbc.encrypt(plaintext);
        System.out.println("Custom CBC Encrypted: " + Arrays.toString(encryptedCustom));

        // 使用 Java 内置的 AES CBC 加密进行验证
        try {
            byte[] encryptedJava = encryptWithJavaAES(key, iv, plaintext);
            System.out.println("Java AES Encrypted: " + Arrays.toString(encryptedJava));

            // 检查结果是否一致
            if (Arrays.equals(encryptedCustom, encryptedJava)) {
                System.out.println("Encryption results match!");
            } else {
                System.out.println("Encryption results do not match!");
            }

            // 验证解密结果
            byte[] decryptedCustom = aesCbc.decrypt(encryptedCustom);
            System.out.println("Decrypted Text: " + new String(decryptedCustom));

            if (Arrays.equals(plaintext, decryptedCustom)) {
                System.out.println("Decryption successful. Plaintext matches.");
            } else {
                System.out.println("Decryption failed. Plaintext does not match.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    */

    // 使用 Java 内置 AES CBC 模式进行加密
    private static byte[] encryptWithJavaAES(byte[] key, byte[] iv, byte[] plaintext) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        return cipher.doFinal(plaintext);
    }
    
    public static void main(String[] args) {
        // 测试数据
        byte[] key = "12345678".getBytes();
        byte[] iv = "12345678".getBytes();
        byte[] plaintext = "Hello World!".getBytes();

        // 测试 AES CBC
        CBC aesCbc = new CBC("DES", key);
        testEncryption(aesCbc, "DES", key, plaintext);
    }

    /**
     * 验证自定义加密类与 Java 内置加密是否一致。
     */
    private static void testEncryption(CBC customCipher, String algorithm, byte[] key,  byte[] plaintext) {
    	byte[] iv = "12345678".getBytes();
    	if (algorithm == "AES") {
    		iv = "1234567890abcdef".getBytes();
    	}
    	
        System.out.println("\nTesting " + algorithm + " CBC Mode:");

        // 使用自定义 CBC 类进行加密
        byte[] encryptedCustom = customCipher.encrypt(plaintext);
        System.out.println("Custom CBC Encrypted: " + Arrays.toString(encryptedCustom));

        // 使用 Java 内置的 AES CBC 加密进行验证
        try {
            byte[] encryptedJava = encryptWithJavaCipher(algorithm, key, iv, plaintext);
            System.out.println("Java Cipher Encrypted: " + Arrays.toString(encryptedJava));

            // 检查加密结果是否一致
            if (Arrays.equals(encryptedCustom, encryptedJava)) {
                System.out.println("Encryption results match!");
            } else {
                System.out.println("Encryption results do not match!");
            }

            // 验证解密结果
            byte[] decryptedCustom = customCipher.decrypt(encryptedCustom);
            System.out.println("Decrypted Text: " + new String(decryptedCustom));

            if (Arrays.equals(plaintext, decryptedCustom)) {
                System.out.println("Decryption successful. Plaintext matches.");
            } else {
                System.out.println("Decryption failed. Plaintext does not match.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 使用 Java 内置 Cipher 类进行 AES CBC 加密。
     */
    private static byte[] encryptWithJavaCipher(String algorithm, byte[] key, byte[] iv, byte[] plaintext) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, algorithm);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        return cipher.doFinal(plaintext);
    }
}