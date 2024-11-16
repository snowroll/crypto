import java.awt.print.Printable;
import java.nio.file.attribute.AclEntry;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class CBC implements EncryptionAlgorithm {
    private int BLOCK_SIZE = 16;
    private byte[] key;
    private byte[] iv;
    private EncryptionAlgorithm encryptor;

    public CBC(String algorithm, byte[] key) {
    	 // 根据算法名称动态设置 BLOCK_SIZE
        switch (algorithm.toUpperCase()) {
            case "AES":
                this.BLOCK_SIZE = 16; // AES 使用 16 字节块大小（128 位）
                this.iv = "1234567890abcdef".getBytes();
                break;
            case "DES":
                this.BLOCK_SIZE = 8; // DES 使用 8 字节块大小（64 位）
                this.iv = "12345678".getBytes();
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
        
        // 处理密钥长度
        this.key = formatKey(key, this.BLOCK_SIZE);
        //this.iv = generateRandomIV();
        // 处理 IV 长度
//        if (iv == null || iv.length != this.BLOCK_SIZE) {
//            throw new IllegalArgumentException("IV must be " + this.BLOCK_SIZE + " bytes.");
//        }
//        this.iv = iv;
        
        switch (algorithm.toUpperCase()) {
	        case "AES":
	            encryptor = new AESAlgorithm(this.key);
	            break;
	        case "DES":
	        	encryptor = new DESAlgorithm(this.key);
	            break;
        }
    }
    
    public CBC(byte[] key, byte[] iv) {
        if (key.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("Key must be 16 bytes (128 bits).");
        }
        if (iv.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("IV must be 16 bytes (128 bits).");
        }
        this.key = key;
        this.iv = iv;
        this.encryptor = new AESAlgorithm(this.key);
    }
    

    // 格式化密钥（填充或截断）
    private byte[] formatKey(byte[] key, int length) {
        byte[] formattedKey = new byte[length];
        if (key.length >= length) {
            // 如果密钥长度过长，截断
            System.arraycopy(key, 0, formattedKey, 0, length);
        } else {
            // 如果密钥长度不足，填充零
            System.arraycopy(key, 0, formattedKey, 0, key.length);
            for (int i = key.length; i < length; i++) {
                formattedKey[i] = 0x00;
            }
        }
        return formattedKey;
    }
    
    // 随机生成偏移量
    private byte[] generateIV(int length) {
        byte[] formattedKey = new byte[length];
        if (key.length >= length) {
            // 如果密钥长度过长，截断
            System.arraycopy(key, 0, formattedKey, 0, length);
        } else {
            // 如果密钥长度不足，填充零
            System.arraycopy(key, 0, formattedKey, 0, key.length);
            for (int i = key.length; i < length; i++) {
                formattedKey[i] = 0x00;
            }
        }
        return formattedKey;
    }

    // PKCS#7 填充
    private byte[] pad(byte[] data) {
        int paddingLength = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = Arrays.copyOf(data, data.length + paddingLength);
        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLength;
        }
        return padded;
    }

    // 移除 PKCS#7 填充
    private byte[] unpad(byte[] data) {
        int paddingLength = data[data.length - 1];
        return Arrays.copyOf(data, data.length - paddingLength);
    }

    // XOR 操作
    private byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }
    
    // 使用随机 IV
    private byte[] generateRandomIV() {
        byte[] randomIV = new byte[BLOCK_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(randomIV);
        return randomIV;
    }

    // 加密单个块
    private byte[] encryptBlock(byte[] block) {
    	return encryptor.encrypt(block);
    }

    // 解密单个块
    private byte[] decryptBlock(byte[] block)  {
    	return encryptor.decrypt(block);
    }

    // CBC 加密
    public byte[] encrypt(byte[] plaintext) {
        plaintext = pad(plaintext);
        byte[] ciphertext = new byte[plaintext.length];
        byte[] previousBlock = iv;
        for (int i = 0; i < plaintext.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(plaintext, i, i + BLOCK_SIZE);
            byte[] xoredBlock = xor(block, previousBlock);
            byte[] encryptedBlock = encryptBlock(xoredBlock);
            System.arraycopy(encryptedBlock, 0, ciphertext, i, BLOCK_SIZE);
            previousBlock = encryptedBlock;
        }

        return ciphertext;
    }

    // CBC 解密
    public byte[] decrypt(byte[] ciphertext) {
        byte[] plaintext = new byte[ciphertext.length];
        byte[] previousBlock = iv;

        for (int i = 0; i < ciphertext.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(ciphertext, i, i + BLOCK_SIZE);
            byte[] decryptedBlock = decryptBlock(block);
            byte[] xoredBlock = xor(decryptedBlock, previousBlock);
            System.arraycopy(xoredBlock, 0, plaintext, i, BLOCK_SIZE);
            previousBlock = block;
        }

        return unpad(plaintext);
    }

    public static void main(String[] args) {
        // 测试
        byte[] key = "abcdef1234567890".getBytes();
        byte[] iv = "12345678".getBytes();
        //byte[] iv = "12345678".getBytes();
        byte[] plaintext = "Hello world!".getBytes();

        CBC Cbc = new CBC("AES", key);

        byte[] encrypted = Cbc.encrypt(plaintext);
        // System.out.println("Encrypted: " + Arrays.toString(encrypted));
        String ciphertextBase64 = Base64.getEncoder().encodeToString(encrypted);
		System.out.println("Encrypted (Base64): " + ciphertextBase64);

        byte[] decrypted = Cbc.decrypt(encrypted);
        System.out.println("Decrypted: " + new String(decrypted));
    }
}