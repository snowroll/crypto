import java.util.Arrays;

public class AESCBC {
    private static final int BLOCK_SIZE = 16;
    private byte[] key;
    private byte[] iv;

    public AESCBC(byte[] key, byte[] iv) {
        if (key.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("Key must be 16 bytes (128 bits).");
        }
        if (iv.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("IV must be 16 bytes (128 bits).");
        }
        this.key = key;
        this.iv = iv;
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

    // AES 加密单个块
    private byte[] encryptBlock(byte[] block) {
        AESAlgorithm aes = new AESAlgorithm(key);
        return aes.encrypt(block);
    }

    // AES 解密单个块
    private byte[] decryptBlock(byte[] block) {
        AESAlgorithm aes = new AESAlgorithm(key);
        return aes.decrypt(block);
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
        byte[] key = "1234567890abcdef".getBytes();
        byte[] iv = "abcdef1234567890".getBytes();
        byte[] plaintext = "Hello, AES-CBC mode!".getBytes();

        AESCBC aesCbc = new AESCBC(key, iv);

        byte[] encrypted = aesCbc.encrypt(plaintext);
        System.out.println("Encrypted: " + Arrays.toString(encrypted));

        byte[] decrypted = aesCbc.decrypt(encrypted);
        System.out.println("Decrypted: " + new String(decrypted));
    }
}