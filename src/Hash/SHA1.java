package Hash;
import java.awt.print.Printable;
import java.util.ArrayList;

public class SHA1 {

    private static final int[] H = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    };

    public static String sha1(String message) {
        byte[] messageBytes = message.getBytes();
        int[] paddedMessage = padMessage(messageBytes);
        printPaddedMessageHex(paddedMessage);
        int[] hash = H.clone();

        for (int i = 0; i < paddedMessage.length / 16; i++) {
            int[] w = new int[80];
            System.arraycopy(paddedMessage, i * 16, w, 0, 16);

            for (int t = 16; t < 80; t++) {
                w[t] = leftRotate(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
            }

            int a = hash[0];
            int b = hash[1];
            int c = hash[2];
            int d = hash[3];
            int e = hash[4];

            for (int t = 0; t < 80; t++) {
                int temp = leftRotate(a, 5) + f(t, b, c, d) + e + w[t] + k(t);
                e = d;
                d = c;
                c = leftRotate(b, 30);
                b = a;
                a = temp;
            }

            hash[0] += a;
            hash[1] += b;
            hash[2] += c;
            hash[3] += d;
            hash[4] += e;
        }

        StringBuilder hexString = new StringBuilder();
        for (int h : hash) {
            hexString.append(String.format("%08x", h));
        }
        return hexString.toString();
        
    }

    private static int[] padMessage(byte[] messageBytes) {
        long originalLength = messageBytes.length * 8;
        long paddedLength = ((originalLength + 64) / 512 + 1) * 512;
        long totalLength = paddedLength / 32;

        int[] paddedMessage = new int[(int)totalLength];  // 这里由于java数组创建的限制，只能处理小文件。 需要改进
        for (int i = 0; i < messageBytes.length; i++) {
            paddedMessage[i / 4] |= (messageBytes[i] & 0xFF) << (24 - (i % 4) * 8);
        }
        paddedMessage[messageBytes.length / 4] |= 0x80 << (24 - (messageBytes.length % 4) * 8);
        paddedMessage[(int)totalLength - 2] = (int) (originalLength >> 32);
        paddedMessage[(int)totalLength - 1] = (int) originalLength;

        return paddedMessage;
    }
    
    private static void printPaddedMessageHex(int[] paddedMessage) {
        for (int i = 0; i < paddedMessage.length; i++) {
            // 将每个int格式化为8位16进制
            System.out.printf("%08x ", paddedMessage[i]);
            // 可选：每4个int换行，方便查看
            if ((i + 1) % 4 == 0) {
                System.out.println();
            }
        }
    }
    

    private static int leftRotate(int value, int bits) {
        return (value << bits) | (value >>> (32 - bits));
    }

    private static int f(int t, int b, int c, int d) {
        if (t < 20) return (b & c) | ((~b) & d);
        if (t < 40) return b ^ c ^ d;
        if (t < 60) return (b & c) | (b & d) | (c & d);
        return b ^ c ^ d;
    }

    private static int k(int t) {
        if (t < 20) return 0x5A827999;
        if (t < 40) return 0x6ED9EBA1;
        if (t < 60) return 0x8F1BBCDC;
        return 0xCA62C1D6;
    }

    public static void main(String[] args) {
        String text = "Hello, world!";
        
        String sha1Hash = sha1(text);
        System.out.println("SHA-1 Hash: " + sha1Hash);
    }
}