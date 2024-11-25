package cipher;

public class EncryptionAlgorithmFactory {
    public static EncryptionAlgorithm getAlgorithm(String algorithmName, String key) {
        switch (algorithmName.toUpperCase()) {
            case "DES":
                return new CBC(algorithmName, key.getBytes());
            case "AES":
                return new CBC(algorithmName, key.getBytes());
            case "RSA":
            	return new RSAAlgorithm(key.getBytes());
            // Future algorithms can be added here
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithmName);
        }
    }
}