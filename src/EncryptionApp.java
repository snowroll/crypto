import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.util.Base64;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;

public class EncryptionApp extends JFrame {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private JTextField inputText;
    private JTextField keyField;
    private JTextArea outputArea;
    private JComboBox<String> algorithmComboBox;
    private JFileChooser fileChooser;

    public EncryptionApp() {
        setTitle("Encryption App");
        setSize(500, 400);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        // Input Panel
        JPanel inputPanel = new JPanel(new GridLayout(4, 2));
        inputPanel.add(new JLabel("Input Text/File Path:"));
        inputText = new JTextField();
        inputPanel.add(inputText);

        inputPanel.add(new JLabel("Encryption Key:"));
        keyField = new JTextField();
        inputPanel.add(keyField);

        inputPanel.add(new JLabel("Select Algorithm:"));
        algorithmComboBox = new JComboBox<>(new String[]{"DES", "AES"});
        inputPanel.add(algorithmComboBox);

        JButton chooseFileButton = new JButton("Choose File");
        inputPanel.add(chooseFileButton);

        add(inputPanel, BorderLayout.NORTH);

        // Output Area
        outputArea = new JTextArea();
        outputArea.setLineWrap(true);
        add(new JScrollPane(outputArea), BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel();
        JButton encryptButton = new JButton("Encrypt");
        JButton decryptButton = new JButton("Decrypt");
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);
        add(buttonPanel, BorderLayout.SOUTH);

        fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new FileNameExtensionFilter("Text Files", "txt"));

        // Action Listeners
        chooseFileButton.addActionListener(e -> {
            int returnValue = fileChooser.showOpenDialog(this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                inputText.setText(selectedFile.getAbsolutePath());
            }
        });

        encryptButton.addActionListener(e -> {
            String algorithm = (String) algorithmComboBox.getSelectedItem();
            String input = inputText.getText();
            String key = keyField.getText();

            try {
                if (new File(input).exists()) {
                    File file = new File(input);
                    byte[] encryptedFile = encryptFile(algorithm, key, file);
                    Files.write(new File(file.getParent(), file.getName() + ".enc").toPath(), encryptedFile);
                    outputArea.setText("File encrypted successfully. Encrypted file saved as: " + file.getName() + ".enc");
                } else {
                    String encryptedText = encryptText(algorithm, key, input);
                    print("encrypt done!");
                    outputArea.setText("Encrypted Text: \n" + encryptedText);
                }
            } catch (Exception ex) {
                outputArea.setText("Error: " + ex.getMessage());
            }
        });

        decryptButton.addActionListener(e -> {
            String algorithm = (String) algorithmComboBox.getSelectedItem();
            String input = inputText.getText();
            String key = keyField.getText();

            try {
                if (new File(input).exists()) {
                    File file = new File(input);
                    byte[] decryptedFile = decryptFile(algorithm, key, file);
                    Files.write(new File(file.getParent(), file.getName().replace(".enc", ".dec")).toPath(), decryptedFile);
                    outputArea.setText("File decrypted successfully. Decrypted file saved as: " + file.getName().replace(".enc", ".dec"));
                } else {
                    String decryptedText = decryptText(algorithm, key, input);
                    outputArea.setText("Decrypted Text: \n" + decryptedText);
                }
            } catch (Exception ex) {
                outputArea.setText("Error: " + ex.getMessage());
            }
        });
    }

    // Encryption for text
    private String encryptText(String algorithm, String key, String input) throws Exception {
        EncryptionAlgorithm cipher = initCipher(algorithm, key);
        byte[] encrypted = cipher.encrypt(input.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decryption for text
    private String decryptText(String algorithm, String key, String input) throws Exception {
    	EncryptionAlgorithm cipher = initCipher(algorithm, key);
        byte[] decrypted = cipher.decrypt(Base64.getDecoder().decode(input));
        return new String(decrypted);
    }

    // Encryption for files
    private byte[] encryptFile(String algorithm, String key, File inputFile) throws Exception {
        Object cipher = initCipher(algorithm, key, Cipher.ENCRYPT_MODE);
        byte[] fileData = Files.readAllBytes(inputFile.toPath());
        return cipher.doFinal(fileData);
    }

    // Decryption for files
    private byte[] decryptFile(String algorithm, String key, File inputFile) throws Exception {
        EncryptionAlgorithm cipher = initCipher(algorithm, key);
        byte[] fileData = Files.readAllBytes(inputFile.toPath());
        return cipher.decrypt(fileData);
    }

    // Initialize Cipher with the chosen algorithm and key
    // 从这里开始修改
    private EncryptionAlgorithm initCipher(String algorithm, String key) throws Exception {
    	String encrypted = "";
    	if (algorithm == "DES") {
    		CBC Cbc = new CBC("DES", key.getBytes()); 
    		return Cbc;
    	}
    	else if (algorithm == "AES") {
    		CBC Cbc = new CBC("AES", key.getBytes()); 
    		return Cbc;
    	}
    	// todo here
        SecretKey secretKey = new SecretKeySpec(formatKey(algorithm, key), algorithm);
        DESAlgorithm tmp = new DESAlgorithm(key.getBytes());
        return tmp;
    }
    
    
    // Format key to required size
    private byte[] formatKey(String algorithm, String key) {
        int keyLength = algorithm.equals("AES") ? 16 : 8;
        byte[] keyBytes = new byte[keyLength];
        System.arraycopy(key.getBytes(), 0, keyBytes, 0, Math.min(key.length(), keyLength));
        return keyBytes;
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            EncryptionApp app = new EncryptionApp();
            app.setVisible(true);
        });
    }
    
    public static void print(String text) {
    	System.out.print(text);
    }
}