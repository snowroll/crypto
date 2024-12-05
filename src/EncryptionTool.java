import javax.swing.*;

import cipher.EncryptionAlgorithm;
import cipher.EncryptionAlgorithmFactory;
import cipher.RSAAlgorithm;
import cipher.CBC;
import Hash.MD5;
import Hash.SHA1;
import utils.RandomKey;
import utils.Utils;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;

// todo
// 1. 密钥加密传输还没搞
// 2. 密钥生成的随机种子问题

public class EncryptionTool {
	private static String inputType = "String";

    public static void main(String[] args) {
        SwingUtilities.invokeLater(EncryptionTool::createAndShowGUI);
    }
    
    public static void showResult(String Result, String type) {
        // 创建弹出窗口
    	String typeString;
    	if (type.equals("encrypt")) {
    		typeString = "加密";
    	} else if (type.equals("decrypt")) {
    		typeString = "解密";
    	} else {
    		typeString = "密钥加密";
    	}
        JFrame frame = new JFrame(typeString + "结果");
        frame.setSize(400, 200);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setLocationRelativeTo(null);

        // 设置窗口布局
        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout(10, 10));

        // 添加加密结果文本框（不可编辑）
        JTextArea resultTextArea = new JTextArea(Result);
        resultTextArea.setEditable(false);
        resultTextArea.setLineWrap(true);
        resultTextArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(resultTextArea);
        panel.add(scrollPane, BorderLayout.CENTER);

        // 添加复制按钮
        JButton copyButton = new JButton("复制到剪切板");
        copyButton.addActionListener(e -> {
            // 将加密结果复制到剪切板
            StringSelection selection = new StringSelection(Result);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, null);

            // 提示已复制
            JOptionPane.showMessageDialog(frame, typeString + "结果已复制到剪切板！");
        });

        panel.add(copyButton, BorderLayout.SOUTH);

        // 显示窗口
        frame.add(panel);
        frame.setVisible(true);
    }
    
    public static void saveEncryptionFile(byte[] Message, String type) {
    	String typeString;
    	if (type.equals("encrypt")) {
    		typeString = "加密";
    	} else {
    		typeString = "解密";
    	}
    	
	    JFileChooser fileChooser = new JFileChooser();
	    fileChooser.setDialogTitle("选择保存文件的路径");
	    if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
	        File saveFile = fileChooser.getSelectedFile();  // 获取用户选择的保存路径
	        try {
	            Files.write(saveFile.toPath(), Message);
	            JOptionPane.showMessageDialog(null, typeString + "文件已保存到:\n" + saveFile.getAbsolutePath(),
	                                          "保存成功", JOptionPane.INFORMATION_MESSAGE);
	        } catch (IOException e) {
	            // 异常处理
	            JOptionPane.showMessageDialog(null, "保存文件失败: " + e.getMessage(), 
	                                          "错误", JOptionPane.ERROR_MESSAGE);
	        }
	    }
    }
    
    public static void generateRSAKey() {
    	BigInteger[] rsaKeys = RSAAlgorithm.RSAKeyGenerate(2048); 
    	BigInteger e = rsaKeys[0];
    	BigInteger d = rsaKeys[1];
    	BigInteger n = rsaKeys[2];
    	
        // 弹框选择保存目录
        JFileChooser directoryChooser = new JFileChooser();
        directoryChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (directoryChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
            String directory = directoryChooser.getSelectedFile().getAbsolutePath();

            // 输入私钥名称
            String privateKeyName = JOptionPane.showInputDialog("请输入私钥文件名 (无需扩展名):");
            if (privateKeyName == null || privateKeyName.trim().isEmpty()) {
                JOptionPane.showMessageDialog(null, "私钥名称不能为空！");
                return;
            }
            
            try {
                // 生成文件路径
                String privateKeyPath = directory + "/" + privateKeyName + "";
                String publicKeyPath  = directory + "/" + privateKeyName + ".pub";

                // 公私钥写入文件
                Utils.writeRSAKeyToFile(publicKeyPath,  e, n, "PUBLIC KEY");
                Utils.writeRSAKeyToFile(privateKeyPath, d, n, "PRIVATE KEY");                 

                // 弹出提示框
                JOptionPane.showMessageDialog(null, 
                    "公私钥已生成:\n私钥: " + privateKeyPath + "\n公钥: " + publicKeyPath);

            } catch (IOException e1) {
                e1.printStackTrace();
                JOptionPane.showMessageDialog(null, 
                    "密钥写入文件失败: " + e1.getMessage(), 
                    "错误", 
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public static String computeHashString(String algorithm, byte[] data) {
    	String hashValue;
    	if (algorithm == "MD5") {
    		hashValue = MD5.computeHash(data);
    	}
    	else {
    		hashValue = SHA1.computeHash(data);
    	}
    	return hashValue;
    }
    
    public static void encryptionProcess(byte[] MessageBytes, String selectedEncryptionAlgorithm, 
    		String encryptionKey, String selectedHashAlgorithm, String sigurateKey, String keyEncrypt, String inputType) {
    	// hash签名计算
    	String hashValue = computeHashString(selectedHashAlgorithm, MessageBytes);
    	EncryptionAlgorithm hashCipher = EncryptionAlgorithmFactory.getAlgorithm("RSA", sigurateKey);
    	byte[] encryptedHash = hashCipher.encrypt(hashValue.getBytes());
    	print("encrypted hash", encryptedHash);
    	// 明文||HMAC
    	byte[] combinedMessageBytes = utils.Utils.joinWithBase64Separator(MessageBytes, encryptedHash, " ");
    	
    	EncryptionAlgorithm cipher = EncryptionAlgorithmFactory.getAlgorithm(selectedEncryptionAlgorithm, encryptionKey);
    	byte[] encryptedMessage = cipher.encrypt(combinedMessageBytes);
    	
    	if (inputType.equals("String")) {
    		String encryptedMessageBase64 = utils.Utils.byteArrayToBase64(encryptedMessage);
    		System.out.println("encrypted message:\n" + encryptedMessageBase64);
    		showResult(encryptedMessageBase64, "encrypt");
    	}
    	else {
    		saveEncryptionFile(encryptedMessage, "encrypt");
    	}    	
    	
    	// 加密密钥
    	EncryptionAlgorithm keyCipher = EncryptionAlgorithmFactory.getAlgorithm("RSA", keyEncrypt);
    	byte[] encryptedKey = keyCipher.encrypt(encryptionKey.getBytes());
    	String encryptedKeyBase64 = utils.Utils.byteArrayToBase64(encryptedKey);
    	showResult(encryptedKeyBase64, "key_encrypt");
    	
    	
    }
    
    public static void print(String prefix, byte[] data) {
    	String base64Data = utils.Utils.byteArrayToBase64(data);
    	System.out.println(prefix + ": " + base64Data); 
    }
    
    public static void decryptionProcess(byte[] inputMessageBytes, String selectedEncryptionAlgorithm, 
    		String encryptionKey, String selectedHashAlgorithm, String sigurateKey, String keyEncrypt, String inputType) {
    	// step1 解密密钥
    	EncryptionAlgorithm keyCipher = EncryptionAlgorithmFactory.getAlgorithm("RSA", keyEncrypt);
    	byte[] decryptKeyByte = utils.Utils.base64ToByteArray(encryptionKey);
    	String decryptKey = new String(keyCipher.decrypt(decryptKeyByte));
    	print("decrypted key", keyCipher.decrypt(decryptKeyByte));
    	
    	EncryptionAlgorithm cipher = EncryptionAlgorithmFactory.getAlgorithm(selectedEncryptionAlgorithm, decryptKey);
    	System.out.println(selectedEncryptionAlgorithm + " " + encryptionKey);
    	byte[] decryptedMessage = cipher.decrypt(inputMessageBytes);
    	System.out.println("decrypted key:\n" + encryptionKey);
    	System.out.println("decrypted combined message:\n" + (new String(decryptedMessage)));
    	
    	// step2 
    	byte[][] combinedMessages = utils.Utils.splitByBase64Separator(decryptedMessage, " ");
    	byte[] message = combinedMessages[0];
    	byte[] encryptedHash = combinedMessages[1];
    	print("decrypted hash", encryptedHash);
    	System.out.println(new String(message));
    	
    	
    	if (inputType.equals("String")) {
    		String decryptedResult = new String(message);
    		showResult(decryptedResult, "decrypt");
    	} else {
    		saveEncryptionFile(message, "decrypt");
    	}
    	
    	
    	// 校验hash值 todo here
    	EncryptionAlgorithm hashCipher = EncryptionAlgorithmFactory.getAlgorithm("RSA", sigurateKey);
    	byte[] decryptedHash = hashCipher.decrypt(encryptedHash);
    	String decryptedHashString = new String(decryptedHash);
    	String recomputedHash = computeHashString(selectedHashAlgorithm, message);
    	
    	System.out.print(decryptedHashString + "\n" + recomputedHash + "\n");
    	if (decryptedHashString.equals(recomputedHash)) {
    		System.out.print("it is good");
    	}
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("加密签名工具");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 600);
        frame.setLayout(new BorderLayout());

        // 输入设置面板
        JPanel inputPanel = new JPanel(new GridLayout(3, 2, 10, 10));
        inputPanel.setBorder(BorderFactory.createTitledBorder("输入设置"));

        JLabel inputTypeLabel = new JLabel("输入类型:");
        JComboBox<String> inputTypeCombo = new JComboBox<>(new String[]{"字符串", "文件"});
        JLabel inputContentLabel = new JLabel("输入内容:");
        JTextField inputContentField = new JTextField();
        JButton fileSelectButton = new JButton("选择文件");
        fileSelectButton.setEnabled(false); // 初始状态禁用

        inputPanel.add(inputTypeLabel);
        inputPanel.add(inputTypeCombo);
        inputPanel.add(inputContentLabel);
        inputPanel.add(inputContentField);
        inputPanel.add(new JLabel()); // 占位
        inputPanel.add(fileSelectButton);

        // 根据输入类型调整组件
        inputTypeCombo.addActionListener(e -> {
            if ("字符串".equals(inputTypeCombo.getSelectedItem())) {
                inputContentField.setEnabled(true);
                fileSelectButton.setEnabled(false);
                fileSelectButton.setText("选择文件");
                inputType = "String";
            } else {
                inputContentField.setEnabled(false);
                fileSelectButton.setEnabled(true);
                inputType = "File";
            }
        });

        fileSelectButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                fileSelectButton.setText(fileChooser.getSelectedFile().getAbsolutePath());
                fileSelectButton.setEnabled(false); // 禁用按钮以防修改
            }
        });     
        
        
        // hash设置面板        
        JPanel hashPanel = new JPanel(new GridLayout(1, 2, 10, 10));
        hashPanel.setBorder(BorderFactory.createTitledBorder("Hash算法"));
        JLabel hashAlgorithmLabel = new JLabel("选择Hash算法:");
        JComboBox<String> hashAlgorithmCombo = new JComboBox<>(new String[]{"SHA", "MD5"});
        hashPanel.add(hashAlgorithmLabel);
        hashPanel.add(hashAlgorithmCombo);
        
        
        // 签名设置面板
        JPanel signaturePanel = new JPanel(new GridLayout(1, 3, 10, 10));
        signaturePanel.setBorder(BorderFactory.createTitledBorder("数字签名设置"));
        JLabel signatureKeyLabel = new JLabel("数字签名密钥:");
        JTextField signatureKeyField = new JTextField();
        JButton importSignatureKeyButton = new JButton("导入密钥");
        
        signaturePanel.add(signatureKeyLabel);
        signaturePanel.add(signatureKeyField);
        signaturePanel.add(importSignatureKeyButton);
        importSignatureKeyButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            	String filePath = fileChooser.getSelectedFile().getAbsolutePath();
            	try {
					String keyString = Utils.loadRSAKey(filePath);
					signatureKeyField.setText(keyString);
				} catch (IOException e1) {
					e1.printStackTrace();
				}
            }
        });
        

        // 加密算法选择面板
        JPanel encryptionPanel = new JPanel(new GridLayout(4, 2, 10, 10));
        encryptionPanel.setBorder(BorderFactory.createTitledBorder("加密设置"));

        JLabel algorithmLabel = new JLabel("选择加密算法:");
        JComboBox<String> algorithmCombo = new JComboBox<>(new String[]{"DES", "AES", "RSA"});
        JLabel keyLabel = new JLabel("密钥输入:");
        JTextField keyField = new JTextField();
        JButton generateKeyButton = new JButton("生成密钥");
        JButton importKeyButton = new JButton("导入密钥");
        JButton generateRSAKeysButton = new JButton("生成公私钥对");

        encryptionPanel.add(algorithmLabel);
        encryptionPanel.add(algorithmCombo);
        encryptionPanel.add(keyLabel);
        encryptionPanel.add(keyField);
        encryptionPanel.add(generateKeyButton);
        encryptionPanel.add(importKeyButton);
        encryptionPanel.add(generateRSAKeysButton);
        
        algorithmCombo.addActionListener(e -> {
            String selectedAlgorithm = (String) algorithmCombo.getSelectedItem();
            boolean isSymmetric = !"RSA".equals(selectedAlgorithm); // 是否为对称加密

            generateKeyButton.setEnabled(isSymmetric); // 仅对称加密可生成密钥
            keyField.setText(""); // 清空密钥输入框
        });

        generateKeyButton.addActionListener(e -> {
        	String algorithm = (String) algorithmCombo.getSelectedItem();
        	long seed = 123456L;  // 随机种子
        	// long seed = System.currentTimeMillis();  // 当前时间戳作为种子

            if ("DES".equals(algorithm)) {
                String desKey = RandomKey.generateDESKey(seed); // 自定义的生成 DES 密钥的函数
                keyField.setText(desKey);
            } else if ("AES".equals(algorithm)) {
                String aesKey = RandomKey.generateAESKey(seed); // 自定义的生成 AES 密钥的函数
                keyField.setText(aesKey);
            } 
        });

        importKeyButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {                
                String filePath = fileChooser.getSelectedFile().getAbsolutePath();
            	try {
					String keyString = Utils.loadRSAKey(filePath);
					keyField.setText(keyString);
				} catch (IOException e1) {
					e1.printStackTrace();
				}
            	
            }
        });
        
        generateRSAKeysButton.addActionListener(e -> {
	      	generateRSAKey();
	    });      

        // 密钥分发设置面板        
        JPanel keyEncryptPanel = new JPanel(new GridLayout(1, 3, 10, 10));
        keyEncryptPanel.setBorder(BorderFactory.createTitledBorder("密钥加密设置"));

        JLabel keyEncryptLabel = new JLabel("密钥分发密钥:");
        JTextField keyEncryptField = new JTextField();
        JButton keyEncryptButton = new JButton("导入密钥");
        keyEncryptPanel.add(keyEncryptLabel);
        keyEncryptPanel.add(keyEncryptField);
        keyEncryptPanel.add(keyEncryptButton);
        
        keyEncryptButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            	String filePath = fileChooser.getSelectedFile().getAbsolutePath();
            	try {
					String keyString = Utils.loadRSAKey(filePath);
					keyEncryptField.setText(keyString);
				} catch (IOException e1) {
					e1.printStackTrace();
				}
            }
        });
        
        
        // 按钮面板
        JPanel buttonPanel = new JPanel();
        JButton encryptButton = new JButton("加密");
        JButton decryptButton = new JButton("解密");
        JButton clearButton = new JButton("清除");
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);
        buttonPanel.add(clearButton);

        encryptButton.addActionListener(e -> {
        	byte[] inputData;
        	if (inputType.equals("String")) {
        		String inputString = inputContentField.getText();
        		inputData = inputString.getBytes();      	
        	}
        	else {
        		String filePath = fileSelectButton.getText();
        	    try {
        	        inputData = Files.readAllBytes(Paths.get(filePath));
        	    } catch (IOException e1) {
        	        JOptionPane.showMessageDialog(null, "文件读取失败: " + e1.getMessage());
        	        inputData = new byte[0];  // 初始化为空字节数组，防止后续出错
        	    }
        		
        	}
        	
        	String selectedEncryptionAlgorithm = (String) algorithmCombo.getSelectedItem();
        	String encryptionKey = keyField.getText();
        	String selectedHashAlgorithm = (String) hashAlgorithmCombo.getSelectedItem();
        	String sigurateKey = signatureKeyField.getText();
        	String keyEncrypt = keyEncryptField.getText();	
        	encryptionProcess(inputData, selectedEncryptionAlgorithm, encryptionKey, selectedHashAlgorithm, sigurateKey, keyEncrypt, inputType);
        	
    	});
        
        
        decryptButton.addActionListener(e -> {
        	byte[] inputData;
        	if (inputType.equals("String")) {
        		String inputString = inputContentField.getText();
        		System.out.println("encrypted message:\n" + (new String(inputString)));
        		inputData = utils.Utils.base64ToByteArray(inputString);
        	}
        	else {
        		String filePath = fileSelectButton.getText();
        	    try {
        	        inputData = Files.readAllBytes(Paths.get(filePath));
        	    } catch (IOException e1) {
        	        JOptionPane.showMessageDialog(null, "文件读取失败: " + e1.getMessage());
        	        inputData = new byte[0];  // 初始化为空字节数组，防止后续出错
        	    }	
        	}
        	
        	String selectedEncryptionAlgorithm = (String) algorithmCombo.getSelectedItem();
        	String encryptionKey = keyField.getText();
        	String selectedHashAlgorithm = (String) hashAlgorithmCombo.getSelectedItem();
        	String sigurateKey = signatureKeyField.getText();
        	String keyEncrypt = keyEncryptField.getText();	
        	decryptionProcess(inputData, selectedEncryptionAlgorithm, encryptionKey, selectedHashAlgorithm, sigurateKey, keyEncrypt, inputType);
        });
        
        clearButton.addActionListener(e -> {
            inputContentField.setText("");
            fileSelectButton.setText("选择文件");
            fileSelectButton.setEnabled(false);
            keyField.setText("");
            signatureKeyField.setText("");
            keyEncryptField.setText("");
        });

        // 布局整体
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        
        mainPanel.add(inputPanel);
        mainPanel.add(hashPanel);
        mainPanel.add(signaturePanel);
        mainPanel.add(encryptionPanel);
        mainPanel.add(keyEncryptPanel);
        
        
        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        //scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        frame.add(scrollPane, BorderLayout.CENTER);
        frame.add(buttonPanel, BorderLayout.SOUTH);
        frame.setVisible(true);
    }
}