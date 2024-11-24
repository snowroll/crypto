import javax.swing.*;

import cipher.EncryptionAlgorithm;
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
import java.io.IOException;
import java.math.BigInteger;
import java.util.Base64;
import java.util.HashMap;


// todo
// 1. 已修改公私钥存储结构，修改导入方式
// 2. 加密hash的解密仍然有问题，修改
// 3. 抽象逻辑为函数
// 4. 密钥加密传输还没搞

public class EncryptionTool {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(EncryptionTool::createAndShowGUI);
    }
    
    public static void showEncryptionResult(String encryptedResult) {
        // 创建弹出窗口
        JFrame frame = new JFrame("加密结果");
        frame.setSize(400, 200);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setLocationRelativeTo(null);

        // 设置窗口布局
        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout(10, 10));

        // 添加加密结果文本框（不可编辑）
        JTextArea resultTextArea = new JTextArea(encryptedResult);
        resultTextArea.setEditable(false);
        resultTextArea.setLineWrap(true);
        resultTextArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(resultTextArea);
        panel.add(scrollPane, BorderLayout.CENTER);

        // 添加复制按钮
        JButton copyButton = new JButton("复制到剪切板");
        copyButton.addActionListener(e -> {
            // 将加密结果复制到剪切板
            StringSelection selection = new StringSelection(encryptedResult);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, null);

            // 提示已复制
            JOptionPane.showMessageDialog(frame, "加密结果已复制到剪切板！");
        });

        panel.add(copyButton, BorderLayout.SOUTH);

        // 显示窗口
        frame.add(panel);
        frame.setVisible(true);
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
            } else {
                inputContentField.setEnabled(false);
                fileSelectButton.setEnabled(true);
            }
        });

        fileSelectButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                fileSelectButton.setText(fileChooser.getSelectedFile().getAbsolutePath());
                fileSelectButton.setEnabled(false); // 禁用按钮以防修改
            }
        });

        // 公私钥生成模块
        JPanel rsaPanel = new JPanel(new GridLayout(1, 2, 10, 10));
        rsaPanel.setBorder(BorderFactory.createTitledBorder("RSA公私钥生成"));
        JButton generateRSAKeysButton = new JButton("生成公私钥对");

        rsaPanel.add(new JLabel("操作:"));
        rsaPanel.add(generateRSAKeysButton);

        generateRSAKeysButton.addActionListener(e -> {
        	generateRSAKey();
        });
        

        // 加密算法选择面板
        JPanel encryptionPanel = new JPanel(new GridLayout(3, 2, 10, 10));
        encryptionPanel.setBorder(BorderFactory.createTitledBorder("加密设置"));

        JLabel algorithmLabel = new JLabel("选择加密算法:");
        JComboBox<String> algorithmCombo = new JComboBox<>(new String[]{"DES", "AES", "RSA"});
        JLabel keyLabel = new JLabel("密钥输入:");
        JTextField keyField = new JTextField();
        JButton generateKeyButton = new JButton("生成密钥");
        JButton importKeyButton = new JButton("导入密钥");

        encryptionPanel.add(algorithmLabel);
        encryptionPanel.add(algorithmCombo);
        encryptionPanel.add(keyLabel);
        encryptionPanel.add(keyField);
        encryptionPanel.add(generateKeyButton);
        encryptionPanel.add(importKeyButton);
        
        algorithmCombo.addActionListener(e -> {
            String selectedAlgorithm = (String) algorithmCombo.getSelectedItem();
            boolean isSymmetric = !"RSA".equals(selectedAlgorithm); // 是否为对称加密

            generateKeyButton.setEnabled(isSymmetric); // 仅对称加密可生成密钥
            keyField.setText(""); // 清空密钥输入框
        });

        generateKeyButton.addActionListener(e -> {
        	String algorithm = (String) algorithmCombo.getSelectedItem();
        	long seed = 123456L;  // 随机种子

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
                keyField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });

        // 签名设置面板        
        JPanel signaturePanel = new JPanel(new GridLayout(3, 3, 10, 10));
        signaturePanel.setBorder(BorderFactory.createTitledBorder("签名设置"));

        JLabel signatureAlgorithmLabel = new JLabel("选择Hash算法:");
        JComboBox<String> signatureAlgorithmCombo = new JComboBox<>(new String[]{"SHA", "MD5"});
        JLabel signatureKeyLabel0 = new JLabel("己方签名私钥:");
        JTextField signatureKeyField0 = new JTextField();
        JButton importSignatureKeyButton0 = new JButton("导入密钥");
        JLabel signatureKeyLabel1 = new JLabel("对方签名公钥:");
        JTextField signatureKeyField1 = new JTextField();
        JButton importSignatureKeyButton1 = new JButton("导入密钥");

        signaturePanel.add(signatureAlgorithmLabel);
        signaturePanel.add(new JLabel()); // 占位
        signaturePanel.add(signatureAlgorithmCombo);
        // 己方私钥
        signaturePanel.add(signatureKeyLabel0);
        signaturePanel.add(signatureKeyField0);
        signaturePanel.add(importSignatureKeyButton0);
        // 对方公钥
        signaturePanel.add(signatureKeyLabel1);
        signaturePanel.add(signatureKeyField1);
        signaturePanel.add(importSignatureKeyButton1);
        
        importSignatureKeyButton0.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            	String filePath = fileChooser.getSelectedFile().getAbsolutePath();
            	try {
					String keyString = Utils.loadRSAKey(filePath);
					signatureKeyField0.setText(keyString);
				} catch (IOException e1) {
					e1.printStackTrace();
				}
            }
        });
        importSignatureKeyButton1.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            	String filePath = fileChooser.getSelectedFile().getAbsolutePath();
            	try {
					String keyString = Utils.loadRSAKey(filePath);
					signatureKeyField1.setText(keyString);
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
        	String message = inputContentField.getText();
        	String encryptAlgorithm = (String)algorithmCombo.getSelectedItem();
        	String encryptKey = keyField.getText();
        	String hashAlgorithm = (String)signatureAlgorithmCombo.getSelectedItem();
        	String mySignatureKey = signatureKeyField0.getText();
        	String otherSignatureKey = signatureKeyField1.getText();
        	
        	// 计算md5
        	String hashValue;
        	byte[] msgBytes = message.getBytes();
        	
        	if (hashAlgorithm == "MD5") {
        		hashValue = MD5.computeHash(msgBytes);
        	}
        	else {
        		hashValue = SHA1.computeHash(msgBytes);
        	}
        	
            BigInteger hashBigInteger = new BigInteger(hashValue.getBytes());
            BigInteger RKa = utils.Utils.base64ToBigInteger(mySignatureKey);
            BigInteger UKa = utils.Utils.base64ToBigInteger(otherSignatureKey);
        	
        	RSAAlgorithm rsaCipher = new RSAAlgorithm();
        	BigInteger encryptedHash =  rsaCipher.encrypt(hashBigInteger, RKa, UKa);
        	BigInteger decryptedHash = rsaCipher.decrypt(encryptedHash, UKa, RKa);
        	String encryptedHashBase64 = utils.Utils.bigIntegerToBase64(encryptedHash);
        	String msgBase64 = utils.Utils.stringToBase64(message);
        	
        	System.out.println("Hash BigInteger: " + hashBigInteger.toString());
        	System.out.println("Hash BigInteger decryption: " + encryptedHash.toString());
        	//System.out.println("RKa: " + RKa.toString());
        	System.out.println("Encrypted Hash: " + encryptedHash.toString());
        	System.out.println("Encrypted Hash Base64: " + encryptedHashBase64);
        	System.out.println("Message Base64: " + msgBase64);
        	
        	String combinedMsg = msgBase64 + ":" + encryptedHashBase64;
        	
        	
        	
        	EncryptionAlgorithm cipher;
        	
        	
        	if (encryptAlgorithm == "DES") {
        		CBC cbc = new CBC("DES", utils.Utils.base64ToByteArray(encryptKey));
        		byte[] encryptedBytes = cbc.encrypt(combinedMsg.getBytes());
        		String encryptedRes = utils.Utils.byteArrayToBase64(encryptedBytes);
        		showEncryptionResult(encryptedRes);
        	} else if (encryptAlgorithm == "AES") {
        		
        	} else if (encryptAlgorithm == "RSA") {
        		
        	}
        	
        	
    	});
        
        
        decryptButton.addActionListener(e -> {
        	String message = inputContentField.getText();
        	String encryptAlgorithm = (String)algorithmCombo.getSelectedItem();
        	String encryptKey = keyField.getText();
        	String hashAlgorithm = (String)signatureAlgorithmCombo.getSelectedItem();
        	String mySignatureKey = signatureKeyField0.getText();
        	String otherSignatureKey = signatureKeyField1.getText();
        	
        	if (encryptAlgorithm == "DES") {
        		CBC cbc = new CBC("DES", utils.Utils.base64ToByteArray(encryptKey));
        		byte[] decryptedBytes = cbc.decrypt(utils.Utils.base64ToByteArray(message));
        		String decryptedCombinedString = new String(decryptedBytes);
        		String[] partStrings = decryptedCombinedString.split(":");
        		String decryptedMsgBase64 = partStrings[0];
        		String encryptedHashBase64 = partStrings[1];
        		String decryptedMsg = utils.Utils.base64ToString(decryptedMsgBase64);
        		byte[] msg = utils.Utils.base64ToByteArray(decryptedMsgBase64);
        		
        		// 重新计算hash值
        		String hashValue;
            	if (hashAlgorithm == "MD5") {
            		hashValue = MD5.computeHash(msg);
            	}
            	else {
            		hashValue = SHA1.computeHash(msg);
            	}
            	
            	
            	BigInteger encryptedHashBigInteger = utils.Utils.base64ToBigInteger(encryptedHashBase64);
            	RSAAlgorithm rsaCipher = new RSAAlgorithm();
            	BigInteger UKa = utils.Utils.base64ToBigInteger(otherSignatureKey);
            	BigInteger decryptedHash =  rsaCipher.decrypt(encryptedHashBigInteger, UKa, UKa);
            	String originHash = decryptedHash.toString(16);
            	
            	System.out.println("---------------------------------------------");
            	System.out.println("Hash BigInteger: " + decryptedHash.toString());
            	//System.out.println("RKa: " + RKa.toString());
            	System.out.println("Encrypted Hash: " + decryptedHash.toString());
            	System.out.println("Encrypted Hash Base64: " + encryptedHashBase64);
            	//System.out.println("Message Base64: " + msgBase64);
            	
        		showEncryptionResult(decryptedMsg + "\n" + hashValue + "\n" + originHash);
        	} else if (encryptAlgorithm == "AES") {
        		
        	} else if (encryptAlgorithm == "RSA") {
        		
        	}
        	
        });
        clearButton.addActionListener(e -> {
            inputContentField.setText("");
            fileSelectButton.setText("选择文件");
            fileSelectButton.setEnabled(false);
            rsaKeyPathField.setText("");
            keyField.setText("");
            signatureKeyField0.setText("");
            signatureKeyField1.setText("");
        });

        // 布局整体
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        
        mainPanel.add(inputPanel);
        mainPanel.add(rsaPanel);
        mainPanel.add(encryptionPanel);
        mainPanel.add(signaturePanel);
        
        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        frame.add(scrollPane, BorderLayout.CENTER);
        frame.add(buttonPanel, BorderLayout.SOUTH);
        frame.setVisible(true);
    }
}