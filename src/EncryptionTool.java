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
import java.io.FileOutputStream;
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
    
    public static void showAutoCloseDialog(JFrame parentFrame, String message, String title, int delayMillis) {
    	JDialog dialog = new JDialog(parentFrame, title, true); // true 表示模态对话框
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JLabel label = new JLabel(message, SwingConstants.CENTER);
        dialog.add(label);
        dialog.setSize(300, 150);
        dialog.setLocationRelativeTo(parentFrame);

        // 使用 Timer 定时关闭
        Timer timer = new Timer(delayMillis, e -> dialog.dispose());
        timer.setRepeats(false);
        timer.start();

        dialog.setVisible(true);
    }
    
    public static void showResults(Object result, String key, String additionalInfo, String op) {
        // 创建主窗口
    	String title = "加密结果";
    	if (op.equals("decrypt")) {
    		title = "解密结果";    	
    	}
        JFrame frame = new JFrame(title);
        frame.setSize(600, 400);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setLocationRelativeTo(null);
        
        Dimension uniformTextSize = new Dimension(400, 150);
        

        // 主面板，垂直布局
//        JPanel mainPanel = new JPanel();
//        mainPanel.setLayout(new GridLayout(3, 1, 10, 10)); // 三行布局
        
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10); // 设置内边距
        gbc.fill = GridBagConstraints.BOTH; // 拉伸组件以填充可用空间
        gbc.weightx = 1.0; // 宽度平分
        gbc.weighty = 0.0; // 高度可控

        // 第一部分：加密/解密结果
        // JPanel resultPanel = new JPanel(new BorderLayout(10, 10));
        JPanel resultPanel = new JPanel(new GridBagLayout());
        resultPanel.setBorder(BorderFactory.createTitledBorder("信息" + title));

        if (result instanceof String) {
            JTextArea resultTextArea = new JTextArea((String) result);
            resultTextArea.setEditable(false);
            resultTextArea.setLineWrap(true);
            resultTextArea.setWrapStyleWord(true);
            JScrollPane scrollPane = new JScrollPane(resultTextArea);
            scrollPane.setPreferredSize(uniformTextSize);

            JButton copyButton = new JButton("复制到剪切板");
            copyButton.addActionListener(e -> {
                StringSelection selection = new StringSelection((String) result);
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(selection, null);
                showAutoCloseDialog(frame, "已复制到剪切板！", "提示", 1000);
            });
            
            // 布局 resultPanel 的子组件
            GridBagConstraints innerGbc = new GridBagConstraints();
            innerGbc.insets = new Insets(5, 5, 5, 5);
            innerGbc.fill = GridBagConstraints.BOTH;
            innerGbc.weightx = 1.0;
            innerGbc.weighty = 1.0;
            innerGbc.gridx = 0;
            innerGbc.gridy = 0;
            innerGbc.gridwidth = 2;
            resultPanel.add(scrollPane, innerGbc);

            innerGbc.weighty = 0.0;
            innerGbc.gridy = 1;
            innerGbc.gridwidth = 1;
            innerGbc.anchor = GridBagConstraints.EAST;
            resultPanel.add(copyButton, innerGbc);
        } else if (result instanceof byte[]) {
            JLabel label = new JLabel("选择结果保存路径");
            JButton saveButton = new JButton("保存文件");
            saveButton.addActionListener(e -> {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("选择保存路径");
                int userSelection = fileChooser.showSaveDialog(null);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = fileChooser.getSelectedFile();
                    try (FileOutputStream fos = new FileOutputStream(fileToSave)) {
                        fos.write((byte[]) result);
                        showAutoCloseDialog(frame, "文件已保存到 " + fileToSave.getAbsolutePath(), "提示", 1000);
                    } catch (IOException ex) {
                        JOptionPane.showMessageDialog(frame, "文件保存失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                    }
                }
            });
            
            GridBagConstraints innerGbc = new GridBagConstraints();
            innerGbc.insets = new Insets(5, 5, 5, 5);
            innerGbc.fill = GridBagConstraints.HORIZONTAL;
            innerGbc.weightx = 1.0;
            innerGbc.gridx = 0;
            innerGbc.gridy = 0;
            resultPanel.add(label, innerGbc);

            innerGbc.gridx = 1;
            resultPanel.add(saveButton, innerGbc);
        }

        // 第二部分：加密/解密密钥
        // JPanel keyPanel = new JPanel(new BorderLayout(10, 10));
        JPanel keyPanel = new JPanel(new GridBagLayout());
        keyPanel.setBorder(BorderFactory.createTitledBorder("密钥" + title));

        JTextArea keyTextArea = new JTextArea(key);
        keyTextArea.setEditable(false);
        keyTextArea.setLineWrap(true);
        keyTextArea.setWrapStyleWord(true);
        JScrollPane keyScrollPane = new JScrollPane(keyTextArea);
        keyScrollPane.setPreferredSize(uniformTextSize);

        JButton copyKeyButton = new JButton("复制到剪切板");
        copyKeyButton.addActionListener(e -> {
            StringSelection selection = new StringSelection(key);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, null);
            showAutoCloseDialog(frame, "密钥已复制到剪切板！", "提示", 1000);
        });
        
        GridBagConstraints innerGbc = new GridBagConstraints();
        innerGbc.insets = new Insets(5, 5, 5, 5);
        innerGbc.fill = GridBagConstraints.BOTH;
        innerGbc.weightx = 1.0;
        innerGbc.weighty = 1.0;
        innerGbc.gridx = 0;
        innerGbc.gridy = 0;
        innerGbc.gridwidth = 2;
        keyPanel.add(keyScrollPane, innerGbc);

        innerGbc.weighty = 0.0;
        innerGbc.gridy = 1;
        innerGbc.gridwidth = 1;
        innerGbc.anchor = GridBagConstraints.EAST;
        keyPanel.add(copyKeyButton, innerGbc);

        // 第三部分：附加信息
        JPanel infoPanel = new JPanel(new GridBagLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("附加信息"));

        JLabel infoLabel = new JLabel(additionalInfo);
        infoLabel.setHorizontalAlignment(SwingConstants.LEFT);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        infoPanel.add(infoLabel, gbc);
        
        // 将所有部分加入主面板
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weighty = 0.3;
        mainPanel.add(resultPanel, gbc);

        gbc.gridy = 1;
        gbc.weighty = 0.3;
        mainPanel.add(keyPanel, gbc);

        gbc.gridy = 2;
        gbc.weighty = 0.1;
        mainPanel.add(infoPanel, gbc);

        // 显示窗口
        frame.add(mainPanel);
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
    	// print("encrypted hash", encryptedHash);
    	// 明文||HMAC
    	byte[] combinedMessageBytes = utils.Utils.joinWithBase64Separator(MessageBytes, encryptedHash, " ");
    	
    	EncryptionAlgorithm cipher = EncryptionAlgorithmFactory.getAlgorithm(selectedEncryptionAlgorithm, encryptionKey);
    	byte[] encryptedMessage = cipher.encrypt(combinedMessageBytes);
    	
    	// 加密密钥
    	EncryptionAlgorithm keyCipher = EncryptionAlgorithmFactory.getAlgorithm("RSA", keyEncrypt);
    	byte[] encryptedKey = keyCipher.encrypt(encryptionKey.getBytes());
    	String encryptedKeyBase64 = utils.Utils.byteArrayToBase64(encryptedKey);
    	
    	Object encryptedResult;
    	if (inputType.equals("String")) {
    		encryptedResult = utils.Utils.byteArrayToBase64(encryptedMessage);
    	}
    	else {
    		encryptedResult = encryptedMessage;
    	}    
    	String additionInfo = "<html>加密成功!<br>hash: " + hashValue + "</html>";
    	showResults(encryptedResult, encryptedKeyBase64, additionInfo, "encrypt");
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
    	// print("decrypted key", keyCipher.decrypt(decryptKeyByte));
    	
    	EncryptionAlgorithm cipher = EncryptionAlgorithmFactory.getAlgorithm(selectedEncryptionAlgorithm, decryptKey);
    	byte[] decryptedMessage = cipher.decrypt(inputMessageBytes);
    	
    	// step2 解密正文
    	byte[][] combinedMessages = utils.Utils.splitByBase64Separator(decryptedMessage, " ");
    	byte[] message = combinedMessages[0];
    	byte[] encryptedHash = combinedMessages[1];
    	Object decryptedResult;
    	if (inputType.equals("String")) {
    		decryptedResult = new String(message);
    	}
    	else {
    		decryptedResult = message;
    	} 
    	
    	// step3 校验数字签名
    	
    	// 校验hash值
    	EncryptionAlgorithm hashCipher = EncryptionAlgorithmFactory.getAlgorithm("RSA", sigurateKey);
    	byte[] decryptedHash = hashCipher.decrypt(encryptedHash);
    	String decryptedHashString = new String(decryptedHash);
    	String recomputedHash = computeHashString(selectedHashAlgorithm, message);
    	String additionInfo = "<html>文件签名校验通过!<br>hash: " + decryptedHashString + "</html>";
    	if (!decryptedHashString.equals(recomputedHash)) {
    		additionInfo = "文件签名校验失败！！！";
    	}
    	
    	showResults(decryptedResult, decryptKey, additionInfo, "decrypt");
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("加密签名工具");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(650, 650);
        frame.setLayout(new BorderLayout());
        
        // 主面板，使用 GridBagLayout
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 10, 5, 10); // 组件之间的间距
        
        Dimension uniformLabelSize = new Dimension(100, 30);
        Dimension uniformButtonSize = new Dimension(100, 30);
        Dimension uniformComboSize = new Dimension(150, 30);
        Dimension uniformFieldSize = new Dimension(300, 40); 

        // 输入设置面板
        JPanel inputPanel = new JPanel(new GridBagLayout());
        inputPanel.setBorder(BorderFactory.createTitledBorder("输入设置"));

        JLabel inputTypeLabel = new JLabel("输入类型:");
        inputTypeLabel.setPreferredSize(uniformLabelSize);
        JComboBox<String> inputTypeCombo = new JComboBox<>(new String[]{"字符串", "文件"});
        //inputTypeCombo.setPreferredSize(uniformComboSize);
        
        JLabel inputContentLabel = new JLabel("输入内容:");
        inputContentLabel.setPreferredSize(uniformLabelSize);
        inputContentLabel.setHorizontalAlignment(SwingConstants.LEFT);
        JTextArea inputContentField = new JTextArea(3, 20);
        inputContentField.setLineWrap(true);
        inputContentField.setWrapStyleWord(true);
        JScrollPane inputContentScrollPane = new JScrollPane(inputContentField);
        inputContentScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

        JButton fileSelectButton = new JButton("选择文件");
        fileSelectButton.setPreferredSize(uniformButtonSize);
        fileSelectButton.setPreferredSize(uniformButtonSize);
        fileSelectButton.setEnabled(false); // 初始状态禁用
        
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        inputPanel.add(inputTypeLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1;
        gbc.gridwidth = 2;
        inputPanel.add(inputTypeCombo, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        inputPanel.add(inputContentLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1;
        gbc.gridwidth = 1;
        inputPanel.add(inputContentScrollPane, gbc);
        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0;
        inputPanel.add(fileSelectButton, gbc);

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
            	inputContentField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });     
        
        
        // hash设置面板        
        JPanel hashPanel = new JPanel(new GridBagLayout());
        hashPanel.setBorder(BorderFactory.createTitledBorder("Hash算法"));
        JLabel hashAlgorithmLabel = new JLabel("选择Hash算法:");
        hashAlgorithmLabel.setPreferredSize(uniformLabelSize);        hashAlgorithmLabel.setHorizontalAlignment(SwingConstants.LEFT);
        JComboBox<String> hashAlgorithmCombo = new JComboBox<>(new String[]{"SHA", "MD5"});
        //hashAlgorithmCombo.setPreferredSize(uniformComboSize);
        
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        hashPanel.add(hashAlgorithmLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1;
        gbc.gridwidth = 1; // 占两列
        hashPanel.add(hashAlgorithmCombo, gbc);
        
        
        // 签名设置面板
        JPanel signaturePanel = new JPanel(new GridBagLayout());
        signaturePanel.setBorder(BorderFactory.createTitledBorder("数字签名设置"));
        JLabel signatureKeyLabel = new JLabel("数字签名密钥:");
        signatureKeyLabel.setPreferredSize(uniformLabelSize);
        signatureKeyLabel.setHorizontalAlignment(SwingConstants.LEFT);
        
        JTextArea signatureKeyField = new JTextArea(1, 20);
        JScrollPane signatureScrollPane = new JScrollPane(signatureKeyField);
        signatureScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        signatureScrollPane.setPreferredSize(uniformFieldSize); // 设置宽度300，高度40
        
        JButton importSignatureKeyButton = new JButton("导入密钥");
        importSignatureKeyButton.setPreferredSize(uniformButtonSize);
        
        
        gbc.gridx = 0; gbc.gridy = 0;  gbc.weightx = 0;
        signaturePanel.add(signatureKeyLabel, gbc);

        gbc.gridx = 1; gbc.gridy = 0; 
        gbc.weightx = 1; gbc.weighty = 1; // 水平 垂直方向扩展
        signaturePanel.add(signatureScrollPane, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0;
        signaturePanel.add(importSignatureKeyButton, gbc);
        
        
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
        JPanel encryptionPanel = new JPanel(new GridBagLayout());;
        encryptionPanel.setBorder(BorderFactory.createTitledBorder("加密设置"));

        JLabel algorithmLabel = new JLabel("选择加密算法:");
        algorithmLabel.setPreferredSize(uniformLabelSize);
        algorithmLabel.setHorizontalAlignment(SwingConstants.LEFT);
        JComboBox<String> algorithmCombo = new JComboBox<>(new String[]{"DES", "AES", "RSA"});
        //algorithmCombo.setPreferredSize(uniformComboSize);
        JLabel keyLabel = new JLabel("密钥输入:");
        keyLabel.setPreferredSize(uniformLabelSize);
        JTextArea keyField = new JTextArea(1, 20);
        JScrollPane keyScrollPane = new JScrollPane(keyField);
        keyScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        keyScrollPane.setPreferredSize(uniformFieldSize);
        
        
        JButton generateKeyButton = new JButton("生成密钥");
        generateKeyButton.setPreferredSize(uniformButtonSize);
        JLabel rsaKeyLabel = new JLabel("RSA算法");
        JButton importKeyButton = new JButton("导入公私钥");
        importKeyButton.setPreferredSize(uniformButtonSize);
        JButton generateRSAKeysButton = new JButton("生成公私钥");
        generateRSAKeysButton.setPreferredSize(uniformButtonSize);
        
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        encryptionPanel.add(algorithmLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1;
        gbc.gridwidth = 2;
        encryptionPanel.add(algorithmCombo, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        encryptionPanel.add(keyLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1;
        gbc.gridwidth = 1;
        encryptionPanel.add(keyScrollPane, gbc);
        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0;
        encryptionPanel.add(generateKeyButton, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        gbc.gridwidth = 1; // 占两列
        encryptionPanel.add(rsaKeyLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 2; gbc.weightx = 1;
        gbc.gridwidth = 1; // 占两列
        encryptionPanel.add(importKeyButton, gbc);
        gbc.gridx = 2; gbc.gridy = 2; gbc.weightx = 0;
        gbc.gridwidth = 1; // 占两列
        encryptionPanel.add(generateRSAKeysButton, gbc);
        
        algorithmCombo.addActionListener(e -> {
            String selectedAlgorithm = (String) algorithmCombo.getSelectedItem();
            boolean isSymmetric = !"RSA".equals(selectedAlgorithm); // 是否为对称加密

            generateKeyButton.setEnabled(isSymmetric); // 仅对称加密可生成密钥
            keyField.setText(""); // 清空密钥输入框
        });

        generateKeyButton.addActionListener(e -> {
        	String algorithm = (String) algorithmCombo.getSelectedItem();
        	//long seed = 123456L;  // 随机种子
        	long seed = System.currentTimeMillis();  // 当前时间戳作为种子

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
        JPanel keyEncryptPanel = new JPanel(new GridBagLayout());;
        keyEncryptPanel.setBorder(BorderFactory.createTitledBorder("密钥加密设置"));

        JLabel keyEncryptLabel = new JLabel("密钥分发密钥:");
        keyEncryptLabel.setPreferredSize(uniformLabelSize);
        keyEncryptLabel.setHorizontalAlignment(SwingConstants.LEFT);
        JTextArea keyEncryptField = new JTextArea(1, 20);
        JScrollPane keyEncryptScrollPane = new JScrollPane(keyEncryptField);
        keyEncryptScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        keyEncryptScrollPane.setPreferredSize(uniformFieldSize);
        
        JButton keyEncryptButton = new JButton("导入密钥");
        keyEncryptButton.setPreferredSize(uniformButtonSize);
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        keyEncryptPanel.add(keyEncryptLabel, gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1; gbc.weighty = 1;
        keyEncryptPanel.add(keyEncryptScrollPane, gbc);
        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0;
        keyEncryptPanel.add(keyEncryptButton, gbc);
        
        
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
        
        // 添加面板到主面板
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 0; gbc.fill = GridBagConstraints.HORIZONTAL;
        mainPanel.add(inputPanel, gbc);
        gbc.gridy++;
        mainPanel.add(hashPanel, gbc);
        gbc.gridy++;
        mainPanel.add(signaturePanel, gbc);
        gbc.gridy++;
        mainPanel.add(encryptionPanel, gbc);
        gbc.gridy++;
        mainPanel.add(keyEncryptPanel, gbc);
        
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
        		String filePath = inputContentField.getText();
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
        		inputData = utils.Utils.base64ToByteArray(inputString);
        	}
        	else {
        		String filePath = inputContentField.getText();
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
        
        // 滚动面板
        JScrollPane scrollPane = new JScrollPane(mainPanel);
        frame.add(scrollPane, BorderLayout.CENTER);
        frame.add(buttonPanel, BorderLayout.SOUTH);
        frame.setVisible(true);
    }
}