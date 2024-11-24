import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class EncryptionTool {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(EncryptionTool::createAndShowGUI);
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
        JButton importRSAKeyButton = new JButton("导入RSA密钥");
        JLabel rsaKeyLabel = new JLabel("公/私钥路径:");
        JTextField rsaKeyPathField = new JTextField();

        rsaPanel.add(new JLabel("操作:"));
        rsaPanel.add(generateRSAKeysButton);

        generateRSAKeysButton.addActionListener(e -> {
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

                // 模拟生成密钥对逻辑
                String privateKeyPath = directory + "/" + privateKeyName + ".key";
                String publicKeyPath = directory + "/" + privateKeyName + ".pub";

                JOptionPane.showMessageDialog(null, "公私钥已生成:\n私钥: " + privateKeyPath + "\n公钥: " + publicKeyPath);
            }
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
            keyField.setText("根据种子生成的" + algorithm + "密钥");
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
        signaturePanel.add(signatureKeyLabel0);
        signaturePanel.add(signatureKeyField0);
        signaturePanel.add(importSignatureKeyButton0);
        signaturePanel.add(signatureKeyLabel1);
        signaturePanel.add(signatureKeyField1);
        signaturePanel.add(importSignatureKeyButton1);
        
        importSignatureKeyButton0.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            	signatureKeyField0.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });
        importSignatureKeyButton1.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            	signatureKeyField1.setText(fileChooser.getSelectedFile().getAbsolutePath());
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

        encryptButton.addActionListener(e -> JOptionPane.showMessageDialog(frame, "执行加密操作 (功能未实现)"));
        decryptButton.addActionListener(e -> JOptionPane.showMessageDialog(frame, "执行解密操作 (功能未实现)"));
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