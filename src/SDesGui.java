import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;


public class SDesGui extends JFrame {
    private JTextField plainTextField;
    private JTextField keyField;
    private JTextField cipherTextField;
    private JButton encryptButton;
    private JButton decryptButton;
    private JButton bruteForceButton;
    private JTextArea closedTestArea;
    private JButton closedTestButton;

    public SDesGui() {
        setTitle("S-DES 加密/解密");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new FlowLayout());

        plainTextField = new JTextField(20);
        keyField = new JTextField(20);
        cipherTextField = new JTextField(20);
        encryptButton = new JButton("加密");
        decryptButton = new JButton("解密");
        bruteForceButton = new JButton("暴力破解");
        closedTestArea = new JTextArea(5,20);
        //closedTestButton = new JButton("封闭测试");

        closedTestArea.setLineWrap(true);
        closedTestArea.setWrapStyleWord(true);

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.insets = new Insets(5, 5, 5, 5); // 设置组件之间的间距

        addComponent(new JLabel("明文:"), 0, 0, 1, 1, constraints);
        addComponent(plainTextField, 1, 0, 2, 1, constraints);
        addComponent(new JLabel("密钥:"), 0, 1, 1, 1, constraints);
        addComponent(keyField, 1, 1, 2, 1, constraints);
        addComponent(new JLabel("密文:"), 0, 2, 1, 1, constraints);
        addComponent(cipherTextField, 1, 2, 2, 1, constraints);
        addComponent(encryptButton, 0, 3, 1, 1, constraints);
        addComponent(decryptButton, 2, 3, 1, 1, constraints);
        addComponent(bruteForceButton,1,3,1,1,constraints);
        addComponent(new JScrollPane(closedTestArea),0,4,3,1,constraints);
        //addComponent(closedTestButton,1,5,1,1,constraints);

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String plaintext = plainTextField.getText();
                String keyString = keyField.getText();


                if (plaintext.length() != 8) {
                    JOptionPane.showMessageDialog(null, "明文必须为8bits.");
                    return;
                }

                if (keyString.length() != 10) {
                    JOptionPane.showMessageDialog(null, "密钥必须为10bits.");
                    return;
                }

                int[] key = new int[10];
                for (int i = 0; i < 10; i++) {
                    key[i] = keyString.charAt(i) - '0';
                }
                if (isBinaryString(plaintext)) {
                    int[] plaintextBinary = new int[8];
                    for (int i = 0; i < 8; i++) {
                        plaintextBinary[i] = plaintext.charAt(i) - '0';
                    }
                    SDes sdes = new SDes(key);
                    int[] ciphertextBinary = sdes.encrypt(plaintextBinary);
                    StringBuilder ciphertext = new StringBuilder();
                    for (int bit : ciphertextBinary) {
                        ciphertext.append(bit);
                    }
                    cipherTextField.setText(ciphertext.toString());
                } else {
                    String ciphertext = SDes.encryptString(plaintext, key);
                    cipherTextField.setText(ciphertext);
                }
            }
        });


        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String ciphertext = cipherTextField.getText();
                String keyString = keyField.getText();


                if (ciphertext.length() != 8) {
                    JOptionPane.showMessageDialog(null, "密文必须为8bits.");
                    return;
                }

                if (keyString.length() != 10) {
                    JOptionPane.showMessageDialog(null, "密钥必须为10bits.");
                    return;
                }
                int[] key = new int[10];
                for (int i = 0; i < 10; i++) {
                    key[i] = keyString.charAt(i) - '0';
                }
                if (isBinaryString(ciphertext)) {
                    int[] ciphertextBinary = new int[8];
                    for (int i = 0; i < 8; i++) {
                        ciphertextBinary[i] = ciphertext.charAt(i) - '0';
                    }
                    SDes sdes = new SDes(key);
                    int[] plaintextBinary = sdes.decrypt(ciphertextBinary);
                    StringBuilder plaintext = new StringBuilder();
                    for (int bit : plaintextBinary) {
                        plaintext.append(bit);
                    }
                    plainTextField.setText(plaintext.toString());
                } else {
                    String plaintext = SDes.decryptString(ciphertext, key);
                    plainTextField.setText(plaintext);
                }
            }
        });


        bruteForceButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                closedTestArea.setText("");
                String plaintext = plainTextField.getText();
                String ciphertext = cipherTextField.getText();

                if (plaintext.length() != 8) {
                    JOptionPane.showMessageDialog(null, "明文必须为8bits.");
                    return;
                }

                if (ciphertext.length() != 8) {
                    JOptionPane.showMessageDialog(null, "密文必须为8bits.");
                    return;
                }


                SDes.bruteForce(plaintext, ciphertext, closedTestArea);
            }
        });

        setSize(300, 400);
        setLocationRelativeTo(null);
    }



    private void addComponent(Component component, int x, int y, int width, int height, GridBagConstraints constraints) {
        constraints.gridx = x;
        constraints.gridy = y;
        constraints.gridwidth = width;
        constraints.gridheight = height;
        add(component, constraints);
    }

    private boolean isBinaryString(String str) {
        for (char c : str.toCharArray()) {
            if (c != '0' && c != '1') {
                return false;
            }
        }
        return true;
    }


    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                SDesGui gui = new SDesGui();
                gui.setVisible(true);
            }
        });
    }
}