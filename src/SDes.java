import javax.swing.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;


public class SDes {
    private static int[] key1;
    private static int[] key2;

    public SDes(int[] key) {
        if (key.length != 10) {
            throw new IllegalArgumentException("Key must be 10 bits long.");
        }
        this.key1 = key_expansion(key, 1);
        this.key2 = key_expansion(key, 2);
    }

    private int[] key_expansion(int[] key, int round) {
        int[] P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
        int[] P8 = {6, 3, 7, 4, 8, 5, 10, 9};
        int[] LS1 = {2, 3, 4, 5, 1};
        int[] LS2 = {3, 4, 5, 1, 2};

        int[] permutedKey = new int[10];
        for (int i = 0; i < 10; i++) {
            permutedKey[i] = key[P10[i] - 1];
        }

        int[] leftHalf = Arrays.copyOfRange(permutedKey, 0, 5);
        int[] rightHalf = Arrays.copyOfRange(permutedKey, 5, 10);

        leftHalf = left_shift(leftHalf, round == 1 ? LS1 : LS2);
        rightHalf = left_shift(rightHalf, round == 1 ? LS1 : LS2);

        int[] combined = new int[10];
        System.arraycopy(leftHalf, 0, combined, 0, 5);
        System.arraycopy(rightHalf, 0, combined, 5, 5);

        int[] keyOut = new int[8];
        for (int i = 0; i < 8; i++) {
            keyOut[i] = combined[P8[i] - 1];
        }

        return keyOut;
    }

    private int[] left_shift(int[] array, int[] shift) {
        int[] shifted = new int[array.length];
        for (int i = 0; i < array.length; i++) {
            shifted[i] = array[shift[i] - 1];
        }
        return shifted;
    }

    public static int[] encrypt(int[] plaintext) {
        int[] IP = {2, 6, 3, 1, 4, 8, 5, 7};
        int[] IP_inv = {4, 1, 3, 5, 7, 2, 8, 6};

        int[] permutedPlaintext = new int[8];
        for (int i = 0; i < 8; i++) {
            permutedPlaintext[i] = plaintext[IP[i] - 1];
        }

        int[] round1 = f_k(permutedPlaintext, key1);
        int[] swapped = swap(round1);
        int[] round2 = f_k(swapped, key2);

        int[] ciphertext = new int[8];
        for (int i = 0; i < 8; i++) {
            ciphertext[i] = round2[IP_inv[i] - 1];
        }

        return ciphertext;
    }

    public static int[] decrypt(int[] ciphertext) {
        int[] IP = {2, 6, 3, 1, 4, 8, 5, 7};
        int[] IP_inv = {4, 1, 3, 5, 7, 2, 8, 6};

        int[] permutedCiphertext = new int[8];
        for (int i = 0; i < 8; i++) {
            permutedCiphertext[i] = ciphertext[IP[i] - 1];
        }

        int[] round1 = f_k(permutedCiphertext, key2);
        int[] swapped = swap(round1);
        int[] round2 = f_k(swapped, key1);

        int[] plaintext = new int[8];
        for (int i = 0; i < 8; i++) {
            plaintext[i] = round2[IP_inv[i] - 1];
        }

        return plaintext;
    }

    private static int[] f_k(int[] input, int[] key) {
        int[] EPBox = {4, 1, 2, 3, 2, 3, 4, 1};
        int[][] SBox1 = {
                {1, 0, 3, 2},
                {3, 2, 1, 0},
                {0, 2, 1, 3},
                {3, 1, 0, 2}
        };
        int[][] SBox2 = {
                {0, 1, 2, 3},
                {2, 3, 1, 0},
                {3, 0, 1, 2},
                {2, 1, 0, 3}
        };
        int[] SPBox = {2, 4, 3, 1};

        int[] leftHalf = Arrays.copyOfRange(input, 0, 4);
        int[] rightHalf = Arrays.copyOfRange(input, 4, 8);

        int[] expandedRightHalf = new int[8];
        for (int i = 0; i < 8; i++) {
            expandedRightHalf[i] = rightHalf[EPBox[i] - 1];
        }

        int[] xorResult = new int[8];
        for (int i = 0; i < 8; i++) {
            xorResult[i] = expandedRightHalf[i] ^ key[i];
        }

        int[] sBoxInput1 = Arrays.copyOfRange(xorResult, 0, 4);
        int[] sBoxInput2 = Arrays.copyOfRange(xorResult, 4, 8);

        int sBoxOutput1 = SBox1[sBoxInput1[0] * 2 + sBoxInput1[3]][sBoxInput1[1] * 2 + sBoxInput1[2]];
        int sBoxOutput2 = SBox2[sBoxInput2[0] * 2 + sBoxInput2[3]][sBoxInput2[1] * 2 + sBoxInput2[2]];

        int[] sBoxOutput = {sBoxOutput1 / 2, sBoxOutput1 % 2, sBoxOutput2 / 2, sBoxOutput2 % 2};

        int[] permutedSBoxOutput = new int[4];
        for (int i = 0; i < 4; i++) {
            permutedSBoxOutput[i] = sBoxOutput[SPBox[i] - 1];
        }

        int[] xorResult2 = new int[4];
        for (int i = 0; i < 4; i++) {
            xorResult2[i] = leftHalf[i] ^ permutedSBoxOutput[i];
        }

        int[] output = new int[8];
        System.arraycopy(xorResult2, 0, output, 0, 4);
        System.arraycopy(rightHalf, 0, output, 4, 4);

        return output;
    }

    private static int[] swap(int[] input) {
        int[] swapped = new int[8];
        System.arraycopy(input, 4, swapped, 0, 4);
        System.arraycopy(input, 0, swapped, 4, 4);
        return swapped;
    }

    public static void main(String[] args) {

    }

    //实现ASCII字符串加密和解密
    public static String encryptString(String plaintext, int[] key) {
        StringBuilder ciphertext = new StringBuilder();
        for (char c : plaintext.toCharArray()) {
            int[] binary = new int[8];
            for (int i = 0; i < 8; i++) {
                binary[7 - i] = (c >> i) & 1;
            }
            SDes sdes = new SDes(key);
            int[] encrypted = sdes.encrypt(binary);
            int encryptedChar = 0;
            for (int i = 0; i < 8; i++) {
                encryptedChar |= encrypted[7 - i] << i;
            }
            ciphertext.append((char) encryptedChar);
        }
        return ciphertext.toString();
    }

    public static String decryptString(String ciphertext, int[] key) {
        StringBuilder plaintext = new StringBuilder();
        for (char c : ciphertext.toCharArray()) {
            int[] binary = new int[8];
            for (int i = 0; i < 8; i++) {
                binary[7 - i] = (c >> i) & 1;
            }
            SDes sdes = new SDes(key);
            int[] decrypted = sdes.decrypt(binary);
            int decryptedChar = 0;
            for (int i = 0; i < 8; i++) {
                decryptedChar |= decrypted[7 - i] << i;
            }
            plaintext.append((char) decryptedChar);
        }
        return plaintext.toString();
    }


    //暴力破解
    public static void bruteForce(String plaintext, String ciphertext, JTextArea textArea) {
        textArea.append("开始暴力破解...\n");
        long startTime = System.currentTimeMillis();

        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        int[] foundKeyCount = new int[1]; // 使用数组来传递计数器

        for (int i = 0; i < 1024; i++) {
            int[] key = new int[10];
            for (int j = 0; j < 10; j++) {
                key[9 - j] = (i >> j) & 1;
            }
            executor.submit(new BruteForceTask(key, plaintext, ciphertext, textArea, foundKeyCount));
        }

        executor.shutdown();
        try {
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        long endTime = System.currentTimeMillis();
        textArea.append("暴力破解完成时间： " + (endTime - startTime) + " ms.\n");
        textArea.append("找到 " + foundKeyCount[0] + " 个密钥.\n");
    }

    static class BruteForceTask implements Runnable {
        private final int[] key;
        private final String plaintext;
        private final String ciphertext;
        private final JTextArea textArea;
        private final int[] foundKeyCount;

        BruteForceTask(int[] key, String plaintext, String ciphertext, JTextArea textArea, int[] foundKeyCount) {
            this.key = key;
            this.plaintext = plaintext;
            this.ciphertext = ciphertext;
            this.textArea = textArea;
            this.foundKeyCount = foundKeyCount;
        }

        @Override
        public void run() {
            int[] ciphertextBinary = new int[8];
            for (int i = 0; i < 8; i++) {
                ciphertextBinary[i] = ciphertext.charAt(i) - '0';
            }

            SDes sdes = new SDes(key);
            int[] decryptedBinary = sdes.decrypt(ciphertextBinary);
            StringBuilder decrypted = new StringBuilder();
            for (int bit : decryptedBinary) {
                decrypted.append(bit);
            }



            if (decrypted.toString().equals(plaintext)) {
                synchronized (foundKeyCount) {
                    foundKeyCount[0]++;
                }
                SwingUtilities.invokeLater(() -> {
                    textArea.append("找到密钥: " + Arrays.toString(key) + "\n");
                });
            }
        }
    }

}
