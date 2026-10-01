package criptografia.algoritmos;

import criptografia.Crypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * 3DES (Triple DES / DESede) em modo CBC com padding PKCS5.
 * Segue o mesmo contrato de {@link RC4Crypt}: implementa {@link Crypt} diretamente
 * (não usa {@code AbstractCrypt}, que é alfabeto clássico A–Z) e envia Base64
 * para não quebrar o protocolo TCP baseado em linhas.
 *
 * <p>Operação EDE com três chaves de 64 bits (56 efetivos + paridade):
 * cifra = E<sub>K3</sub>(D<sub>K2</sub>(E<sub>K1</sub>(P))),
 * decifra = D<sub>K1</sub>(E<sub>K2</sub>(D<sub>K3</sub>(C))).
 */
public class TripleDesCrypt implements Crypt {

    private static final int BLOCK_SIZE = 8;
    private static final int KEY_MATERIAL_SIZE = 24;

    private final DesEngine k1;
    private final DesEngine k2;
    private final DesEngine k3;
    private final SecureRandom random = new SecureRandom();

    public TripleDesCrypt(String chave) {
        byte[] material = deriveKeyMaterial(chave);
        this.k1 = new DesEngine(Arrays.copyOfRange(material, 0, 8));
        this.k2 = new DesEngine(Arrays.copyOfRange(material, 8, 16));
        this.k3 = new DesEngine(Arrays.copyOfRange(material, 16, 24));
        Arrays.fill(material, (byte) 0);
    }

    @Override
    public String encrypt(String message) {
        byte[] plain = pkcs5Pad(message.getBytes(StandardCharsets.UTF_8));
        byte[] iv = new byte[BLOCK_SIZE];
        random.nextBytes(iv);

        byte[] cipher = new byte[plain.length];
        byte[] previous = Arrays.copyOf(iv, BLOCK_SIZE);
        byte[] block = new byte[BLOCK_SIZE];

        for (int offset = 0; offset < plain.length; offset += BLOCK_SIZE) {
            System.arraycopy(plain, offset, block, 0, BLOCK_SIZE);
            xorInPlace(block, previous);
            byte[] encrypted = tripleEncrypt(block);
            System.arraycopy(encrypted, 0, cipher, offset, BLOCK_SIZE);
            previous = encrypted;
        }

        byte[] payload = new byte[BLOCK_SIZE + cipher.length];
        System.arraycopy(iv, 0, payload, 0, BLOCK_SIZE);
        System.arraycopy(cipher, 0, payload, BLOCK_SIZE, cipher.length);
        return Base64.getEncoder().encodeToString(payload);
    }

    @Override
    public String decrypt(String message) {
        byte[] payload = Base64.getDecoder().decode(message);
        if (payload.length < BLOCK_SIZE * 2 || payload.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Ciphertext 3DES inválido.");
        }

        byte[] iv = Arrays.copyOfRange(payload, 0, BLOCK_SIZE);
        byte[] cipher = Arrays.copyOfRange(payload, BLOCK_SIZE, payload.length);
        byte[] plain = new byte[cipher.length];
        byte[] previous = iv;
        byte[] block = new byte[BLOCK_SIZE];

        for (int offset = 0; offset < cipher.length; offset += BLOCK_SIZE) {
            System.arraycopy(cipher, offset, block, 0, BLOCK_SIZE);
            byte[] decrypted = tripleDecrypt(block);
            xorInPlace(decrypted, previous);
            System.arraycopy(decrypted, 0, plain, offset, BLOCK_SIZE);
            previous = Arrays.copyOfRange(cipher, offset, offset + BLOCK_SIZE);
        }

        return new String(pkcs5Unpad(plain), StandardCharsets.UTF_8);
    }

    private byte[] tripleEncrypt(byte[] block) {
        return k3.encrypt(k2.decrypt(k1.encrypt(block)));
    }

    private byte[] tripleDecrypt(byte[] block) {
        return k1.decrypt(k2.encrypt(k3.decrypt(block)));
    }

    private static byte[] deriveKeyMaterial(String chave) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest(chave.getBytes(StandardCharsets.UTF_8));
            return Arrays.copyOf(digest, KEY_MATERIAL_SIZE);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponível", e);
        }
    }

    private static byte[] pkcs5Pad(byte[] data) {
        int pad = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = Arrays.copyOf(data, data.length + pad);
        Arrays.fill(padded, data.length, padded.length, (byte) pad);
        return padded;
    }

    private static byte[] pkcs5Unpad(byte[] data) {
        if (data.length == 0 || data.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Padding PKCS5 inválido.");
        }
        int pad = data[data.length - 1] & 0xFF;
        if (pad < 1 || pad > BLOCK_SIZE || pad > data.length) {
            throw new IllegalArgumentException("Padding PKCS5 inválido.");
        }
        for (int i = data.length - pad; i < data.length; i++) {
            if ((data[i] & 0xFF) != pad) {
                throw new IllegalArgumentException("Padding PKCS5 inválido.");
            }
        }
        return Arrays.copyOf(data, data.length - pad);
    }

    private static void xorInPlace(byte[] block, byte[] other) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block[i] ^= other[i];
        }
    }

    /**
     * DES de 64 bits (16 rodadas Feistel). Tabelas oficiais FIPS 46-3.
     */
    private static final class DesEngine {

        private static final int[] IP = {
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
        };

        private static final int[] FP = {
                40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25
        };

        private static final int[] E = {
                32, 1, 2, 3, 4, 5,
                4, 5, 6, 7, 8, 9,
                8, 9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32, 1
        };

        private static final int[] P = {
                16, 7, 20, 21, 29, 12, 28, 17,
                1, 15, 23, 26, 5, 18, 31, 10,
                2, 8, 24, 14, 32, 27, 3, 9,
                19, 13, 30, 6, 22, 11, 4, 25
        };

        private static final int[] PC1 = {
                57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4
        };

        private static final int[] PC2 = {
                14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32
        };

        private static final int[] SHIFTS = {
                1, 1, 2, 2, 2, 2, 2, 2,
                1, 2, 2, 2, 2, 2, 2, 1
        };

        private static final int[][][] SBOX = {
                {
                        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
                },
                {
                        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
                },
                {
                        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
                },
                {
                        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
                },
                {
                        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
                },
                {
                        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
                },
                {
                        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
                },
                {
                        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
                }
        };

        private final long[] subkeys = new long[16];

        DesEngine(byte[] key8) {
            long keyBits = bytesToLong(key8);
            long permuted = permute(keyBits, PC1, 64);
            int c = (int) ((permuted >>> 28) & 0x0FFFFFFF);
            int d = (int) (permuted & 0x0FFFFFFF);

            for (int round = 0; round < 16; round++) {
                c = rotateLeft28(c, SHIFTS[round]);
                d = rotateLeft28(d, SHIFTS[round]);
                long cd = ((long) c << 28) | (d & 0x0FFFFFFFL);
                subkeys[round] = permute(cd, PC2, 56);
            }
        }

        byte[] encrypt(byte[] block) {
            return process(block, false);
        }

        byte[] decrypt(byte[] block) {
            return process(block, true);
        }

        private byte[] process(byte[] block, boolean decrypt) {
            long bits = permute(bytesToLong(block), IP, 64);
            int left = (int) (bits >>> 32);
            int right = (int) bits;

            for (int i = 0; i < 16; i++) {
                long subkey = decrypt ? subkeys[15 - i] : subkeys[i];
                int previousLeft = left;
                left = right;
                right = previousLeft ^ f(right, subkey);
            }

            long preOutput = ((long) right << 32) | (left & 0xFFFFFFFFL);
            return longToBytes(permute(preOutput, FP, 64));
        }

        private static int f(int right, long subkey) {
            long expanded = permute(right & 0xFFFFFFFFL, E, 32);
            long mixed = expanded ^ subkey;
            int sOutput = 0;
            for (int i = 0; i < 8; i++) {
                int sixBits = (int) ((mixed >>> (42 - 6 * i)) & 0x3F);
                int row = ((sixBits & 0x20) >>> 4) | (sixBits & 0x01);
                int col = (sixBits >>> 1) & 0x0F;
                sOutput = (sOutput << 4) | SBOX[i][row][col];
            }
            return (int) permute(sOutput & 0xFFFFFFFFL, P, 32);
        }

        private static int rotateLeft28(int value, int shift) {
            return ((value << shift) | (value >>> (28 - shift))) & 0x0FFFFFFF;
        }

        private static long permute(long input, int[] table, int inputBits) {
            long output = 0L;
            for (int position : table) {
                long bit = (input >>> (inputBits - position)) & 1L;
                output = (output << 1) | bit;
            }
            return output;
        }

        private static long bytesToLong(byte[] data) {
            long value = 0L;
            for (int i = 0; i < 8; i++) {
                value = (value << 8) | (data[i] & 0xFFL);
            }
            return value;
        }

        private static byte[] longToBytes(long value) {
            byte[] data = new byte[8];
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (value & 0xFF);
                value >>>= 8;
            }
            return data;
        }
    }

    public static void main(String[] args) {
        DesEngine des = new DesEngine(hexToBytes("133457799BBCDFF1"));
        String desCipher = bytesToHex(des.encrypt(hexToBytes("0123456789ABCDEF")));
        System.out.println("DES FIPS: " + desCipher
                + ("85E813540F0AB405".equalsIgnoreCase(desCipher) ? " OK" : " FAIL"));

        Crypt crypt = new TripleDesCrypt("chave-secreta-3des");
        String mensagem = "Cybersecurity melhor disciplina do curso.";
        String cifrado = crypt.encrypt(mensagem);
        System.out.println("Cifrado (Base64): " + cifrado);
        System.out.println("Decifrado: " + crypt.decrypt(cifrado));
        System.out.println("Roundtrip vazio: [" + crypt.decrypt(crypt.encrypt("")) + "]");
    }

    private static byte[] hexToBytes(String hex) {
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return data;
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
