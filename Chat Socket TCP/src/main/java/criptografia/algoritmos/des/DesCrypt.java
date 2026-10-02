package criptografia.algoritmos.des;

import criptografia.Crypt;
import criptografia.algoritmos.RC4Crypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * DES (Data Encryption Standard) em modo CBC com padding PKCS5.
 * Segue o mesmo contrato de {@link RC4Crypt}: implementa {@link Crypt} diretamente
 * (não usa {@code AbstractCrypt}, que é alfabeto clássico A–Z) e envia Base64
 * para não quebrar o protocolo TCP baseado em linhas.
 *
 * <p>Uma chave de 64 bits (56 efetivos + paridade), 16 rodadas Feistel (FIPS 46-3).
 */
public class DesCrypt implements Crypt {

    private final int BLOCK_SIZE = 8;
    private final int KEY_MATERIAL_SIZE = 8;

    private final DesEngine des;
    private final SecureRandom random = new SecureRandom();

    public DesCrypt(String chave) {
        byte[] material = deriveKeyMaterial(chave);
        this.des = new DesEngine(material);
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
            byte[] encrypted = des.encrypt(block);
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
            throw new IllegalArgumentException("Ciphertext DES inválido.");
        }

        byte[] iv = Arrays.copyOfRange(payload, 0, BLOCK_SIZE);
        byte[] cipher = Arrays.copyOfRange(payload, BLOCK_SIZE, payload.length);
        byte[] plain = new byte[cipher.length];
        byte[] previous = iv;
        byte[] block = new byte[BLOCK_SIZE];

        for (int offset = 0; offset < cipher.length; offset += BLOCK_SIZE) {
            System.arraycopy(cipher, offset, block, 0, BLOCK_SIZE);
            byte[] decrypted = des.decrypt(block);
            xorInPlace(decrypted, previous);
            System.arraycopy(decrypted, 0, plain, offset, BLOCK_SIZE);
            previous = Arrays.copyOfRange(cipher, offset, offset + BLOCK_SIZE);
        }

        return new String(pkcs5Unpad(plain), StandardCharsets.UTF_8);
    }

    private byte[] deriveKeyMaterial(String chave) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest(chave.getBytes(StandardCharsets.UTF_8));
            return Arrays.copyOf(digest, KEY_MATERIAL_SIZE);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponível", e);
        }
    }

    private byte[] pkcs5Pad(byte[] data) {
        int pad = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = Arrays.copyOf(data, data.length + pad);
        Arrays.fill(padded, data.length, padded.length, (byte) pad);
        return padded;
    }

    private byte[] pkcs5Unpad(byte[] data) {
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

    private void xorInPlace(byte[] block, byte[] other) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block[i] ^= other[i];
        }
    }

    public static void main(String[] args) {
        DesEngine engine = new DesEngine(hexToBytes("133457799BBCDFF1"));
        String desCipher = bytesToHex(engine.encrypt(hexToBytes("0123456789ABCDEF")));
        System.out.println("DES FIPS: " + desCipher
                + ("85E813540F0AB405".equalsIgnoreCase(desCipher) ? " OK" : " FAIL"));

        Crypt crypt = new DesCrypt("chave-secreta-des");
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
