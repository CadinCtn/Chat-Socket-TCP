package criptografia.algoritmos.aes;

import criptografia.Crypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class AesCrypt implements Crypt {

    private final int BLOCK_SIZE = AesEngine.BLOCK_SIZE; // 16 bytes
    // 16 = AES-128 | 24 = AES-192 | 32 = AES-256 (o AesEngine aceita os três)
    private final int KEY_MATERIAL_SIZE = 16;

    private final AesEngine aes;
    private final SecureRandom random = new SecureRandom();
    private final boolean modoValidacao;
    private final byte[] validationKeyBytes;

    public AesCrypt(String chave) {
        this(chave, false);
    }

    public AesCrypt(String chave, boolean modoValidacao) {
        this.modoValidacao = modoValidacao;
        byte[] material;

        if (modoValidacao) {
            material = chave.getBytes(StandardCharsets.US_ASCII);
            if (material.length != KEY_MATERIAL_SIZE
                    || !chave.equals(new String(material, StandardCharsets.US_ASCII))) {
                throw new IllegalArgumentException(
                        "No modo de validação, a chave deve conter exatamente "
                                + KEY_MATERIAL_SIZE + " caracteres ASCII.");
            }
        } else {
            material = deriveKeyMaterial(chave);
        }

        this.aes = new AesEngine(material);
        this.validationKeyBytes = modoValidacao ? material.clone() : null;
        Arrays.fill(material, (byte) 0);
    }

    @Override
    public String encrypt(String message) {
        if (modoValidacao) {
            return encryptBlocosParaValidacao(message);
        }

        byte[] plain = pkcs7Pad(message.getBytes(StandardCharsets.UTF_8));
        byte[] iv = new byte[BLOCK_SIZE];
        random.nextBytes(iv);

        byte[] cipher = new byte[plain.length];
        byte[] previous = Arrays.copyOf(iv, BLOCK_SIZE);
        byte[] block = new byte[BLOCK_SIZE];

        for (int offset = 0; offset < plain.length; offset += BLOCK_SIZE) {
            System.arraycopy(plain, offset, block, 0, BLOCK_SIZE);
            xorInPlace(block, previous);
            byte[] encrypted = aes.encrypt(block);
            System.arraycopy(encrypted, 0, cipher, offset, BLOCK_SIZE);
            previous = encrypted;
        }

        // payload = IV || ciphertext, em Base64 para não quebrar o protocolo por linha
        byte[] payload = new byte[BLOCK_SIZE + cipher.length];
        System.arraycopy(iv, 0, payload, 0, BLOCK_SIZE);
        System.arraycopy(cipher, 0, payload, BLOCK_SIZE, cipher.length);
        return Base64.getEncoder().encodeToString(payload);
    }

    @Override
    public String decrypt(String message) {
        if (modoValidacao) {
            return decryptBlocosHex(message);
        }

        byte[] payload = Base64.getDecoder().decode(message);
        if (payload.length < BLOCK_SIZE * 2 || payload.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Ciphertext AES inválido.");
        }

        byte[] iv = Arrays.copyOfRange(payload, 0, BLOCK_SIZE);
        byte[] cipher = Arrays.copyOfRange(payload, BLOCK_SIZE, payload.length);
        byte[] plain = new byte[cipher.length];
        byte[] previous = iv;
        byte[] block = new byte[BLOCK_SIZE];

        for (int offset = 0; offset < cipher.length; offset += BLOCK_SIZE) {
            System.arraycopy(cipher, offset, block, 0, BLOCK_SIZE);
            byte[] decrypted = aes.decrypt(block);
            xorInPlace(decrypted, previous);
            System.arraycopy(decrypted, 0, plain, offset, BLOCK_SIZE);
            previous = Arrays.copyOfRange(cipher, offset, offset + BLOCK_SIZE);
        }

        return new String(pkcs7Unpad(plain), StandardCharsets.UTF_8);
    }

    // ---------------------------------------------------- modo de validação

    private String encryptBlocosParaValidacao(String message) {
        byte[] plain = message.getBytes(StandardCharsets.US_ASCII);
        if (plain.length == 0 || !message.equals(new String(plain, StandardCharsets.US_ASCII))) {
            throw new IllegalArgumentException("A mensagem deve ser ASCII e não pode ser vazia.");
        }
        if (plain.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException(
                    "No modo de validação, a mensagem deve ter tamanho múltiplo de "
                            + BLOCK_SIZE + " bytes. Recebidos: " + plain.length + " bytes.");
        }

        System.out.println("\n=== VALIDAÇÃO AES (blocos independentes) ===");
        System.out.println("Mensagem ASCII: [" + message + "]");
        System.out.println("Mensagem HEX: " + bytesToHex(plain));
        System.out.println("Chave HEX: " + bytesToHex(validationKeyBytes));

        byte[] cipher = new byte[plain.length];
        for (int offset = 0, numeroBloco = 1; offset < plain.length;
             offset += BLOCK_SIZE, numeroBloco++) {
            byte[] block = Arrays.copyOfRange(plain, offset, offset + BLOCK_SIZE);
            byte[] encrypted = aes.encrypt(block);
            System.arraycopy(encrypted, 0, cipher, offset, BLOCK_SIZE);
            System.out.println("\nBloco " + numeroBloco + " ASCII: [" +
                    new String(block, StandardCharsets.US_ASCII) + "]");
            System.out.println("Message (HEX): " + bytesToHex(block));
            System.out.println("Cifrado (HEX): " + bytesToHex(encrypted));
        }
        String result = bytesToHex(cipher);
        System.out.println("Resultado completo (HEX): " + result);
        System.out.println("=== FIM DA VALIDAÇÃO AES ===\n");
        return result;
    }

    private String decryptBlocosHex(String message) {
        byte[] cipher = hexToBytes(message);
        if (cipher.length == 0 || cipher.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException(
                    "No modo de validação, o texto cifrado HEX deve conter blocos completos de "
                            + (BLOCK_SIZE * 2) + " dígitos.");
        }
        byte[] plain = new byte[cipher.length];
        for (int offset = 0; offset < cipher.length; offset += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(cipher, offset, offset + BLOCK_SIZE);
            byte[] decrypted = aes.decrypt(block);
            System.arraycopy(decrypted, 0, plain, offset, BLOCK_SIZE);
        }
        return new String(plain, StandardCharsets.US_ASCII);
    }

    // --------------------------------------------------------------- helpers

    /** Deriva a chave AES a partir da senha digitada (SHA-256 truncado). */
    private byte[] deriveKeyMaterial(String chave) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest(chave.getBytes(StandardCharsets.UTF_8));
            return Arrays.copyOf(digest, KEY_MATERIAL_SIZE);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponível", e);
        }
    }

    // PKCS#7 (o "PKCS5" do DES é o mesmo esquema, só que com bloco de 8)
    private byte[] pkcs7Pad(byte[] data) {
        int pad = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = Arrays.copyOf(data, data.length + pad);
        Arrays.fill(padded, data.length, padded.length, (byte) pad);
        return padded;
    }

    private byte[] pkcs7Unpad(byte[] data) {
        if (data.length == 0 || data.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Padding PKCS7 inválido.");
        }
        int pad = data[data.length - 1] & 0xFF;
        if (pad < 1 || pad > BLOCK_SIZE || pad > data.length) {
            throw new IllegalArgumentException("Padding PKCS7 inválido.");
        }
        for (int i = data.length - pad; i < data.length; i++) {
            if ((data[i] & 0xFF) != pad) {
                throw new IllegalArgumentException("Padding PKCS7 inválido.");
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
        // Vetores de teste oficiais do FIPS-197 (apêndice C)
        String plainHex = "00112233445566778899AABBCCDDEEFF";
        String[][] vetores = {
                {"AES-128", "000102030405060708090A0B0C0D0E0F", "69C4E0D86A7B0430D8CDB78070B4C55A"},
                {"AES-192", "000102030405060708090A0B0C0D0E0F1011121314151617", "DDA97CA4864CDFE06EAF70A0EC0D7191"},
                {"AES-256", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "8EA2B7CA516745BFEAFC49904B496089"},
        };
        for (String[] v : vetores) {
            AesEngine engine = new AesEngine(hexToBytes(v[1]));
            String cifrado = bytesToHex(engine.encrypt(hexToBytes(plainHex)));
            String decifrado = bytesToHex(engine.decrypt(hexToBytes(v[2])));
            System.out.println(v[0] + " FIPS: " + cifrado
                    + (v[2].equalsIgnoreCase(cifrado) && plainHex.equalsIgnoreCase(decifrado) ? " OK" : " FAIL"));
        }

        Crypt crypt = new AesCrypt("chave-secreta-aes");
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
