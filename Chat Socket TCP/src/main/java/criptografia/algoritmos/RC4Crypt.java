package criptografia.algoritmos;

import criptografia.Crypt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class RC4Crypt implements Crypt {

    private final byte[] key;

    public RC4Crypt(String chave) {
        this.key = chave.getBytes(StandardCharsets.UTF_8);
    }

    // KSA + PRGA. O estado (S, i, j) é sempre reiniciado a cada chamada,
    // para que cada mensagem seja cifrada/decifrada de forma independente
    // (mesmo padrão que VigenereCrypt.applyCrypt já usa, resetando indexCifra).
    private byte[] rc4(byte[] data) {
        int[] S = new int[256];
        for (int i = 0; i < 256; i++) S[i] = i;

        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + (key[i % key.length] & 0xFF)) & 0xFF;
            int tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        }

        byte[] out = new byte[data.length];
        int i = 0;
        j = 0;
        for (int n = 0; n < data.length; n++) {
            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;
            int tmp = S[i]; S[i] = S[j]; S[j] = tmp;
            int k = S[(S[i] + S[j]) & 0xFF];
            out[n] = (byte) (data[n] ^ k);
        }
        return out;
    }

    @Override
    public String encrypt(String message) {
        byte[] plain = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipher = rc4(plain);
        // Base64 evita que bytes crus (ex: 0x0A) quebrem o protocolo
        // baseado em linhas (println / readLine)
        return Base64.getEncoder().encodeToString(cipher);
    }

    @Override
    public String decrypt(String message) {
        byte[] cipher = Base64.getDecoder().decode(message);
        byte[] plain = rc4(cipher); // RC4 é simétrico: mesma função cifra e decifra
        return new String(plain, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        Crypt crypt = new RC4Crypt("D&Ot)[YW");
        String mensagem = "Cybersecurity melhor disciplina do curso.";
        String cifrado = crypt.encrypt(mensagem);
        System.out.println("Cifrado (Base64): " + cifrado);
        System.out.println("Decifrado: " + crypt.decrypt(cifrado));
    }
}