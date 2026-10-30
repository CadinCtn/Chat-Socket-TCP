package criptografia.algoritmos.aes;

/*
AES de 128 bits de bloco
Aceita chaves de 128, 192 ou 256 bits (10, 12 ou 14 rodadas).
Decifra um bloco de 16 bytes de cada vez.
Organização do estado: state[linha + 4 * coluna]
Os 16 bytes do bloco preenchem as colunas da matriz 4x4 de cima para baixo.
*/

public class AesEngine {

    public static final int BLOCK_SIZE = 16;

    private static final int[] SBOX = new int[256];
    private static final int[] INV_SBOX = new int[256];

    // S-box gerada a partir da definição matemática
    // (inverso multiplicativo em GF(2^8) + transformação afim).
    static {
        for (int i = 0; i < 256; i++) {
            int b = inverso(i);
            int s = b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63;
            SBOX[i] = s & 0xFF;
            INV_SBOX[s & 0xFF] = i;
        }
    }

    private final int rounds;
    private final int[] roundKey; // Guarda 16 bytes de chave para cada rodada, incluindo a inicial.

    // Expande uma chave AES válida nas chaves usadas em cada rodada.
    public AesEngine(byte[] key) {
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("Chave AES deve ter 16, 24 ou 32 bytes.");
        }
        int nk = key.length / 4;          // Número de palavras de 4 bytes na chave.
        this.rounds = nk + 6;             // Define 10, 12 ou 14 rodadas conforme o tamanho da chave.
        int totalWords = 4 * (rounds + 1);
        this.roundKey = new int[totalWords * 4];

        for (int i = 0; i < key.length; i++) {
            roundKey[i] = key[i] & 0xFF;
        }

        int rcon = 1;
        int[] temp = new int[4];
        for (int i = nk; i < totalWords; i++) {
            for (int j = 0; j < 4; j++) {
                temp[j] = roundKey[(i - 1) * 4 + j];
            }
            if (i % nk == 0) {
                // Gira a palavra, substitui seus bytes pela S-box e aplica a constante da rodada.
                int t0 = temp[0];
                temp[0] = SBOX[temp[1]] ^ rcon;
                temp[1] = SBOX[temp[2]];
                temp[2] = SBOX[temp[3]];
                temp[3] = SBOX[t0];
                rcon = xtime(rcon);
            } else if (nk > 6 && i % nk == 4) {
                // No AES-256, aplica uma substituição extra pela S-box nesta palavra.
                for (int j = 0; j < 4; j++) {
                    temp[j] = SBOX[temp[j]];
                }
            }
            for (int j = 0; j < 4; j++) {
                roundKey[i * 4 + j] = roundKey[(i - nk) * 4 + j] ^ temp[j];
            }
        }
    }

    // Cifra um bloco de 16 bytes aplicando as rodadas do AES.
    byte[] encrypt(byte[] block) {
        int[] state = toState(block);

        addRoundKey(state, 0);
        for (int round = 1; round < rounds; round++) {
            subBytes(state, SBOX);
            shiftRows(state);
            mixColumns(state, false);
            addRoundKey(state, round);
        }
        subBytes(state, SBOX);
        shiftRows(state);
        addRoundKey(state, rounds);

        return fromState(state);
    }

    // Decifra um bloco de 16 bytes aplicando as operações inversas do AES.
    byte[] decrypt(byte[] block) {
        int[] state = toState(block);

        addRoundKey(state, rounds);
        for (int round = rounds - 1; round >= 1; round--) {
            invShiftRows(state);
            subBytes(state, INV_SBOX);
            addRoundKey(state, round);
            mixColumns(state, true);
        }
        invShiftRows(state);
        subBytes(state, INV_SBOX);
        addRoundKey(state, 0);

        return fromState(state);
    }

    // ---------------------------------------------------------------- rodada

    // Combina o estado com a chave da rodada usando XOR.
    private void addRoundKey(int[] state, int round) {
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKey[round * 16 + i];
        }
    }

    // Substitui cada byte do estado pela entrada correspondente na tabela.
    private static void subBytes(int[] state, int[] box) {
        for (int i = 0; i < 16; i++) {
            state[i] = box[state[i]];
        }
    }

    // Rotaciona cada linha do estado para a esquerda conforme seu índice.
    private static void shiftRows(int[] state) {
        int[] old = state.clone();
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r + 4 * c] = old[r + 4 * ((c + r) % 4)];
            }
        }
    }

    // Desfaz as rotações aplicadas às linhas do estado.
    private static void invShiftRows(int[] state) {
        int[] old = state.clone();
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r + 4 * ((c + r) % 4)] = old[r + 4 * c];
            }
        }
    }

    // Mistura os bytes de cada coluna usando a transformação direta ou inversa.
    private static void mixColumns(int[] state, boolean inverse) {
        int m0 = inverse ? 14 : 2;
        int m1 = inverse ? 11 : 3;
        int m2 = inverse ? 13 : 1;
        int m3 = inverse ? 9 : 1;

        for (int c = 0; c < 4; c++) {
            int a0 = state[4 * c];
            int a1 = state[4 * c + 1];
            int a2 = state[4 * c + 2];
            int a3 = state[4 * c + 3];

            state[4 * c]     = gmul(a0, m0) ^ gmul(a1, m1) ^ gmul(a2, m2) ^ gmul(a3, m3);
            state[4 * c + 1] = gmul(a0, m3) ^ gmul(a1, m0) ^ gmul(a2, m1) ^ gmul(a3, m2);
            state[4 * c + 2] = gmul(a0, m2) ^ gmul(a1, m3) ^ gmul(a2, m0) ^ gmul(a3, m1);
            state[4 * c + 3] = gmul(a0, m1) ^ gmul(a1, m2) ^ gmul(a2, m3) ^ gmul(a3, m0);
        }
    }

    // ------------------------------------------------------- aritmética GF(2^8)

    // Multiplica por 2 em GF(2^8), reduzindo pelo polinômio do AES quando necessário.
    private static int xtime(int a) {
        int r = (a << 1) & 0xFF;
        return (a & 0x80) != 0 ? r ^ 0x1B : r;
    }

    // Multiplica dois valores no campo finito GF(2^8).
    private static int gmul(int a, int b) {
        int result = 0;
        while (b != 0) {
            if ((b & 1) != 0) {
                result ^= a;
            }
            a = xtime(a);
            b >>= 1;
        }
        return result;
    }

    // Encontra o inverso multiplicativo em GF(2^8); zero permanece zero na S-box.
    private static int inverso(int a) {
        if (a == 0) return 0;
        for (int x = 1; x < 256; x++) {
            if (gmul(a, x) == 1) return x;
        }
        throw new IllegalStateException("Sem inverso em GF(2^8)");
    }

    // Rotaciona os oito bits para a esquerda sem descartar os bits deslocados.
    private static int rotl8(int value, int shift) {
        return ((value << shift) | (value >>> (8 - shift))) & 0xFF;
    }

    // ------------------------------------------------------------ conversões

    // Valida o bloco e converte seus bytes para o estado interno do AES.
    private static int[] toState(byte[] block) {
        if (block.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("Bloco AES deve ter 16 bytes.");
        }
        int[] state = new int[16];
        for (int i = 0; i < 16; i++) {
            state[i] = block[i] & 0xFF;
        }
        return state;
    }

    // Converte o estado interno do AES em um bloco de 16 bytes.
    private static byte[] fromState(int[] state) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            out[i] = (byte) state[i];
        }
        return out;
    }
}
