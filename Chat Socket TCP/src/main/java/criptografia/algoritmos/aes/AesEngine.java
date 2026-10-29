package criptografia.algoritmos.aes;

/**
 * AES de 128 bits de bloco (FIPS-197). Aceita chaves de 128, 192 ou 256 bits
 * (10, 12 ou 14 rodadas).
 *
 * Assim como o DesEngine, esta classe só sabe cifrar/decifrar UM bloco.
 * Modo de operação (CBC), padding e Base64 ficam na AesCrypt.
 *
 * Organização do estado: state[linha + 4 * coluna], ou seja, os 16 bytes do
 * bloco preenchem as colunas da matriz 4x4 de cima para baixo (como na spec).
 */
public class AesEngine {

    public static final int BLOCK_SIZE = 16;

    private static final int[] SBOX = new int[256];
    private static final int[] INV_SBOX = new int[256];

    // A S-box não é digitada: é gerada a partir da definição matemática
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
    private final int[] roundKey; // 16 * (rounds + 1) bytes, um byte por posição

    public AesEngine(byte[] key) {
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("Chave AES deve ter 16, 24 ou 32 bytes.");
        }
        int nk = key.length / 4;          // palavras de 32 bits na chave
        this.rounds = nk + 6;             // 10, 12 ou 14
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
                // RotWord + SubWord + Rcon
                int t0 = temp[0];
                temp[0] = SBOX[temp[1]] ^ rcon;
                temp[1] = SBOX[temp[2]];
                temp[2] = SBOX[temp[3]];
                temp[3] = SBOX[t0];
                rcon = xtime(rcon);
            } else if (nk > 6 && i % nk == 4) {
                // só no AES-256: SubWord extra
                for (int j = 0; j < 4; j++) {
                    temp[j] = SBOX[temp[j]];
                }
            }
            for (int j = 0; j < 4; j++) {
                roundKey[i * 4 + j] = roundKey[(i - nk) * 4 + j] ^ temp[j];
            }
        }
    }

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

    private void addRoundKey(int[] state, int round) {
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKey[round * 16 + i];
        }
    }

    private static void subBytes(int[] state, int[] box) {
        for (int i = 0; i < 16; i++) {
            state[i] = box[state[i]];
        }
    }

    /** Linha r do estado é rotacionada r posições para a esquerda. */
    private static void shiftRows(int[] state) {
        int[] old = state.clone();
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r + 4 * c] = old[r + 4 * ((c + r) % 4)];
            }
        }
    }

    private static void invShiftRows(int[] state) {
        int[] old = state.clone();
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r + 4 * ((c + r) % 4)] = old[r + 4 * c];
            }
        }
    }

    /** Multiplica cada coluna pela matriz fixa de MixColumns (ou pela inversa). */
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

    /** Multiplica por x (ou seja, por 2) em GF(2^8), polinômio x^8+x^4+x^3+x+1. */
    private static int xtime(int a) {
        int r = (a << 1) & 0xFF;
        return (a & 0x80) != 0 ? r ^ 0x1B : r;
    }

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

    private static int inverso(int a) {
        if (a == 0) return 0;
        for (int x = 1; x < 256; x++) {
            if (gmul(a, x) == 1) return x;
        }
        throw new IllegalStateException("Sem inverso em GF(2^8)");
    }

    private static int rotl8(int value, int shift) {
        return ((value << shift) | (value >>> (8 - shift))) & 0xFF;
    }

    // ------------------------------------------------------------ conversões

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

    private static byte[] fromState(int[] state) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            out[i] = (byte) state[i];
        }
        return out;
    }
}
