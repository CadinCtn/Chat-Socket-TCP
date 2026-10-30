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

//    private static final int[] SBOX = new int[256];
//    private static final int[] INV_SBOX = new int[256];
//
//    // S-box gerada a partir da definição matemática
//    // (inverso multiplicativo em GF(2^8) + transformação afim).
//    static {
//        for (int i = 0; i < 256; i++) {
//            int b = inverso(i);
//            int s = b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63;
//            SBOX[i] = s & 0xFF;
//            INV_SBOX[s & 0xFF] = i;
//        }
//    }
//
    // Tabela de substituição S-Box padrão do AES
    private static final int[] SBOX = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    // Tabela S-Box Inversa padrão do AES
    private static final int[] INV_SBOX = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

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
//    private static int inverso(int a) {
//        if (a == 0) return 0;
//        for (int x = 1; x < 256; x++) {
//            if (gmul(a, x) == 1) return x;
//        }
//        throw new IllegalStateException("Sem inverso em GF(2^8)");
//    }

//    // Rotaciona os oito bits para a esquerda sem descartar os bits deslocados.
//    private static int rotl8(int value, int shift) {
//        return ((value << shift) | (value >>> (8 - shift))) & 0xFF;
//    }

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
