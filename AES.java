import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class AES {

    private final static byte[][] SBOX = {
            { (byte) 0x63, (byte) 0x7C, (byte) 0x77, (byte) 0x7B, (byte) 0xF2, (byte) 0x6B, (byte) 0x6F, (byte) 0xC5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2B, (byte) 0xFE, (byte) 0xD7, (byte) 0xAB, (byte) 0x76 },
            { (byte) 0xCA, (byte) 0x82, (byte) 0xC9, (byte) 0x7D, (byte) 0xFA, (byte) 0x59, (byte) 0x47, (byte) 0xF0, (byte) 0xAD, (byte) 0xD4, (byte) 0xA2, (byte) 0xAF, (byte) 0x9C, (byte) 0xA4, (byte) 0x72, (byte) 0xC0 },
            { (byte) 0xB7, (byte) 0xFD, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3F, (byte) 0xF7, (byte) 0xCC, (byte) 0x34, (byte) 0xA5, (byte) 0xE5, (byte) 0xF1, (byte) 0x71, (byte) 0xD8, (byte) 0x31, (byte) 0x15 },
            { (byte) 0x04, (byte) 0xC7, (byte) 0x23, (byte) 0xC3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9A, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xE2, (byte) 0xEB, (byte) 0x27, (byte) 0xB2, (byte) 0x75 },
            { (byte) 0x09, (byte) 0x83, (byte) 0x2C, (byte) 0x1A, (byte) 0x1B, (byte) 0x6E, (byte) 0x5A, (byte) 0xA0, (byte) 0x52, (byte) 0x3B, (byte) 0xD6, (byte) 0xB3, (byte) 0x29, (byte) 0xE3, (byte) 0x2F, (byte) 0x84 },
            { (byte) 0x53, (byte) 0xD1, (byte) 0x00, (byte) 0xED, (byte) 0x20, (byte) 0xFC, (byte) 0xB1, (byte) 0x5B, (byte) 0x6A, (byte) 0xCB, (byte) 0xBE, (byte) 0x39, (byte) 0x4A, (byte) 0x4C, (byte) 0x58, (byte) 0xCF },
            { (byte) 0xD0, (byte) 0xEF, (byte) 0xAA, (byte) 0xFB, (byte) 0x43, (byte) 0x4D, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xF9, (byte) 0x02, (byte) 0x7F, (byte) 0x50, (byte) 0x3C, (byte) 0x9F, (byte) 0xA8 },
            { (byte) 0x51, (byte) 0xA3, (byte) 0x40, (byte) 0x8F, (byte) 0x92, (byte) 0x9D, (byte) 0x38, (byte) 0xF5, (byte) 0xBC, (byte) 0xB6, (byte) 0xDA, (byte) 0x21, (byte) 0x10, (byte) 0xFF, (byte) 0xF3, (byte) 0xD2 },
            { (byte) 0xCD, (byte) 0x0C, (byte) 0x13, (byte) 0xEC, (byte) 0x5F, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xC4, (byte) 0xA7, (byte) 0x7E, (byte) 0x3D, (byte) 0x64, (byte) 0x5D, (byte) 0x19, (byte) 0x73 },
            { (byte) 0x60, (byte) 0x81, (byte) 0x4F, (byte) 0xDC, (byte) 0x22, (byte) 0x2A, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xEE, (byte) 0xB8, (byte) 0x14, (byte) 0xDE, (byte) 0x5E, (byte) 0x0B, (byte) 0xDB },
            { (byte) 0xE0, (byte) 0x32, (byte) 0x3A, (byte) 0x0A, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5C, (byte) 0xC2, (byte) 0xD3, (byte) 0xAC, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xE4, (byte) 0x79 },
            { (byte) 0xE7, (byte) 0xC8, (byte) 0x37, (byte) 0x6D, (byte) 0x8D, (byte) 0xD5, (byte) 0x4E, (byte) 0xA9, (byte) 0x6C, (byte) 0x56, (byte) 0xF4, (byte) 0xEA, (byte) 0x65, (byte) 0x7A, (byte) 0xAE, (byte) 0x08 },
            { (byte) 0xBA, (byte) 0x78, (byte) 0x25, (byte) 0x2E, (byte) 0x1C, (byte) 0xA6, (byte) 0xB4, (byte) 0xC6, (byte) 0xE8, (byte) 0xDD, (byte) 0x74, (byte) 0x1F, (byte) 0x4B, (byte) 0xBD, (byte) 0x8B, (byte) 0x8A },
            { (byte) 0x70, (byte) 0x3E, (byte) 0xB5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xF6, (byte) 0x0E, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xB9, (byte) 0x86, (byte) 0xC1, (byte) 0x1D, (byte) 0x9E },
            { (byte) 0xE1, (byte) 0xF8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xD9, (byte) 0x8E, (byte) 0x94, (byte) 0x9B, (byte) 0x1E, (byte) 0x87, (byte) 0xE9, (byte) 0xCE, (byte) 0x55, (byte) 0x28, (byte) 0xDF },
            { (byte) 0x8C, (byte) 0xA1, (byte) 0x89, (byte) 0x0D, (byte) 0xBF, (byte) 0xE6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2D, (byte) 0x0F, (byte) 0xB0, (byte) 0x54, (byte) 0xBB, (byte) 0x16 }
    };

    private final static byte[][] SBOX_INVERTIDA = {
            { (byte) 0x52, (byte) 0x09, (byte) 0x6A, (byte) 0xD5, (byte) 0x30, (byte) 0x36, (byte) 0xA5, (byte) 0x38, (byte) 0xBF, (byte) 0x40, (byte) 0xA3, (byte) 0x9E, (byte) 0x81, (byte) 0xF3, (byte) 0xD7, (byte) 0xFB },
            { (byte) 0x7C, (byte) 0xE3, (byte) 0x39, (byte) 0x82, (byte) 0x9B, (byte) 0x2F, (byte) 0xFF, (byte) 0x87, (byte) 0x34, (byte) 0x8E, (byte) 0x43, (byte) 0x44, (byte) 0xC4, (byte) 0xDE, (byte) 0xE9, (byte) 0xCB },
            { (byte) 0x54, (byte) 0x7B, (byte) 0x94, (byte) 0x32, (byte) 0xA6, (byte) 0xC2, (byte) 0x23, (byte) 0x3D, (byte) 0xEE, (byte) 0x4C, (byte) 0x95, (byte) 0x0B, (byte) 0x42, (byte) 0xFA, (byte) 0xC3, (byte) 0x4E },
            { (byte) 0x08, (byte) 0x2E, (byte) 0xA1, (byte) 0x66, (byte) 0x28, (byte) 0xD9, (byte) 0x24, (byte) 0xB2, (byte) 0x76, (byte) 0x5B, (byte) 0xA2, (byte) 0x49, (byte) 0x6D, (byte) 0x8B, (byte) 0xD1, (byte) 0x25 },
            { (byte) 0x72, (byte) 0xF8, (byte) 0xF6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xD4, (byte) 0xA4, (byte) 0x5C, (byte) 0xCC, (byte) 0x5D, (byte) 0x65, (byte) 0xB6, (byte) 0x92 },
            { (byte) 0x6C, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xFD, (byte) 0xED, (byte) 0xB9, (byte) 0xDA, (byte) 0x5E, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xA7, (byte) 0x8D, (byte) 0x9D, (byte) 0x84 },
            { (byte) 0x90, (byte) 0xD8, (byte) 0xAB, (byte) 0x00, (byte) 0x8C, (byte) 0xBC, (byte) 0xD3, (byte) 0x0A, (byte) 0xF7, (byte) 0xE4, (byte) 0x58, (byte) 0x05, (byte) 0xB8, (byte) 0xB3, (byte) 0x45, (byte) 0x06 },
            { (byte) 0xD0, (byte) 0x2C, (byte) 0x1E, (byte) 0x8F, (byte) 0xCA, (byte) 0x3F, (byte) 0x0F, (byte) 0x02, (byte) 0xC1, (byte) 0xAF, (byte) 0xBD, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8A, (byte) 0x6B },
            { (byte) 0x3A, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4F, (byte) 0x67, (byte) 0xDC, (byte) 0xEA, (byte) 0x97, (byte) 0xF2, (byte) 0xCF, (byte) 0xCE, (byte) 0xF0, (byte) 0xB4, (byte) 0xE6, (byte) 0x73 },
            { (byte) 0x96, (byte) 0xAC, (byte) 0x74, (byte) 0x22, (byte) 0xE7, (byte) 0xAD, (byte) 0x35, (byte) 0x85, (byte) 0xE2, (byte) 0xF9, (byte) 0x37, (byte) 0xE8, (byte) 0x1C, (byte) 0x75, (byte) 0xDF, (byte) 0x6E },
            { (byte) 0x47, (byte) 0xF1, (byte) 0x1A, (byte) 0x71, (byte) 0x1D, (byte) 0x29, (byte) 0xC5, (byte) 0x89, (byte) 0x6F, (byte) 0xB7, (byte) 0x62, (byte) 0x0E, (byte) 0xAA, (byte) 0x18, (byte) 0xBE, (byte) 0x1B },
            { (byte) 0xFC, (byte) 0x56, (byte) 0x3E, (byte) 0x4B, (byte) 0xC6, (byte) 0xD2, (byte) 0x79, (byte) 0x20, (byte) 0x9A, (byte) 0xDB, (byte) 0xC0, (byte) 0xFE, (byte) 0x78, (byte) 0xCD, (byte) 0x5A, (byte) 0xF4 },
            { (byte) 0x1F, (byte) 0xDD, (byte) 0xA8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xC7, (byte) 0x31, (byte) 0xB1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xEC, (byte) 0x5F },
            { (byte) 0x60, (byte) 0x51, (byte) 0x7F, (byte) 0xA9, (byte) 0x19, (byte) 0xB5, (byte) 0x4A, (byte) 0x0D, (byte) 0x2D, (byte) 0xE5, (byte) 0x7A, (byte) 0x9F, (byte) 0x93, (byte) 0xC9, (byte) 0x9C, (byte) 0xEF },
            { (byte) 0xA0, (byte) 0xE0, (byte) 0x3B, (byte) 0x4D, (byte) 0xAE, (byte) 0x2A, (byte) 0xF5, (byte) 0xB0, (byte) 0xC8, (byte) 0xEB, (byte) 0xBB, (byte) 0x3C, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61 },
            { (byte) 0x17, (byte) 0x2B, (byte) 0x04, (byte) 0x7E, (byte) 0xBA, (byte) 0x77, (byte) 0xD6, (byte) 0x26, (byte) 0xE1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0C, (byte) 0x7D },
    };

    public static void main(String[] args) throws Exception {
        boolean loop = true;
        Scanner scanner = new Scanner(System.in);

        while (loop) {
            System.out.print("Quer cifrar (C) ou decifrar (D)? S para sair: ");
            String opcao = scanner.next();

            if (opcao.equalsIgnoreCase("c")) {
                File file;

                do {
                    System.out.print("Entre o caminho do arquivo que quer cifrar (a partir do diretório atual): ");
                    String caminhoDoArquivo = System.getProperty("user.dir") + scanner.next();
                    file = new File(caminhoDoArquivo);

                    if (!file.exists()) {
                        System.out.println("ERRO: arquivo não encontrado.");
                    }

                } while (!file.exists());

                System.out.print("Forneça a chave ou tecle G para gerar uma: ");
                String chave = scanner.next();

                if (chave.equalsIgnoreCase("g")) {
                    chave = gerarChaveAleatoria();
                    System.out.println("A sua chave é: " + chave + ". Anote-a para não esquecer.");
                }

                Path path;
                String caminhoDoArquivoCifrado;

                do {
                    System.out.print("Onde guardar o arquivo cifrado (a partir do diretório atual)? ");
                    caminhoDoArquivoCifrado = System.getProperty("user.dir") + scanner.next();
                    path = Paths.get(caminhoDoArquivoCifrado);

                    if (!Files.exists(path)) {
                        Files.createFile(path);
                    }

                } while (!Files.exists(path));

                byte[] textoCifrado = cifrar(Files.readAllBytes(file.toPath()), parseChave(chave));
                Files.write(path, textoCifrado);
                System.out.println("Pronto!");

            } else if (opcao.equalsIgnoreCase("d")) {
                File file;
                do {
                    System.out.print("Entre o caminho do arquivo que quer decifrar (a partir do diretório atual): ");
                    String caminhoDoArquivo = System.getProperty("user.dir") + scanner.next();
                    file = new File(caminhoDoArquivo);

                    if (!file.exists()) {
                        System.out.println("ERRO: arquivo não encontrado.");
                    }

                } while (!file.exists());

                System.out.print("Forneça a chave: ");
                String chave = scanner.next();

                Path path;
                String caminhoDoArquivoDecifrado;

                do {
                    System.out.print("Onde guardar o arquivo decifrado (a partir do diretório atual)? ");
                    caminhoDoArquivoDecifrado = System.getProperty("user.dir") + scanner.next();
                    path = Paths.get(caminhoDoArquivoDecifrado);

                    if (!Files.exists(path)) {
                        Files.createFile(path);
                    }

                } while (!Files.exists(path));

                byte[] textoDecifrado = decifrar(Files.readAllBytes(file.toPath()), parseChave(chave));
                Files.write(path, textoDecifrado);
                System.out.println("Pronto!");

            } else if (opcao.equalsIgnoreCase("s")) {
                loop = false;

            } else {
                System.out.println("ERRO: opção inválida.");
            }
        }

        scanner.close();
    }

    private static byte[] cifrar(byte[] textoSimples, byte[] chave) {
        int numBlocos = (textoSimples.length + 16) / 16;
        byte[] resultadoFinal = new byte[numBlocos * 16];
        byte[][] matrizDeEstado = gerarMatrizDeEstado(chave);
        byte[][] roundKeys = expandirChave(matrizDeEstado);
        byte[][] primeiraRoundKey = new byte[4][4];
        byte[][] ultimaRoundKey = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                primeiraRoundKey[i][j] = roundKeys[i][j];
            }
        }

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                ultimaRoundKey[i][j] = roundKeys[40 + i][j];
            }
        }

        for (int blocoIdx = 0; blocoIdx < numBlocos; blocoIdx++) {
            byte[] blocoAtual = Arrays.copyOfRange(textoSimples, blocoIdx * 16, (blocoIdx + 1) * 16);
            byte[][] roundKeyAtual = new byte[4][4];
            byte[][] estado = new byte[4][4];

            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    estado[j][i] = blocoAtual[i + (j * 4)];
                }
            }

            if (blocoIdx == numBlocos - 1) {
                estado = adicionarPadding(estado);
            }

            estado = addRoundKey(estado, primeiraRoundKey);

            for (int i = 1; i < 10; i++) {
                estado = substituirBytes(estado);
                estado = shiftRows(estado);
                estado = mixColumns(estado);

                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        roundKeyAtual[j][k] = roundKeys[i * 4 + j][k];
                    }
                }

                estado = addRoundKey(estado, roundKeyAtual);
            }

            estado = substituirBytes(estado);
            estado = shiftRows(estado);
            estado = addRoundKey(estado, ultimaRoundKey);

            byte[] blocoCifrado = flattenByteMatrix(estado);
            System.arraycopy(blocoCifrado, 0, resultadoFinal, blocoIdx * 16, 16);
        }

        return resultadoFinal;
    }

    private static byte[] decifrar(byte[] textoCifrado, byte[] chave) {
        int numBlocos = textoCifrado.length / 16;
        byte[] resultadoFinal = new byte[textoCifrado.length];
        byte[][] matrizDeEstado = gerarMatrizDeEstado(chave);
        byte[][] roundKeys = expandirChave(matrizDeEstado);
        byte[][] primeiraRoundKey = new byte[4][4];
        byte[][] ultimaRoundKey = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                primeiraRoundKey[i][j] = roundKeys[i][j];
            }
        }

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                ultimaRoundKey[i][j] = roundKeys[40 + i][j];
            }
        }

        for (int blocoIdx = 0; blocoIdx < numBlocos; blocoIdx++) {
            byte[] blocoAtual = Arrays.copyOfRange(textoCifrado, blocoIdx * 16, (blocoIdx + 1) * 16);
            byte[][] roundKeyAtual = new byte[4][4];
            byte[][] estado = new byte[4][4];

            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    estado[j][i] = blocoAtual[i + (j * 4)];
                }
            }

            estado = addRoundKey(estado, ultimaRoundKey);

            for (int i = 9; i > 0; i--) {
                estado = inverterShiftRows(estado);
                estado = inverterSubstituirPalavras(estado);

                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        roundKeyAtual[j][k] = roundKeys[i * 4 + j][k];
                    }
                }

                estado = addRoundKey(estado, roundKeyAtual);
                estado = inverterMixColumns(estado);
            }

            estado = inverterShiftRows(estado);
            estado = inverterSubstituirPalavras(estado);
            estado = addRoundKey(estado, primeiraRoundKey);

            if (blocoIdx == numBlocos - 1) {
                estado = removerPadding(estado);
            }

            byte[] blocoDecifrado = flattenByteMatrix(estado);
            System.arraycopy(blocoDecifrado, 0, resultadoFinal, blocoIdx * 16, 16);
        }

        return resultadoFinal;
    }

    public static byte[][] adicionarPadding(byte[][] bloco) {
        int casasVazias = 0;

        for (int i = 0; i < bloco.length; i++) {
            for (int j = 0; j < bloco[i].length; j++) {
                if (bloco[i][j] == 0) {
                    casasVazias++;
                }
            }
        }

        int contador = 0;
        for (int i = 3; i >= 0; i--) {
            for (int j = 3; j >= 0; j--) {
                if (bloco[i][j] == 0) {
                    bloco[i][j] = (byte) casasVazias;
                    contador++;
                }

                if (contador == casasVazias) {
                    return bloco;
                }
            }
        }

        return null;
    }

    public static byte[][] removerPadding(byte[][] bloco) {
        byte padding = bloco[3][3];
        int contador = 0;

        loop:
        for (int i = 3; i >= 0; i--) {
            for (int j = 3; j >= 0; j--) {
                bloco[i][j] = 0;
                contador++;

                if (contador == padding) {
                    break loop;
                }
            }
        }

        return bloco;
    }

    public static byte[][]  inverterShiftRows(byte[][] estado) {
        byte[][] novoEstado = new byte[4][4];

        novoEstado[0][0] = estado[0][0];
        novoEstado[1][0] = estado[1][0];
        novoEstado[2][0] = estado[2][0];
        novoEstado[3][0] = estado[3][0];

        novoEstado[0][1] = estado[3][1];
        novoEstado[1][1] = estado[0][1];
        novoEstado[2][1] = estado[1][1];
        novoEstado[3][1] = estado[2][1];

        novoEstado[0][2] = estado[2][2];
        novoEstado[1][2] = estado[3][2];
        novoEstado[2][2] = estado[0][2];
        novoEstado[3][2] = estado[1][2];

        novoEstado[0][3] = estado[1][3];
        novoEstado[1][3] = estado[2][3];
        novoEstado[2][3] = estado[3][3];
        novoEstado[3][3] = estado[0][3];

        return novoEstado;
    }

    private static byte[] flattenByteMatrix(byte[][] byteMatrix) {
        int rows = byteMatrix.length;
        int cols = byteMatrix[0].length;
        byte[] flatArray = new byte[rows * cols];

        int index = 0;
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                flatArray[index++] = byteMatrix[i][j];
            }
        }

        return flatArray;
    }

    private static byte[][] inverterMixColumns(byte[][] bytes) {
        byte[][] tabela = {
                {(byte) 0x0e, (byte) 0x0b, (byte) 0x0d, (byte) 0x09},
                {(byte) 0x09, (byte) 0x0e, (byte) 0x0b, (byte) 0x0d},
                {(byte) 0x0d, (byte) 0x09, (byte) 0x0e, (byte) 0x0b},
                {(byte) 0x0b, (byte) 0x0d, (byte) 0x09, (byte) 0x0e}
        };

        for (int i = 0; i < 4; i++) {
            byte[] coluna = new byte[4];
            for (int j = 0; j < 4; j++) {
                coluna[j] = bytes[i][j];
            }

            bytes[i][0] = (byte) (gmul(coluna[0], tabela[0][0]) ^ gmul(coluna[1], tabela[0][1]) ^ gmul(coluna[2], tabela[0][2]) ^ gmul(coluna[3], tabela[0][3]));
            bytes[i][1] = (byte) (gmul(coluna[0], tabela[1][0]) ^ gmul(coluna[1], tabela[1][1]) ^ gmul(coluna[2], tabela[1][2]) ^ gmul(coluna[3], tabela[1][3]));
            bytes[i][2] = (byte) (gmul(coluna[0], tabela[2][0]) ^ gmul(coluna[1], tabela[2][1]) ^ gmul(coluna[2], tabela[2][2]) ^ gmul(coluna[3], tabela[2][3]));
            bytes[i][3] = (byte) (gmul(coluna[0], tabela[3][0]) ^ gmul(coluna[1], tabela[3][1]) ^ gmul(coluna[2], tabela[3][2]) ^ gmul(coluna[3], tabela[3][3]));
        }

        return bytes;
    }

    private static byte gmul(byte a, byte b) {
        byte p = 0;
        byte hiBitSet;

        for (int i = 7; i >= 0; i--) {
            if ((b & 0x01) != 0) {
                p ^= a;
            }

            hiBitSet = (byte) (a & 0x80);
            a <<= 1;

            if (hiBitSet != 0) {
                a ^= 0x1b;
            }

            b >>= 1;
        }

        return p;
    }

    private static byte[][] mixColumns(byte[][] matrizDeEstado) {
        for (int i = 0; i < 4; i++) {
            byte[] coluna = new byte[4];
            for (int j = 0; j < 4; j++) {
                coluna[j] = matrizDeEstado[i][j];
            }

            matrizDeEstado[i][0] = (byte) (multiplicarPor02(coluna[0]) ^ multiplicarPor03(coluna[1]) ^ coluna[2] ^ coluna[3]);
            matrizDeEstado[i][1] = (byte) (coluna[0] ^ multiplicarPor02(coluna[1]) ^ multiplicarPor03(coluna[2]) ^ coluna[3]);
            matrizDeEstado[i][2] = (byte) (coluna[0] ^ coluna[1] ^ multiplicarPor02(coluna[2]) ^ multiplicarPor03(coluna[3]));
            matrizDeEstado[i][3] = (byte) (multiplicarPor03(coluna[0]) ^ coluna[1] ^ coluna[2] ^ multiplicarPor02(coluna[3]));
        }

        return matrizDeEstado;
    }

    private static byte multiplicarPor02(byte b) {
        int result = (b & 0xFF) << 1;
        if ((result & 0x100) != 0) {
            result ^= 0x1B;
        }
        return (byte) (result & 0xFF);
    }

    private static byte multiplicarPor03(byte b) {
        return (byte) (multiplicarPor02(b) ^ b);
    }

    public static byte[][] shiftRows(byte[][] estado) {
        byte[][] novoEstado = new byte[4][4];

        novoEstado[0][0] = estado[0][0];
        novoEstado[1][0] = estado[1][0];
        novoEstado[2][0] = estado[2][0];
        novoEstado[3][0] = estado[3][0];

        novoEstado[0][1] = estado[1][1];
        novoEstado[1][1] = estado[2][1];
        novoEstado[2][1] = estado[3][1];
        novoEstado[3][1] = estado[0][1];

        novoEstado[0][2] = estado[2][2];
        novoEstado[1][2] = estado[3][2];
        novoEstado[2][2] = estado[0][2];
        novoEstado[3][2] = estado[1][2];

        novoEstado[0][3] = estado[3][3];
        novoEstado[1][3] = estado[0][3];
        novoEstado[2][3] = estado[1][3];
        novoEstado[3][3] = estado[2][3];

        return novoEstado;
    }

    public static byte[][] addRoundKey(byte[][] estado, byte[][] roundKey) {
        byte[][] novoEstado = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                novoEstado[i][j] = (byte) (estado[i][j] ^ roundKey[i][j]);
            }
        }

        return novoEstado;
    }

    protected static byte[][] gerarMatrizDeEstado(byte[] chave) {
        byte[][] matrizDeEstado = new byte[4][4];
        int contador = 0;

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                matrizDeEstado[i][j] = chave[contador];
                contador++;
            }
        }

        return matrizDeEstado;
    }

    private static byte[][] expandirChave(byte[][] matrizDeEstado) {
        byte[][] roundKeys = new byte[44][4];
        byte[][] temp = new byte[1][4];
        byte[][] palavra = new byte[1][4];
        byte[][] roundConstant;
        int contador = 1;

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                roundKeys[i][j] = matrizDeEstado[i][j];
            }
        }

        for (int i = 4; i < 44; i++) {
            if (i % 4 == 0) {

                for (int j = 0; j < 4; j++) {
                    temp[0][j] = roundKeys[i - 1][j];
                }

                temp = rotacionarBytes(temp);
                temp = substituirBytes(temp);
                roundConstant = gerarRoundConstant(contador++);
                temp = xor(temp, roundConstant);

                for (int j = 0; j < 4; j++) {
                    palavra[0][j] = roundKeys[i - 4][j];
                }

                temp = xor(temp, palavra);

                for (int j = 0; j < 4; j++) {
                    roundKeys[i][j] = temp[0][j];
                }

            } else {
                for (int j = 0; j < 4; j++) {
                    palavra[0][j] = roundKeys[i - 4][j];
                }

                for (int j = 0; j < 4; j++) {
                    temp[0][j] = roundKeys[i - 1][j];
                }

                temp = xor(temp, palavra);

                for (int j = 0; j < 4; j++) {
                    roundKeys[i][j] = temp[0][j];
                }
            }
        }

        return roundKeys;
    }

    private static byte[][] rotacionarBytes(byte[][] bytes) {
        byte[][] temp = new byte[1][4];

        temp[0][0] = bytes[0][0];
        temp[0][1] = bytes[0][1];
        temp[0][2] = bytes[0][2];
        temp[0][3] = bytes[0][3];

        bytes[0][0] = temp[0][1];
        bytes[0][1] = temp[0][2];
        bytes[0][2] = temp[0][3];
        bytes[0][3] = temp[0][0];

        return bytes;
    }

    private static byte[][] gerarRoundConstant(int numero) {
        byte[][] roundConstant = new byte[1][4];

        switch (numero) {
            case 1:
                roundConstant[0][0] = (byte) 0x01;
                break;
            case 2:
                roundConstant[0][0] = (byte) 0x02;
                break;
            case 3:
                roundConstant[0][0] = (byte) 0x04;
                break;
            case 4:
                roundConstant[0][0] = (byte) 0x08;
                break;
            case 5:
                roundConstant[0][0] = (byte) 0x10;
                break;
            case 6:
                roundConstant[0][0] = (byte) 0x20;
                break;
            case 7:
                roundConstant[0][0] = (byte) 0x40;
                break;
            case 8:
                roundConstant[0][0] = (byte) 0x80;
                break;
            case 9:
                roundConstant[0][0] = (byte) 0x1B;
                break;
            case 10:
                roundConstant[0][0] = (byte) 0x36;
                break;
        }

        roundConstant[0][1] = (byte) 0x00;
        roundConstant[0][2] = (byte) 0x00;
        roundConstant[0][3] = (byte) 0x00;

        return roundConstant;
    }

    public static byte[][] xor(byte[][] matriz1, byte[][] matriz2) {
        byte[][] resultado = new byte[matriz1.length][matriz1[0].length];

        for (int i = 0; i < matriz1.length; i++) {
            for (int j = 0; j < matriz1[i].length; j++) {
                resultado[i][j] = (byte) (matriz1[i][j] ^ matriz2[i][j]);
            }
        }

        return resultado;
    }

    private static byte[][] substituirBytes(byte[][] bytes) {
        byte[][] resultado = new byte[bytes.length][4];

        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 4; j++) {
                int fileira = (bytes[i][j] & 0xF0) >> 4;
                int coluna = (bytes[i][j] & 0x0F);
                resultado[i][j] = (byte) SBOX[fileira][coluna];
            }
        }

        return resultado;
    }

    private static byte[][] inverterSubstituirPalavras(byte[][] bytes) {
        byte[][] novoEstado = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                byte valor = bytes[i][j];
                int indice = valor & 0xFF;
                novoEstado[i][j] = SBOX_INVERTIDA[indice / 16][indice % 16];
            }
        }

        return novoEstado;
    }

    public static byte[] parseChave(String chave) {
        String[] stringArray = chave.split(",");
        byte[] bytes = new byte[stringArray.length];

        for (int i = 0; i < stringArray.length; i++) {
            bytes[i] = (byte) Integer.parseInt(stringArray[i]);
        }

        return bytes;
    }

    private static String gerarChaveAleatoria() {
        Random random = new Random();
        byte[] chave = new byte[16];
        random.nextBytes(chave);

        StringBuilder chaveFormatada = new StringBuilder();

        for (int i = 0; i < chave.length; i++) {
            chaveFormatada.append(chave[i] & 0xff);
            if (i < chave.length - 1) chaveFormatada.append(",");
        }

        return chaveFormatada.toString();
    }
}
