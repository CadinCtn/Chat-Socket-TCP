package utils;

import criptografia.Crypt;
import criptografia.algoritmos.*;
import utils.Utils;

import java.util.Scanner;

public class CryptSelect {

    public static Crypt SelectCryptography() {

        Scanner scanner = new Scanner(System.in);

        System.out.println("Escolha o modo de transmissão (número):");
        System.out.println("1 - Sem criptografia");
        System.out.println("2 - Cifra de César");
        System.out.println("3 - Cifra monoalfabética");
        System.out.println("4 - Cifra Playfair");
        System.out.println("5 - Cifra de Vigenère");
        System.out.print("Modo: ");

        while (!scanner.hasNextInt()) {
            scanner.next();
            System.out.println("Seleção inválida, insira uma opção válida.");
            System.out.print("Modo: ");
        }

        int selectedCrypt = scanner.nextInt();

        switch (selectedCrypt) {

            case 2:
                System.out.println("Cifra de César selecionada.");
                System.out.print("Chave (número inteiro): ");

                while (!scanner.hasNextInt()) {
                    scanner.next();
                    System.out.println("Seleção inválida, insira uma opção válida.");
                    System.out.print("Chave: ");
                }

                int key = scanner.nextInt();
                return new CesarCrypt(key);

            case 3:
                System.out.println("Cifra monoalfabética selecionada.");
                System.out.println("Insira a chave (sequência de 26 caracteres): ");
                System.out.println("ABCDEFGHIJKLMNOPQRSTUVWXYZ");

                String key2 = scanner.next();

                return new MonoalphabeticCrypt(Utils.cleanString(key2));

            case 4:
                System.out.println("Cifra Playfair selecionada.");
                return null;

            case 5:
                System.out.println("Cifra de Vigenère selecionada.");
                return null;

            default:
                return new NoCrypt();
        }
    }

    public static void main(String[] args) {
        SelectCryptography();
    }
}