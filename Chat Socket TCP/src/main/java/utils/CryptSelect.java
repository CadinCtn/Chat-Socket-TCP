package utils;

import criptografia.Crypt;
import criptografia.algoritmos.*;

import java.util.Scanner;

public class CryptSelect {

    public static Crypt SelectCryptography(Scanner scanner) {

        System.out.println("Escolha o modo de transmissão (número):");
        System.out.println("1 - Sem criptografia");
        System.out.println("2 - Cifra de César");
        System.out.println("3 - Cifra monoalfabética");
        System.out.println("4 - Cifra Playfair");
        System.out.println("5 - Cifra de Vigenère");
        System.out.print("Modo: ");

        int selectedCrypt;

        while (!scanner.hasNextInt()) {
            scanner.next();
            System.out.println("Seleção inválida, insira uma opção válida.");
            System.out.print("Modo: ");
        }

        selectedCrypt = scanner.nextInt();
        scanner.nextLine(); // limpa o \n deixado pelo nextInt()

        switch (selectedCrypt) {

            case 1:
                System.out.println("Sem criptografia selecionada.");
                return new NoCrypt();

            case 2:
                System.out.println("Cifra de César selecionada.");
                System.out.print("Chave (número inteiro): ");

                while (!scanner.hasNextInt()) {
                    scanner.next();
                    System.out.println("Chave inválida, insira um número inteiro.");
                    System.out.print("Chave: ");
                }

                int key = scanner.nextInt();
                scanner.nextLine();

                return new CesarCrypt(key);

            case 3:
                System.out.println("Cifra monoalfabética selecionada.");
                System.out.println("Insira a chave (sequência de 26 caracteres):");
                System.out.println("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                System.out.print("Chave: ");

                String key2 = scanner.nextLine();

                return new MonoalphabeticCrypt(
                        Utils.cleanString(key2)
                );

            case 4:
                System.out.println("Cifra Playfair selecionada.");
                System.out.print("Chave: ");

                String playfairKey = Utils.cleanString(scanner.nextLine());

                if (playfairKey.isEmpty()) {
                    System.out.println("A chave não pode ser vazia.");
                    return SelectCryptography(scanner);
                }

                return new PlayfairCrypt(playfairKey);

            case 5:
                System.out.println("Cifra de Vigenère selecionada.");
                System.out.print("Chave: ");

                String vigenereKey = scanner.nextLine();

                vigenereKey = Utils.cleanString(vigenereKey);

                if (vigenereKey.isEmpty()) {
                    System.out.println("A chave não pode ser vazia.");
                    return SelectCryptography(scanner);
                }

                return new VigenereCrypt(vigenereKey);

            default:
                System.out.println("Opção inválida.");
                return SelectCryptography(scanner);
        }
    }
}