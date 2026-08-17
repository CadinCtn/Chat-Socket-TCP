package utils;

import criptografia.Crypt;
import criptografia.algoritmos.*;

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
        while(!scanner.hasNextInt()) {
            scanner.next();
            System.out.println("Seleção inválida, insira uma opção válida.");
            System.out.print("Modo: ");
        }
        int selectedCrypt = scanner.nextInt();

        switch(selectedCrypt) {
            case 2:
                System.out.println("Cifra de César selecionada.");
                System.out.print("Insira a chave (número inteiro): ");
                System.out.print("Chave: ");
                while(!scanner.hasNextInt()) {
                    scanner.next();
                    System.out.println("Seleção inválida, insira uma opção válida.");
                    System.out.print("Chave: ");
                }
                int Key = scanner.nextInt();
                return new CesarCrypt(Key);
            case 3:
                System.out.println("Cifra monoalfabética selecionada.");
                System.out.println("Insira a chave (sequência de caracteres): ");
                System.out.println("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                while(!scanner.hasNextLine()) {
                    scanner.next();
                    System.out.println("Chave vazia, insira uma chave.");
                    System.out.print("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                }
                String Key = scanner.nextLine();
                return new MonoalphabeticCrypt(Key);
            case 4:
                return null;
            case 5:
                return null;
            default:
                return new NoCrypt();
        }

    }

    public static void main (String[] args) {
        SelectCryptography();
    }

}