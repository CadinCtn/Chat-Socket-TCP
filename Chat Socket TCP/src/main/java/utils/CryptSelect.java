package utils;

import java.util.Scanner;

public class CryptSelect {

    public static Crypt SelectCryptography() {

        Scanner scanner = new Scanner(System.in);

        System.out.println("Escolha o modo de transmissão:");
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
            case 1:
                return null;
            case 2:
                
                return new 
            case 3:
                break;
            case 4:
                break;
            case 5:
                break;
            default:
                return null;

        }

    }

    public static void main (String[] args) {
        SelectCryptography();
    }

}