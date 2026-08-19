package criptografia.algoritmos;


import criptografia.AbstractCrypt;
import criptografia.Crypt;

public class MonoalphabeticCrypt extends AbstractCrypt {


    public MonoalphabeticCrypt(String chave) {
        super();
        for(char letra : chave.toCharArray()){
            rodaAlfabetoEncriptada.add(letra);
        }
    }


    public static void main(String[] args) {
        Crypt crypt = new MonoalphabeticCrypt("CBADEFGHIJKLMNOPQRSTUVWXYZ");

        String message = "testando criptogracria monofabetica com numeros 123 456 precisa funcionar também com pontos.....".toUpperCase();
        System.out.println(crypt.encrypt(message));
        System.out.println(crypt.decrypt(crypt.encrypt(message)));
    }
}
