package criptografia.algoritmos;

import criptografia.AbstractCrypt;
import criptografia.Crypt;

public class NoCrypt extends AbstractCrypt {

    public NoCrypt() {
        super();
        rodaEncriptada.addAll(rodaPadrao);
    }


    public static void main(String[] args) {
        Crypt crypt = new NoCrypt();
        String message = "Teste".toUpperCase();
        String cryptedMessage = crypt.encrypt(message);
        System.out.println(cryptedMessage);
        System.out.println(crypt.decrypt(cryptedMessage));

    }
}
