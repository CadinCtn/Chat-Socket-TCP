package criptografia.algoritmos;

import criptografia.AbstractCrypt;
import criptografia.Crypt;

public class VigenereCrypt extends AbstractCrypt {

    private int indexCifra;
    private final String cifra;

    public VigenereCrypt(String cifra){
        super();
        this.cifra = cifra;
    }

    @Override
    protected char getLetraCriptografada(char letra, boolean encrypt){
        if(letra < 65 || letra > 90) return letra;

        int x = letra-65;
        int y = cifra.toCharArray()[indexCifra]-65;
        if(encrypt){
            return rodaAlfabetoPadrao.get(((x+y)%26));
        } else {
            return rodaAlfabetoPadrao.get(((x-y+26)%26));
        }
    }

    @Override
    protected String applyCrypt(String message, boolean encrypt){
        this.indexCifra = 0;
        StringBuilder mensagemCriptografada = new StringBuilder();

        for(String palavra : message.split(" ")){
            for(char letra : palavra.toCharArray()){
                mensagemCriptografada.append(
                        getLetraCriptografada(letra, encrypt)
                );
                indexCifra++;
                if(indexCifra >= cifra.length()) indexCifra = 0;
            }
            mensagemCriptografada.append(" ");
        }
        return mensagemCriptografada.toString();
    }


    public static void main(String[] args) {
        Crypt crypt = new VigenereCrypt("FOGO");
        String message = "ATACARBASENORTE10:45)".toUpperCase();
        String cryptedMessage = crypt.encrypt(message);
        System.out.println(cryptedMessage);
        System.out.println(crypt.decrypt(cryptedMessage));
    }

}
