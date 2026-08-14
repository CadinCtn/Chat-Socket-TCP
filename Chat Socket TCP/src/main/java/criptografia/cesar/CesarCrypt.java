package criptografia.cesar;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

public class CesarCrypt {

    private final List<Character> rodaPadrao;
    private final List<Character> rodaEncriptada;
    private final int chave;

    public CesarCrypt(int chave) {
        this.rodaPadrao = new ArrayList<>();
        this.rodaEncriptada = new ArrayList<>();

        this.chave = chave;

        for(char c = 'A'; c <= 'Z'; c++){
            rodaPadrao.add(c);
            char letraCriptografada = (char) (c + chave);

            if(chave > 26) letraCriptografada = (char) (letraCriptografada % 26);
            if(letraCriptografada > 'Z') letraCriptografada-=26;

            rodaEncriptada.add(letraCriptografada);
        }
    }

    private char getLetraCriptografada(char letra, boolean encrypt){
        if(encrypt) {
            return rodaEncriptada.get(rodaPadrao.indexOf(letra));
        } else {
            return rodaPadrao.get(rodaEncriptada.indexOf(letra));
        }
    }

    private String criptografiaDeCesar(String message, boolean encrypt){
        StringBuilder mensagemCriptografada = new StringBuilder();

        for(String palavra : message.split(" ")){
            for(char letra : palavra.toCharArray()){
                mensagemCriptografada.append(
                        getLetraCriptografada(letra, encrypt)
                );
            }
            mensagemCriptografada.append(" ");
        }
        return mensagemCriptografada.toString();
    }


    public String encrypt(String message){
        return criptografiaDeCesar(message, true);
    }

    public String decrypt(String message){
        return criptografiaDeCesar(message, false);
    }


    public static void main(String[] args) {
        CesarCrypt cesarCrypt = new CesarCrypt(4);

        String message = Pattern
                .compile("\\p{InCombiningDiacriticalMarks}+")
                .matcher(
                        Normalizer
                                .normalize("Agora fúcionou HAHA",
                                            Normalizer.Form.NFD))
                .replaceAll("");

        System.out.println(cesarCrypt.encrypt(message.toUpperCase()));
        System.out.println(cesarCrypt.decrypt(cesarCrypt.encrypt(message.toUpperCase())));
    }


}
