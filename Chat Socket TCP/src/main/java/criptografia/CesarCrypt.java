package criptografia;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class CesarCrypt implements Crypt{

    private final List<Character> rodaPadrao;
    private final List<Character> rodaEncriptada;

    public CesarCrypt(int chave) {
        this.rodaPadrao = new ArrayList<>();
        this.rodaEncriptada = new ArrayList<>();

        for(char c = 'A'; c <= 'Z'; c++){
            rodaPadrao.add(c);
            char letraCriptografada = (char) (c + chave);

            if(chave > 26) letraCriptografada = (char) (((rodaPadrao.indexOf(c)+1) % 26)+65);
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

    @Override
    public String encrypt(String message){
        return criptografiaDeCesar(message, true);
    }

    @Override
    public String decrypt(String message){
        return criptografiaDeCesar(message, false);
    }


    public static void main(String[] args) {
        CesarCrypt cesarCrypt = new CesarCrypt(50);

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
