package criptografia;

import java.text.Normalizer;
import java.util.regex.Pattern;

public class CesarCrypt extends AbstractCrypt{

    public CesarCrypt(int chave) {
        super();

        for(char c = 'A'; c <= 'Z'; c++){
            rodaPadrao.add(c);
            char letraCriptografada = (char) (c + chave);

            if(chave > 26) letraCriptografada = (char) (((rodaPadrao.indexOf(c)+1) % 26)+65);
            if(letraCriptografada > 'Z') letraCriptografada-=26;

            rodaEncriptada.add(letraCriptografada);
        }
    }

    @Override
    public String criptografar(String message, boolean encrypt){
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



    public static void main(String[] args) {
        Crypt cesarCrypt = new CesarCrypt(50);

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
