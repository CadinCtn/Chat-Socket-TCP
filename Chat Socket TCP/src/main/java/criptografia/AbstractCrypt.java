package criptografia;

import java.util.ArrayList;
import java.util.List;

public abstract class AbstractCrypt implements Crypt {

    protected final List<Character> rodaPadrao;
    protected final List<Character> rodaEncriptada;

    public AbstractCrypt() {
        this.rodaPadrao = new ArrayList<>();
        this.rodaEncriptada = new ArrayList<>();

        for(char c = 'A'; c <= 'Z'; c++){
            rodaPadrao.add(c);
        }
    }

    public char getLetraCriptografada(char letra, boolean encrypt){
        if(encrypt) {
            return rodaEncriptada.get(rodaPadrao.indexOf(letra));
        } else {
            return rodaPadrao.get(rodaEncriptada.indexOf(letra));
        }
    }

    @Override
    public String encrypt(String message){
        return applyCrypt(message, true);
    }

    public String applyCrypt(String message, boolean encrypt){
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
    public String decrypt(String message){
        return applyCrypt(message, false);
    }

}
