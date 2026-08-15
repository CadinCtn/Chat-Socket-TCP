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
        return criptografar(message, true);
    }

    @Override
    public String decrypt(String message){
        return criptografar(message, false);
    }

    protected String criptografar(String message, boolean encrypt){
        return message;
    }
}
