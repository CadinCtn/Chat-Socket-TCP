package criptografia;

import java.util.ArrayList;
import java.util.List;

public abstract class AbstractCrypt implements Crypt {

    protected final List<Character> rodaAlfabetoPadrao;
    protected final List<Character> rodaAlfabetoEncriptada;

    public AbstractCrypt() {
        this.rodaAlfabetoPadrao = new ArrayList<>();
        this.rodaAlfabetoEncriptada = new ArrayList<>();

        for(char c = 'A'; c <= 'Z'; c++){
            rodaAlfabetoPadrao.add(c);
        }
    }

    protected char getLetraCriptografada(char letra, boolean encrypt){
        if(encrypt) {
            return rodaAlfabetoEncriptada.get(rodaAlfabetoPadrao.indexOf(letra));
        } else { // decrypt
            return rodaAlfabetoPadrao.get(rodaAlfabetoEncriptada.indexOf(letra));
        }
    }

    @Override
    public String encrypt(String message){
        return applyCrypt(message, true);
    }

    protected String applyCrypt(String message, boolean encrypt){
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
