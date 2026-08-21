package criptografia.algoritmos;

import criptografia.AbstractCrypt;
import criptografia.Crypt;


public class PlayfairCrypt extends AbstractCrypt {

    private final StringBuilder crifraSemDuplicatas;
    private final char[][] matrizPlayfair;

    public PlayfairCrypt(String cifra){
        super();
        this.matrizPlayfair = new char[5][5];

        //Remove J do alfabeto
        rodaAlfabetoPadrao.remove('J'-65);

        // Substitui J por I na cifra
        cifra = cifra.replace('J', 'I');

        // Monta cifra retirando caracteres duplicados
        crifraSemDuplicatas = new StringBuilder();
        for(char letra : cifra.toCharArray()){
            if(!crifraSemDuplicatas.toString().contains(letra+"")){
                crifraSemDuplicatas.append(letra);
                rodaAlfabetoPadrao.remove(rodaAlfabetoPadrao.indexOf(letra));
            }
        }

        // Inclui o restante do alfabeto na cifra
        rodaAlfabetoPadrao.forEach(crifraSemDuplicatas::append);

        // Monta matriz
        int indexCifra = 0;
        for(int y = 0; y < 5; y++){
            for(int x = 0; x < 5; x++){
                matrizPlayfair[y][x] = crifraSemDuplicatas.toString().toCharArray()[indexCifra];
                indexCifra++;
            }
        }
    }

    private String getMensagemDigrafada(String message){
        rodaAlfabetoEncriptada.clear();
        message = message.replace('J', 'I');
        StringBuilder mensagemDigrafada = new StringBuilder();

        for(char letra : message.toCharArray()){
            rodaAlfabetoEncriptada.add(letra);
        }

        // Cria digrafos
        for(int i = 0; i < rodaAlfabetoEncriptada.size();){
            mensagemDigrafada.append(rodaAlfabetoEncriptada.get(i));

            if(i+1 < rodaAlfabetoEncriptada.size() &&
                    rodaAlfabetoEncriptada.get(i).equals(rodaAlfabetoEncriptada.get(i+1))){
                mensagemDigrafada.append('X');
            } else if(i+1 == rodaAlfabetoEncriptada.size() &&
                    mensagemDigrafada.length() % 2 != 0){
                mensagemDigrafada.append('X');
            }
            i++;
        }

        return mensagemDigrafada.toString();
    }

    protected char getLetraCriptografada(char letra1, char letra2, boolean encrypt){
        Integer y1 = null;
        Integer x1 = null;
        Integer y2 = null;
        Integer x2 = null;

        boolean encontrou = false;

        // Busca posições na matriz
        for(int y = 0; y < matrizPlayfair.length; y++){
            if(encontrou) break;
            for(int x = 0; x < matrizPlayfair.length; x++){
                if(letra1 == matrizPlayfair[y][x]){
                    x1 = x;
                    y1 = y;
                }
                if(letra2 == matrizPlayfair[y][x]){
                    x2 = x;
                    y2 = y;
                }
                if(x2 != null && y1 != null) {
                    encontrou = true;
                    break;
                }
            }
        }

        // Verifica se o resultado foi encontrado na mesma linha ou coluna
        if(x1.equals(x2)){
            if(encrypt){
                y1++;
                if(y1 > matrizPlayfair.length-1) y1 = 0;
            } else {
                y1--;
                if(y1 < 0) y1 = matrizPlayfair.length-1;
            }
            return matrizPlayfair[y1][x1];
        }
        if(y1.equals(y2)){
            if(encrypt){
                x1++;
                if(x1 > matrizPlayfair.length-1) x1 = 0;
            } else {
                x1--;
                if(x1 < 0) x1 = matrizPlayfair.length-1;
            }
            return matrizPlayfair[y1][x1];
        }

        // Retorna intersecção das letras
        return matrizPlayfair[y1][x2];
    }


    @Override
    protected String applyCrypt(String message, boolean encrypt){
        String mensagemDigrafada;
        if(encrypt){
            mensagemDigrafada = getMensagemDigrafada(message);
        } else {
            mensagemDigrafada = message;
        }

        StringBuilder mensagemCriptografada = new StringBuilder();

        // Gera mensagem criptografada a partir dos digrafos da mensagem
        for(int i = 0; i < mensagemDigrafada.length(); i+=2){
            mensagemCriptografada.append(getLetraCriptografada(mensagemDigrafada.toCharArray()[i], mensagemDigrafada.toCharArray()[i+1], encrypt));
            mensagemCriptografada.append(getLetraCriptografada(mensagemDigrafada.toCharArray()[i+1], mensagemDigrafada.toCharArray()[i], encrypt));
        }

        return mensagemCriptografada.toString();
    }


    public static void main(String[] args) {
        Crypt crypt = new PlayfairCrypt("JACINTO");
        String mensagem = "FELIPEGOSTADOSONICPORQUEELEEAZUL";
        String mensagemCriptografada = crypt.encrypt(mensagem);
        System.out.println(mensagemCriptografada);
        System.out.println(crypt.decrypt(mensagemCriptografada));
    }

}
