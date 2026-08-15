package criptografia;


public class MonofabeticaCrypt extends AbstractCrypt{


    public MonofabeticaCrypt(String chave) {
        super();
        for(char letra : chave.toCharArray()){
            rodaEncriptada.add(letra);
        }
    }

    @Override
    public String criptografar(String message, boolean encrypt) {
        return "";
    }

    @Override
    public String encrypt(String message) {
        StringBuilder mensagemCriptografada = new StringBuilder();
        message.replace('Ç', 'C');

        for(String palavra : message.split(" ")){
            for(char letra : palavra.toCharArray()){
                mensagemCriptografada.append(getLetraCriptografada(letra, true));
            }
            mensagemCriptografada.append(" ");
        }

        return mensagemCriptografada.toString();
    }

    @Override
    public String decrypt(String message) {
        return "";
    }
}
