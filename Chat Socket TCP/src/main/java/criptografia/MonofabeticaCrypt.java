package criptografia;


public class MonofabeticaCrypt extends AbstractCrypt{


    public MonofabeticaCrypt(String chave) {
        super();
        for(char letra : chave.toCharArray()){
            rodaEncriptada.add(letra);
        }
    }


    public static void main(String[] args) {
        Crypt crypt = new MonofabeticaCrypt("CBADEFGHIJKLMNOPQRSTUVWXYZ");

        String message = "testando criptogracria monofabetica".toUpperCase();
        System.out.println(crypt.encrypt(message));
        System.out.println(crypt.decrypt(crypt.encrypt(message)));
    }
}
