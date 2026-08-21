package client;

import java.io.*;
import java.net.*;
import java.util.Scanner;

import criptografia.Crypt;
import utils.*;

public class Client {
    private static final String SERVER_ADDRESS = "26.232.54.30";
    private static final int SERVER_PORT = 12345;

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        Crypt crypt = CryptSelect.SelectCryptography(scanner);

        try {
            Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            System.out.println("Connected to the chat server!");

            // Setting up input and output streams
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Start a thread to handle incoming messages
            new Thread(() -> {
                try {
                    String serverResponse;
                    while ((serverResponse = in.readLine()) != null) {
                        if (serverResponse.startsWith("SYS|")) {
                            // Mensagem de protocolo/sistema (prompts, avisos do admin, etc).
                            // NUNCA passa pelo decrypt(): é texto puro por definição.
                            System.out.println(serverResponse.substring(4));

                        } else if (serverResponse.startsWith("MSG|")) {
                            // Mensagem de chat no formato "MSG|remetente|textoCifrado".
                            // Só o campo textoCifrado (payload puro em Playfair) vai pro decrypt().
                            String payload = serverResponse.substring(4);
                            String[] parts = payload.split("\\|", 2);
                            String sender = parts[0];
                            String cipherText = parts.length > 1 ? parts[1] : "";

                            String decrypted = cipherText.isEmpty() ? "" : crypt.decrypt(cipherText);
                            System.out.println("[" + sender + "]: " + decrypted);

                        } else {
                            // Fallback de segurança: qualquer linha fora do protocolo
                            // é apenas exibida, nunca decodificada às cegas.
                            System.out.println(serverResponse);
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();

            // Read messages from the console and send to the server
            boolean firstMessage = true;
            String userInput;
            while (true) {
                userInput = scanner.nextLine();
                if (firstMessage) {
                    // Primeira linha digitada = nome de usuário.
                    // Trafega em texto puro (não cifrado), pois o servidor o usa
                    // como identificador de protocolo, não como payload de chat.
                    out.println(userInput);
                    firstMessage = false;
                } else {
                    out.println(crypt.encrypt(Utils.cleanString(userInput)));
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}