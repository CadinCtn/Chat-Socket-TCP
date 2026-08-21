package client;

import criptografia.Crypt;
import utils.CryptSelect;

import java.io.*;
import java.net.*;
import java.util.Scanner;

public class Client {

    private static final String SERVER_ADDRESS = "10.164.20.105";
    private static final int SERVER_PORT = 12345;

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        /*
         * Seleciona a criptografia antes de iniciar o chat.
         */
        Crypt crypt = CryptSelect.SelectCryptography(scanner);

        try (
                Socket socket = new Socket(
                        SERVER_ADDRESS,
                        SERVER_PORT
                );

                PrintWriter out = new PrintWriter(
                        socket.getOutputStream(),
                        true
                );

                BufferedReader in = new BufferedReader(
                        new InputStreamReader(
                                socket.getInputStream()
                        )
                )
        ) {

            System.out.println(
                    "Connected to the chat server!"
            );

            /*
             * ============================
             * HANDSHAKE
             * ============================
             */

            // Recebe solicitação de username
            String serverMessage = in.readLine();

            if (serverMessage != null) {
                String[] parts = serverMessage.split("\\|", 2);

                if (parts.length == 2 &&
                        parts[0].equals("SYSTEM")) {

                    System.out.println(parts[1]);
                }
            }

            // Solicita username ao usuário
            System.out.print("Nome: ");

            String username = scanner.nextLine();

            // Envia username sem criptografia
            out.println(username);

            // Recebe mensagem de boas-vindas
            serverMessage = in.readLine();

            if (serverMessage != null) {

                String[] parts =
                        serverMessage.split("\\|", 2);

                if (parts.length == 2 &&
                        parts[0].equals("SYSTEM")) {

                    System.out.println(parts[1]);
                }
            }

            // Recebe "Digite sua mensagem"
            serverMessage = in.readLine();

            if (serverMessage != null) {

                String[] parts =
                        serverMessage.split("\\|", 2);

                if (parts.length == 2 &&
                        parts[0].equals("SYSTEM")) {

                    System.out.println(parts[1]);
                }
            }

            /*
             * ============================
             * RECEBIMENTO DE MENSAGENS
             * ============================
             */

            new Thread(() -> {

                try {

                    String message;

                    while ((message = in.readLine()) != null) {

                        String[] parts =
                                message.split("\\|", 3);

                        /*
                         * Mensagem do sistema:
                         *
                         * SYSTEM|Mensagem
                         */
                        if (parts.length >= 2 &&
                                parts[0].equals("SYSTEM")) {

                            System.out.println(parts[1]);
                        }

                        /*
                         * Mensagem de chat:
                         *
                         * CHAT|username|mensagem criptografada
                         */
                        else if (parts.length == 3 &&
                                parts[0].equals("CHAT")) {

                            String sender = parts[1];

                            String encryptedMessage =
                                    parts[2];

                            /*
                             * Somente a mensagem é
                             * descriptografada.
                             *
                             * "CHAT" e o username ficam
                             * fora da criptografia.
                             */
                            String decryptedMessage =
                                    crypt.decrypt(
                                            encryptedMessage
                                    );

                            System.out.println(
                                    "[" + sender + "]: "
                                            + decryptedMessage
                            );
                        }

                        else {
                            System.out.println(message);
                        }
                    }

                } catch (IOException e) {

                    System.out.println(
                            "Conexão com o servidor encerrada."
                    );
                }

            }).start();

            /*
             * ============================
             * ENVIO DE MENSAGENS
             * ============================
             */

            while (true) {

                String userInput = scanner.nextLine();

                /*
                 * Se quiser aplicar cleanString
                 * antes da criptografia:
                 *
                 * userInput = Utils.cleanString(userInput);
                 */

                String encryptedMessage =
                        crypt.encrypt(userInput);

                /*
                 * Envia SOMENTE a mensagem criptografada.
                 *
                 * O servidor adicionará:
                 *
                 * CHAT|username|
                 */
                out.println(encryptedMessage);
            }

        } catch (IOException e) {

            System.out.println(
                    "Não foi possível conectar ao servidor."
            );

            e.printStackTrace();
        }
    }
}