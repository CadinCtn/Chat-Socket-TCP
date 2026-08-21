package server;

import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.util.concurrent.CopyOnWriteArrayList;

public class Server {

    private static final int PORT = 12345;

    private static final CopyOnWriteArrayList<ClientHandler> clients =
            new CopyOnWriteArrayList<>();

    public static void main(String[] args) {

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {

            System.out.println("Server is running and waiting for connections...");

            // Thread para mensagens enviadas pelo administrador
            new Thread(() -> {

                Scanner scanner = new Scanner(System.in);

                while (true) {

                    String serverMessage = scanner.nextLine();

                    broadcast(
                            "SYSTEM|[Server]: " + serverMessage,
                            null
                    );
                }

            }).start();

            // Aceita conexões
            while (true) {

                Socket clientSocket = serverSocket.accept();

                System.out.println(
                        "New client connected: " + clientSocket
                );

                ClientHandler clientHandler =
                        new ClientHandler(clientSocket);

                clients.add(clientHandler);

                new Thread(clientHandler).start();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void broadcast(
            String message,
            ClientHandler sender
    ) {

        for (ClientHandler client : clients) {

            if (client != sender) {
                client.sendMessage(message);
            }
        }
    }

    private static class ClientHandler implements Runnable {

        private final Socket clientSocket;

        private PrintWriter out;
        private BufferedReader in;

        private String username;

        public ClientHandler(Socket socket) {

            this.clientSocket = socket;

            try {

                out = new PrintWriter(
                        clientSocket.getOutputStream(),
                        true
                );

                in = new BufferedReader(
                        new InputStreamReader(
                                clientSocket.getInputStream()
                        )
                );

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() {

            try {

                // Solicita o nome de usuário
                sendMessage(
                        "SYSTEM|Insira seu nome de usuário:"
                );

                username = in.readLine();

                if (username == null || username.isBlank()) {
                    username = "Usuário";
                }

                System.out.println(
                        "Usuário " + username + " conectado."
                );

                sendMessage(
                        "SYSTEM|Bem-vindo ao chat, " + username + "!"
                );

                sendMessage(
                        "SYSTEM|Digite sua mensagem"
                );

                String inputLine;

                while ((inputLine = in.readLine()) != null) {

                    System.out.println(
                            "\n[" + username + "]: " + inputLine
                    );

                    /*
                     * inputLine já está criptografada.
                     *
                     * O servidor não precisa conhecer a cifra.
                     * Apenas adicionamos o identificador CHAT
                     * e o nome do usuário.
                     */
                    broadcast(
                            "CHAT|" + username + "|" + inputLine,
                            this
                    );
                }

            } catch (IOException e) {

                System.out.println(
                        "Conexão encerrada para o usuário "
                                + username
                );

            } finally {

                clients.remove(this);

                System.out.println(
                        "Usuário " + username + " desconectado."
                );

                try {

                    if (in != null) {
                        in.close();
                    }

                    if (out != null) {
                        out.close();
                    }

                    clientSocket.close();

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        public void sendMessage(String message) {
            out.println(message);
        }
    }
}
