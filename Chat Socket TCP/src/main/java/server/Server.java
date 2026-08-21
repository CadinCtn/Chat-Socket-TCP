package server;
import java.io.*;
import java.net.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.Scanner;

public class Server {
    private static final int PORT = 12345;
    private static CopyOnWriteArrayList<ClientHandler> clients = new CopyOnWriteArrayList<>();

    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server is running and waiting for connections...");

            // Thread to handle server admin input
            new Thread(() -> {
                Scanner scanner = new Scanner(System.in);
                while (true) {
                    String serverMessage = scanner.nextLine();
                    // Mensagens de admin são marcadas como SYS| para nunca serem
                    // enviadas ao decodificador Playfair no cliente
                    broadcast("SYS|[Server]: " + serverMessage, null);
                }
            }).start();

            // Accept incoming connections
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("New client connected: " + clientSocket);

                // Create a new client handler for the connected client
                ClientHandler clientHandler = new ClientHandler(clientSocket);
                clients.add(clientHandler);
                new Thread(clientHandler).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Broadcast a message to all clients
    public static void broadcast(String message, ClientHandler sender) {
        for (ClientHandler client : clients) {
            if (client != sender) {
                client.sendMessage(message);
            }
        }
    }

    // Internal class to handle client connections
    private static class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private PrintWriter out;
        private BufferedReader in;
        private String username;

        public ClientHandler(Socket socket) {
            this.clientSocket = socket;

            try {
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() {
            try {
                // Prompt de sistema: SYS| garante que o cliente nunca tente
                // descriptografar esta linha
                out.println("SYS|Insira seu nome de usuário:");

                // O nome de usuário trafega em texto puro (não passou por crypt.encrypt
                // no cliente), então é lido normalmente, sem qualquer decodificação
                username = in.readLine();
                if (username == null || username.isBlank()) {
                    username = "Anonimo";
                }
                // Remove '|' do username para não quebrar o parsing "MSG|usuario|texto"
                username = username.replace("|", "").trim();

                System.out.println("Usuário " + username + " conectado.");
                out.println("SYS|Bem-vindo ao chat, " + username + "!");
                out.println("SYS|Digite sua mensagem");

                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    // inputLine já chega cifrado (payload puro em Playfair) do cliente
                    System.out.println("\n[" + username + "]: " + inputLine);
                    // Formato: MSG|remetente|textoCifrado
                    // O prefixo e o remetente ficam FORA do texto cifrado,
                    // evitando que caracteres como [ ] : espaço entrem no decrypt()
                    broadcast("MSG|" + username + "|" + inputLine, this);
                }

                // Remove the client handler from the list
                clients.remove(this);
                System.out.println("Usuário " + username + " desconectado.");
                broadcast("SYS|[Server]: " + username + " saiu do chat.", this);
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    in.close();
                    out.close();
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