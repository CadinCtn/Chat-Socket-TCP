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
                        System.out.println(crypt.decrypt(serverResponse));
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();

            // Read messages from the console and send to the server
            String userInput;
            while (true) {
                userInput = scanner.nextLine();
                out.println(crypt.encrypt(Utils.cleanString(userInput)));
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
