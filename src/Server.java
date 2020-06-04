
// NIS 2020
// Server Class
// -- Performs the server services - allows clients to coonect and sends & recives
//    messages making use of other classes utilities
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

import java.io.IOException;
import java.io.PrintStream;
import java.io.FileInputStream;
import java.io.DataInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import java.util.Scanner;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.awt.BorderLayout;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class Server {

    private static String clientName = "";
    private static String serverName = "Server";
    private static String serverPubKey = "serverPub";
    private static String serverPvtKey = "serverPvt";
    private static String clientPubKey = "";
    private static String sharedKey = "";

    private static PrintStream defaultStream;
    private static PrintStream clientWriter;
    
    private static ServerClient serverClient;
   
    public static void main(String[] args) throws Exception {
        System.out.println("The chat server is running...");
        serverClient = new ServerClient(defaultStream);
        ExecutorService pool = Executors.newFixedThreadPool(500);
        try (ServerSocket listener = new ServerSocket(59002)) {
            while (true) {
                Handler handle = new Handler(listener.accept());
                pool.execute(handle);
            }
        }
    }

    private static class Handler implements Runnable {
        private String name;
        private Socket socket;
        private Scanner in;



        public Handler(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                in = new Scanner(socket.getInputStream());
                PrintStream prt = new PrintStream(socket.getOutputStream(), true);
                // Keep requesting a name until we get a unique one.
                while (true) {
                    prt.println("SUBMITNAME");
                    String [] namePubKey = in.nextLine().split("#");
                    name = namePubKey [0];
                    String cpubKey = namePubKey [1];
                    if (name == null) {
                        return;
                    }
                    synchronized (clientName) {
                        if (!name.equals("") && clientName.equals("")) {
                            clientName = name;
                            clientPubKey = cpubKey;
                            serverClient.output = prt;
                            clientWriter = prt;
                            break;
                        }
                    }
                }
                // --- Authentication --- //
                // authenticate
                clientWriter.println("NAMEACCEPTED " + serverName + "#" + serverPubKey);
                String clientAccept =  in.nextLine();
                if (clientAccept.equals("declined")) {
                    return;
                }
                // get shared key
                sharedKey = "shared";
                // send shared key to client
                serverClient.sharedKey = sharedKey;

                // --- Show authentication complete --- //
                serverClient.msgField.append(clientName + " has joined the chat." + "\n");
                serverClient.txtEnter.setEditable(true);

                // --- Read messages from client --- //
                while (true) {
                    String input = in.nextLine();
                    if (input.toLowerCase().startsWith("/quit")) {
                        return;
                    }
                    serverClient.msgField.append(clientName + " encrypted: " + input + "\n");
                    // --- Decrypt & Decompress input --- //
                    // Decrypt
                    // Decompress

                    serverClient.msgField.append(clientName + " decrypted: " + input + "\n");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            finally {
                if (clientWriter != null) {
                    clientWriter = null;
                }
                if (clientName != null || clientName != "") {
                    System.out.println(clientName + " is leaving");
                    clientName = "";
                    clientPubKey = "";
                }
                try {
                    socket.close();
                } catch (IOException e) {
                }
            }
        }

    }
}