
// NIS 2020
// Client Class
// -- Performs the client services - connects to server and sends & recives
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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.BorderLayout;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import java.util.concurrent.TimeUnit;

public class Client {
    private String pubKey;
    private String pvtKey;
    String serverName;
    String serverPubKey;

    String clientName = "Client";
    String sharedKey;
    String serverAddress;
    Scanner input;
    PrintStream output;
    JFrame UI = new JFrame("Encrypto - Client");
    JTextField txtEnter = new JTextField(50);
    JTextArea msgField = new JTextArea(16, 50);

    // --- Takes server IP address and same port number to connect to each other --- //
    public Client(String serverAddress) {
        this.serverAddress = serverAddress;
        txtEnter.setEditable(false);
        msgField.setEditable(false);
        UI.getContentPane().add(txtEnter, BorderLayout.SOUTH);
        UI.getContentPane().add(new JScrollPane(msgField), BorderLayout.CENTER);
        UI.pack();

        // --- Send message and print it on screen --- //
        txtEnter.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String msg = txtEnter.getText();
                msgField.append(clientName + ": " + msg + "\n");
                // --- Compress & Encrypt --- //
                // Compress
                // Encrypt

                output.println(msg);
                txtEnter.setText("");
            }

        });
    }

    private void run() throws IOException {
        try {
            Socket socket = new Socket(serverAddress, 59002);
            input = new Scanner(socket.getInputStream());
            output = new PrintStream(socket.getOutputStream(), true);
            while (input.hasNextLine()) {
                String line = input.nextLine();
                if (line.startsWith("SUBMITNAME")) {
                    output.println(clientName + "#" + pubKey);
                } else if (line.startsWith("NAMEACCEPTED")) {
                    this.UI.setTitle("Encrypto - " + clientName);
                    msgField.append("Joined chat with Server\n");
                    txtEnter.setEditable(true);
                    String [] namePubKey = line.split("#");
                    serverName = namePubKey [0];
                    serverPubKey = namePubKey [1];
                    boolean authenticate = true;
                    // --- Authenticate Server --- //
                    // authentication

                    if (authenticate) {
                        output.println("accepted");
                    } else {
                        output.println("declined");
                        msgField.append("Server identity unknown, closing services...\n");
                        try {
                           TimeUnit.SECONDS.sleep(1);
                           msgField.append("3...");
                           TimeUnit.SECONDS.sleep(1);
                           msgField.append("2...");
                           TimeUnit.SECONDS.sleep(1);
                           msgField.append("1...");
                           TimeUnit.SECONDS.sleep(1);
                           return;
                        }
                        catch (Exception e) {
                           return;
                        }
                        
                        
                    }
                    
                } else if (line.startsWith("MESSAGE")) {
                    String encryptedMessage = line.substring(8);
                    msgField.append("Server encrypted: " + encryptedMessage + "\n");
                    // --- Decompression & Decryption --- //
                    //Decrypt Message
                    //Decompress Message

                    String decryptedMessage = encryptedMessage;
                    msgField.append("Server decrypted: " + decryptedMessage + "\n");
                }
            }
        } finally {
            UI.setVisible(false);
            UI.dispose();
        }
    }


        public static void main(String[] args) throws Exception {
            Client client;
            if (args.length == 1) {
                client = new Client(args[0]);
            }
            else {
                client = new Client("127.0.0.1");
            }
            client.UI.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            client.UI.setVisible(true);
            client.run();
        }



    }