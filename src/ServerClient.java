
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.PrintStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.net.Socket;
import java.util.Scanner;
import java.awt.BorderLayout;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

 // --- Server Client deals with input on the server side --- //
public class ServerClient {
    String serverName = "Server";
    String sharedKey;

    Scanner input;
    PrintStream output;
    JFrame UI = new JFrame("Encrypto - Server");
    JTextField txtEnter = new JTextField(50);
    JTextArea msgField = new JTextArea(16, 50);

    // --- Takes Printstream of client to send messages directly --- //
    public ServerClient(PrintStream out) {
        output = out;
        txtEnter.setEditable(false);
        msgField.setEditable(false);
        UI.getContentPane().add(txtEnter, BorderLayout.SOUTH);
        UI.getContentPane().add(new JScrollPane(msgField), BorderLayout.CENTER);
        UI.pack();
        UI.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        UI.setVisible(true);

        // --- Send message and print it on screen --- //
        txtEnter.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String msg = txtEnter.getText();
                msgField.append(serverName + ": " + msg + "\n");
                // --- Compress & Encrypt --- //
                //TODO: compress [-] ~ needs both public keys + server private key
                Message message = new Message(msg,pubKey,clientPubKey);
                Authentication.sign(pvtKey,message);
                byte[] msgBytes = message.toByteArray();
                //TODO: encrypt [-]

                output.println("MESSAGE " + msg + "\n");
                txtEnter.setText("");
            }

        });
    }



}
