
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
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
    String serverUKey;
    String serverRKey;
    String clientUKey;

    Scanner input;
    ObjectOutputStream output;
    JFrame UI = new JFrame("Encrypto - Server");
    JTextField txtEnter = new JTextField(50);
    JTextArea msgField = new JTextArea(16, 50);

    // --- Takes Printstream of client to send messages directly --- //
    public ServerClient(ObjectOutputStream out) {
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
                Message message = new Message(msg,serverUKey,clientUKey);
                Authentication.sign(serverRKey,message);
                byte[] msgBytes = message.toByteArray();
                //TODO: encrypt [-]
                try {
                    output.writeObject(message);
                    txtEnter.setText("");
                } catch (Exception ex){
                    System.out.println("Error Sending Message Object");
                }
            }

        });
    }



}
