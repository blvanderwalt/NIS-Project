
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import java.awt.BorderLayout;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

 // --- Server Client deals with input on the server side --- //
public class ServerClient {
    SecretKey sharedKey;
    PublicKey serverUKey;
    PrivateKey serverRKey;
    PublicKey clientUKey;
    IvParameterSpec ivspec;


    Scanner input;
    ObjectOutputStream output;
    JFrame UI = new JFrame("Encrypto - Server");
    JTextField txtEnter = new JTextField(50);
    JTextArea msgField = new JTextArea(16, 50);

    // --- Takes Printstream of client to send messages directly --- //
    public ServerClient(ObjectOutputStream out) throws NoSuchAlgorithmException {
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
                msgField.append("server: " + msg + "\n");

                // --- Compress & Encrypt --- //
                Message message = new Message(msg,serverUKey,clientUKey);
                Authentication.sign(serverRKey,message);
                byte[] msgBytes = message.toByteArray();
                byte[] encryptedMsgBytes;

                try {
                    encryptedMsgBytes = Encryption.encrypt(sharedKey, ivspec.getIV(), clientUKey,msgBytes);
                    output.writeInt(encryptedMsgBytes.length);
                    output.write(encryptedMsgBytes); // Send encryptedMessage
                    txtEnter.setText("");
                } catch (Exception ex){
                    System.out.println("Error Sending Message Object");
                }
            }

        });
    }



}
