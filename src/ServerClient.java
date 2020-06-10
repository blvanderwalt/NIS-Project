
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.awt.BorderLayout;
import javax.crypto.SecretKey;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

 // --- Server Client deals with input on the server side --- //
public class ServerClient {
    SecretKey sharedKey;
    PublicKey serverUKey;
    PrivateKey serverRKey;
    PublicKey clientUKey;
    byte [] ivspec;

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
                    encryptedMsgBytes = Encryption.encrypt(sharedKey, ivspec, clientUKey,msgBytes);
                    // --- Send to Client --- //
                    output.writeObject(encryptedMsgBytes);
                    txtEnter.setText("");
                } catch (Exception ex){
                    System.out.println("Error Sending Message Object");
                }
            }

        });
    }



}
