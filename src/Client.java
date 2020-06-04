
// NIS 2020
// Client Class
// -- Performs the client services - connects to server and sends & recives
//    messages making use of other classes utilities
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

import java.io.IOException;
import java.io.PrintStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.FileInputStream;
import java.io.DataInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import java.util.Scanner;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.BorderLayout;
import javax.crypto.SecretKey;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import java.util.concurrent.TimeUnit;
//for certificate
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import java.math.BigInteger;
import java.util.GregorianCalendar;
import java.util.Locale;


public class Client {
    private PublicKey clientPubKey;
    private PrivateKey clientPvtKey;
    PublicKey serverPubKey;
    X509CertificateHolder serverCert;
    X509CertificateHolder clientCert;
    private SecretKey sharedKey;
    String serverAddress;
    ObjectInputStream input;
    ObjectOutputStream output;
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

        // --- generate public/private key pair --- //
        //TODO: assign pubKey and pvtKey [-]
        //TODO: create certificate [-] ~ needs pubKey as a PublicKey object
        SubjectPublicKeyInfo subjectPubKeyInfo = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X509CertificateStructure.id_RSAES_OAEP),
            serverPubKey.getEncoded() 
        );
        X509v3CertificateBuilder certBuild = new X509v3CertificateBuilder(
            new X500Name("CN=issuer"), //issuer
            new BigInteger("3874699348568"), //serial no
            new GregorianCalendar(2020,4,1).getTime(), //issue date
            new GregorianCalendar(2020,8,31).getTime(), //expiry date
            Locale.getDefault(), //date locale
            new X500Name("CN=server"), //subject
            subjectPubKeyInfo //subject's public key info: algorithm and public key
        );
        clientCert = certBuild.build(
            new Signer(subjectPubKeyInfo.getAlgorithm(), clientPubKey.getEncoded())
        );

        // --- Send message and print it on screen --- //
        txtEnter.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String msg = txtEnter.getText();
                msgField.append("Client: " + msg + "\n");

                // --- Compress & Encrypt --- //
                Message message = new Message(msg,clientPubKey,serverPubKey);
                Authentication.sign(clientPvtKey,message);
                byte[] msgBytes = message.toByteArray();
                //TODO: encrypt msgBytes [-]
                //encrypt message
                try {
                    output.writeObject(msg);
                } catch (Exception ex){
                    System.out.println("Error Sending Message Object");
                }
                txtEnter.setText("");

            }

        });
    }

    private void run() throws IOException, ClassNotFoundException {
        try {
            Socket socket = new Socket(serverAddress, 59002);
            input = new ObjectInputStream(socket.getInputStream());
            output = new ObjectOutputStream(socket.getOutputStream());
            while (true) {

                Object obj = input.readObject();
                if (obj instanceof String) {
                    String line = (String)obj;
                    if (line.startsWith("SUBMITNAME")) {
                        //Send public Key
                        output.writeObject(clientPubKey);
                    }

                    line = (String)input.readObject();
                    if (line.startsWith("SENDCERT")) {
                        output.writeObject(clientCert);
                    }
                    if (line.startsWith("NAMEACCEPTED")) {
                        this.UI.setTitle("Encrypto - Client");
                        serverPubKey = (PublicKey)input.readObject();
                        X509CertificateHolder servCert = (X509CertificateHolder)input.readObject();
                        boolean authenticate = true;
                        // --- Authenticate Server --- //
                        authenticate = Authentication.authenticateSender(servCert);
                        if (authenticate) {
                            output.writeObject("accepted");
                            sharedKey = (SecretKey) input.readObject();
                            msgField.append("Joined chat with Server\n");
                            txtEnter.setEditable(true);
                        }
                        else {
                            output.writeObject("declined");
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
                            } catch (Exception e) {
                                return;
                            }
                        }


                    }
                }
                else if (obj instanceof Message) {
                    Message msg = (Message)obj;
                    String encryptedMessage = msg.payload.plaintext;
                    msgField.append("Server encrypted: " + encryptedMessage + "\n");
                    // --- Decompression & Decryption --- //
                    //TODO: decryption [-]
                    byte[] dcMsg; //decrypted but still compressed message
                    String decompMsg = Encryption.decompress(dcMsg);
                    Message newMsg = new Message(decompMsg);

                    // --- Authenticate Message --- //
                    if (Authentication.authenticateMessage(newMsg)){
                        msgField.append("Server decrypted: " + decompMsg + "\n");
                    }
                    else {
                        msgField.append("Message Authentication failed");
                    }


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
