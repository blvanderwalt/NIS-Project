
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
    private String pubKey;
    private String pvtKey;
    String serverName;
    String serverPubKey;
    X509CertificateHolder serverCert;

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
        serverCert = certBuild.build(
            new Signer(subjectPubKeyInfo.getAlgorithm(), serverPubKey.getEncoded())
        );

        // --- Send message and print it on screen --- //
        txtEnter.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String msg = txtEnter.getText();
                msgField.append(clientName + ": " + msg + "\n");

                // --- Compress & Encrypt --- //
                Message message = new Message(msg,pubKey,serverPubKey);
                Authentication.sign(pvtKey,message);
                byte[] msgBytes = message.toByteArray();
                //TODO: encrypt msgBytes [-]

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
                    // TODO: authentication [x]
                    authenticate = Authentication.authenticateSender(serverCert);

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
                    //TODO: decryption [-]
                    byte[] dcMsg; //decrypted but still compressed message
                    //TODO: decompress [x]
                    String decmpMsg = Encryption.decompress(dcMsg);
                    Message msg = new Message(decmpMsg);

                    // --- Authenticate Message --- //
                    //TODO: authentication [-]
                    Authentication.authenticateMessage(msg);

                    String decryptedMessage = msg.payload.plaintext;
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
