
// NIS 2020
// Client Class
// -- Performs the client services - connects to server and sends & recives
//    messages making use of other classes utilities
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.BorderLayout;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFrame;
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


public class Client {
    private PublicKey clientPubKey;
    private PrivateKey clientPvtKey;
    PublicKey serverPubKey;
    X509CertificateHolder clientCert;
    private SecretKey sharedKey;
    private byte[] init_vector;

    String serverAddress;
    ObjectInputStream input;
    ObjectOutputStream output;
    JFrame UI = new JFrame("Encrypto - Client");
    JTextField txtEnter = new JTextField(50);
    JTextArea msgField = new JTextArea(16, 50);

    // --- Takes server IP address and same port number to connect to each other --- //
    public Client(String serverAddress) throws NoSuchAlgorithmException {
        this.serverAddress = serverAddress;
        txtEnter.setEditable(false);
        msgField.setEditable(false);
        UI.getContentPane().add(txtEnter, BorderLayout.SOUTH);
        UI.getContentPane().add(new JScrollPane(msgField), BorderLayout.CENTER);
        UI.pack();

        // --- Generate public/private key pair --- //
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); //size of RSA key - 2048
        KeyPair pair = keyGen.generateKeyPair();

        clientPvtKey = pair.getPrivate(); // returns PKCS#8 format
        clientPubKey = pair.getPublic(); // returns X.509 format

        byte[] publicByteArray = clientPubKey.getEncoded();

        SubjectPublicKeyInfo subjectPubKeyInfo = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X509CertificateStructure.id_RSAES_OAEP),
            clientPubKey.getEncoded() //self-signed
        );

        // --- Generate Certificate --- //
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
            new OurSigner(subjectPubKeyInfo.getAlgorithm(), clientPubKey.getEncoded())
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
                byte[] encryptedMsgBytes;
                try {
                    encryptedMsgBytes = Encryption.encrypt(sharedKey, init_vector, serverPubKey,msgBytes);
                    // --- Send to Server ---//
                    output.writeObject(encryptedMsgBytes);
                } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IOException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException ex) {
                    ex.printStackTrace();
                    System.out.println("Error Sending Message Object");
                }
                txtEnter.setText("");
            }

        });
    }

    private void run() throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, ClassNotFoundException, InvalidKeySpecException {
        try {
            // --- Set up Socket and Object Streams --- //
            Socket socket = new Socket(serverAddress, 59002);
            output = new ObjectOutputStream(socket.getOutputStream());
            input = new ObjectInputStream(socket.getInputStream());

            Object obj = input.readObject();
            if (obj instanceof String) {
                String line = (String) obj;
                if (line.startsWith("SUBMITNAME")) {
                    // --- Send public Key --- //
                    output.writeObject(clientPubKey);
                }
                // --- Send Certificate --- //
                line = (String) input.readObject();
                if (line.startsWith("SENDCERT")) {
                    output.writeObject(clientCert);
                }
                line = (String) input.readObject();
                if (line.startsWith("NAMEACCEPTED")) {
                    this.UI.setTitle("Encrypto - Client");

                    // --- Authenticate Server --- //
                    serverPubKey = (PublicKey) input.readObject();
                    X509CertificateHolder servCert = (X509CertificateHolder) input.readObject();
                    boolean authenticate = true;
                    authenticate = Authentication.authenticateSender(servCert);
                    // --- Accept --- //
                    if (authenticate) {
                        output.writeObject("accepted");

                        // --- get shared key and init vector --- //
                        byte [] sKey = (byte[]) input.readObject();
                        sKey = Encryption.decrypt(clientPvtKey, sKey);
                        sharedKey = new SecretKeySpec(sKey,0,sKey.length,"AES");
                        byte [] iVec = (byte[]) input.readObject();
                        init_vector = Encryption.decrypt(clientPvtKey, iVec);

                        msgField.append("Joined chat with Server\n");
                        txtEnter.setEditable(true);
                    }
                    // --- Decline --- //
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
            // --- Loop receiving Messages from Server --- //
            while (true) {
                    // --- Get Message --- //
                    byte [] msg = (byte[]) input.readObject();
                    msgField.append("Server encrypted: " + msg + "\n");

                    // --- Decryption & Decompression --- //
                    byte[] dcMsg = Encryption.decrypt(clientPvtKey, msg);
                    String decompMsg = Encryption.decompress(dcMsg);
                    System.out.printf("Final Decompressed Message: %s", decompMsg);

                    // --- Authenticate Message --- //
                    Message newMsg = new Message(decompMsg);
                    if (Authentication.authenticateMessage(newMsg)){
                        msgField.append("Server decrypted: " + newMsg.payload.plaintext + "\n");
                    }
                    else {
                        msgField.append("Message Authentication failed");
                    }
            }
        // --- Close Client Window --- //
        } finally {
            UI.setVisible(false);
            UI.dispose();
        }
    }

        // --- Start Client --- //
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
