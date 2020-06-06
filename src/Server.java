
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
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import java.util.Scanner;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.awt.BorderLayout;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
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

public class Server {

    private static String clientName = "";
    private static String serverName = "Server";
    private static PublicKey serverPubKey;
    private static PrivateKey serverPvtKey;
    private static PublicKey clientPubKey;
    private static byte[] sharedKey;
    private X509CertificateHolder clientCert;

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
                    byte[] clientUK = cpubKey.getBytes();

                    // Not sure if this works??


                    if (name == null) {
                        return;
                    }
                    synchronized (clientName) {
                        if (!name.equals("") && clientName.equals("")) {
                            clientName = name;
                            clientPubKey = (PublicKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(clientUK));
                            serverClient.output = prt;
                            clientWriter = prt;
                            //getClientCertificate();
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

                // Create sharedKey
                KeyGenerator k_gen = KeyGenerator.getInstance("AES");
                k_gen.init(128); // size of AES Key - 128
                SecretKey shared_key = k_gen.generateKey();
                sharedKey = shared_key.getEncoded();
                // send shared key to client
                serverClient.sharedKey = sharedKey;

                //Create initilization vector
                SecureRandom random = new SecureRandom(); // generates random vector
                byte[] init_vect = new byte[128/8]; // AES default block size = 128
                random.nextBytes(init_vect);
                IvParameterSpec ivspec = new IvParameterSpec(init_vect);
                serverClient.ivspec = ivspec;





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
                    //TODO: decrypt [-]
                    byte[] init_vector = null;
                    byte[] dcMsg = Encryption.fullDecryption(clientPubKey, sharedKey, init_vector, input.getBytes());

                    //TODO: decompress [x]
                    String decmpMsg = Encryption.decompress(dcMsg);
                    Message msg = new Message(decmpMsg);
                    input = msg.payload.plaintext;

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
                    clientPubKey = null;
                }
                try {
                    socket.close();
                } catch (IOException e) {
                }
            }
        }

    }

    /*
    public static void getClientCertificate(){
        //TODO: create certificate [x]
        SubjectPublicKeyInfo subjectPubKeyInfo = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X509CertificateStructure.id_RSAES_OAEP),
            clientPubKey.getEncoded()
        );
        X509v3CertificateBuilder certBuild = new X509v3CertificateBuilder(
            new X500Name("CN=issuer"), //issuer
            new BigInteger("3874699348569"), //serial no
            new GregorianCalendar(2020,4,1).getTime(), //issue date
            new GregorianCalendar(2020,8,31).getTime(), //expiry date
            Locale.getDefault(), //date locale
            new X500Name("CN="+clientName), //subject
            subjectPubKeyInfo //subject's public key info: algorithm and public key
        );
        clientCert = certBuild.build(
            new Signer(subjectPubKeyInfo.getAlgorithm(), clientPubKey.getEncoded())
        );
    }
    */
}
