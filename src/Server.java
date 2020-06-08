
// NIS 2020
// Server Class
// -- Performs the server services - allows clients to coonect and sends & recives
//    messages making use of other classes utilities
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

import java.io.*;
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

    private static PublicKey serverPubKey;
    private static PrivateKey serverPvtKey;
    private static PublicKey clientPubKey;
    private static SecretKey sharedKey; // B
    public static byte[] init_vector;


    private X509CertificateHolder clientCert;
    private static X509CertificateHolder serverCert; //B

    private static ObjectOutputStream defaultStream;
    private static ObjectOutputStream clientWriter;

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
        private Socket socket;
        private ObjectInputStream in;



        public Handler(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                in = new ObjectInputStream(socket.getInputStream());
                ObjectOutputStream prt = new ObjectOutputStream(socket.getOutputStream());
                // Keep requesting a name until we get a unique one.
                while (true) {
                    prt.writeObject("SUBMITNAME");
                    PublicKey cPubKey = (PublicKey)in.readObject();
                    synchronized (clientPubKey) {
                        if (!cPubKey.equals(null) && clientPubKey.equals(null)) {
                            clientPubKey = cPubKey;
                            serverClient.output = prt;
                            clientWriter = prt;
                            serverClient.clientUKey = clientPubKey;
                            serverClient.serverRKey = serverPvtKey;
                            serverClient.serverUKey = serverPubKey;
                            break;
                        }
                    }
                }
                // --- Authentication --- //
                //Get certificate and verify
                clientWriter.writeObject("SENDCERT");
                X509CertificateHolder clientCert = (X509CertificateHolder) in.readObject();
                if (!Authentication.authenticateSender(clientCert)) {
                    serverClient.msgField.append("Client not verified - cancelling connection");
                    clientWriter.writeObject("DECLINED");
                    return;
                }
                //Send Public key to client and await their verification
                clientWriter.writeObject("NAMEACCEPTED");
                clientWriter.writeObject(serverPubKey);
                clientWriter.writeObject(serverCert);
                String clientAccept =  (String)in.readObject();
                if (clientAccept.equals("declined")) {
                    return;
                }

                // Create sharedKey
                KeyGenerator k_gen = KeyGenerator.getInstance("AES");
                k_gen.init(128); // size of AES Key - 128
                SecretKey shared_key = k_gen.generateKey();
                sharedKey = shared_key;
                // send shared key to client
                serverClient.sharedKey = sharedKey; // CHeck whats up here

                //Create initilization vector
                SecureRandom random = new SecureRandom(); // generates random vector
                byte[] init_vect = new byte[128/8]; // AES default block size = 128
                random.nextBytes(init_vect);
                IvParameterSpec ivspec = new IvParameterSpec(init_vect);
                serverClient.ivspec = ivspec;

                // --- Show authentication complete --- //
                serverClient.msgField.append("Client has joined the chat.\n");
                serverClient.txtEnter.setEditable(true);

                // --- Read messages from client --- //
                while (true) {
                    byte[] input = new byte[in.readInt()];
                    in.readFully(input);
                    serverClient.msgField.append("Client encrypted: " + input + "\n");
                    // --- Decrypt & Decompress input --- //
                    byte[] init_vector = null;
                    byte[] dcMsg = Encryption.decrypt(sharedKey, init_vector, serverPvtKey, serverPubKey,
                            new String(input));

                    String decmpMsg = Encryption.decompress(dcMsg);
                    Message msg = new Message(decmpMsg);
                    
                    if (msg.payload.plaintext.startsWith("/quit")) { return; }
                    if (Authentication.authenticateMessage(msg)){
                        serverClient.msgField.append("Client decrypted: " + msg.payload.plaintext + "\n");
                    }
                    else {
                        serverClient.msgField.append("Message Authentication failed");
                    }


                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            finally {
                if (clientWriter != null) {
                    clientWriter = null;
                }
                if (clientPubKey != null) {
                    System.out.println("Client is leaving");
                    clientPubKey = null;
                }
                try {
                    socket.close();
                } catch (IOException e) {
                }
            }
        }

    }
}
