
// NIS 2020
// Encryption Class
// -- Performs the compression and encryption services
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

//for encryption/decryption
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

import org.bouncycastle.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//for (de)compression
import java.util.zip.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class Encryption {
    // --- Encryptionion and Decryption --- //
    /*
    RSA encryption has a very low limit for data that can be encrypted. therefore to encrypt larger sets of data
    we use symmetric encryption, AES, for encryption - THEN we use the RSA for encrypting the AES key itself
    */
    public static String encrypt (String message, String base64PublicKey) {
        PublicKey publicKey = null;
        byte[] encrypted = null;
        try {
            System.out.printf("Before anything: %s\n", base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);

            System.out.printf("Before Encryption:       %s\n", message);

            // ECB - Electronic Code book
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Could use AES here as well
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // call doUpdate() for intermediate blocks of data in the case of segmentation of message
            // then finally call doFinal() to ensure padding is added correctly

    */
    /**
     * Process: RSA encryption has a very low limit for data that can be encrypted. therefore to encrypt larger sets of
     * data we use symmetric encryption, AES, for encryption - THEN we encrypt the RSA for encrypting the AES key itself
     *
     * Takes a whole bunch of variables used to encryption AND the secret message
     * created a file for the encryptedAES key and plaintext.txt for the secret message
     *
     * @return the encrypted sharedKey byte array.
     */
    public static byte[] fullEncryption(SecretKey sKey, byte[] init_vect, IvParameterSpec ivspec, PrivateKey privateKey,
                                        PublicKey publicKey, String message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] bytes_sharedKey = cipher.doFinal(sKey.getEncoded());

        FileOutputStream out = new FileOutputStream("encryptedAESkey.enc");

        out.write(bytes_sharedKey); //write a shared key to file
        byte[] sharedkey = new byte[256];
        //System.out.println(Arrays.toString(bytes_sharedKey));

        byte[] init_vec = init_vect;
        //System.out.println(Arrays.toString(init_vect));
        out.write(init_vect); // write init_vector to file

        // Encrypt File content using AES key
        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ci.init(Cipher.ENCRYPT_MODE, sKey, ivspec);

        //Write Message to plaintext.txt
        try{
            File file = new File("plaintext.txt");
            file.createNewFile();
            FileWriter fw = new FileWriter(file);
            fw.write(message);
            fw.close();
        } catch (IOException e) {
            System.out.println("File Write Error");
            e.printStackTrace();
        }

        try (FileInputStream in = new FileInputStream("plaintext.txt")) {
            processFile(ci, in, out); // write encrypted message to file
        }
        out.close();

        return bytes_sharedKey;
    }

    public static String[] fullDecryption(PublicKey publicKey, byte[] encryptedsharedKey, byte[] init_vect) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        FileInputStream in = new FileInputStream("encryptedAESkey.enc");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] b = new byte[256];
        in.read(b); // load encrypted file: read encrypted AES key

        byte[] keyb = cipher.doFinal(b); //retrieves secret AES key
        SecretKeySpec secret_key = new SecretKeySpec(keyb, "AES");

        byte[] init_vector = new byte[128/8];
        //init_vector = init_vect.clone(); --  If you want to get rid of files **
        in.read(init_vector); // load encrypted file: read init_vector
        IvParameterSpec ivspec = new IvParameterSpec(init_vector);

        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ci.init(Cipher.DECRYPT_MODE, secret_key, ivspec);
        try (FileOutputStream out = new FileOutputStream("final.txt")){
            processFile(ci, in, out); //decrypt message from file
        }

        String line = "";
        ArrayList<String> lines = new ArrayList<String>();
        try{
            BufferedReader br = new BufferedReader(new FileReader("final.txt"));
            while ( (line = br.readLine()) != null){
                lines.add(line);
            }
            br.close();
        } catch (IOException e) {
            System.out.println("File Reading Error");
            e.printStackTrace();
        }
        return lines.toArray(new String[lines.size()]);
    }

    public static void processFile(Cipher cipher,InputStream in,OutputStream out) throws IOException,
            BadPaddingException, IllegalBlockSizeException {
        byte[] input_buffer = new byte[1024];
        int input_len = 0;
        // in.read reads input_buffer.length # of bytes; returned as int
        if ((input_len = in.read(input_buffer)) != -1) { // if =-1, then end of stream is found
            do {
                byte[] out_buffer = cipher.update(input_buffer, 0, input_len); //Continues a multiple-part encryption
                if (out_buffer != null) {
                    out.write(out_buffer);
                }
            } while ((input_len = in.read(input_buffer)) != -1);
        }
        byte[] out_buffer = cipher.doFinal();
        if ( out_buffer != null ) out.write(out_buffer);
    }

    // --- Compression and Decompression --- //

    // --- Compression --- //
    // Compresses String message into a byte array with ZIP
    public static byte [] compress (String message) {
        try {
            ByteArrayOutputStream byteArrOut = new ByteArrayOutputStream(message.length());
            GZIPOutputStream gzip = new GZIPOutputStream(byteArrOut);
            gzip.write(message.getBytes(StandardCharsets.UTF_8));
            gzip.close();
            byte[] compressed = byteArrOut.toByteArray();
            byteArrOut.close();
            return compressed;
        }
        catch (IOException e) {
            throw new RuntimeException ("Failed to zip message", e);
        }
    }

    // --- Decompression --- //
    // Decompresses the byte array into a string message
    public static String decompress (byte [] compressage) {
        try {
            ByteArrayInputStream byteArrIn = new ByteArrayInputStream(compressage);
            GZIPInputStream gzip = new GZIPInputStream(byteArrIn);
            InputStreamReader inStreamRead = new InputStreamReader(gzip, StandardCharsets.UTF_8);
            BufferedReader buffReader = new BufferedReader(inStreamRead);

            StringBuilder output = new StringBuilder();
            String line;
            int i = 0;
            while((line = buffReader.readLine()) != null){
                if (i > 0){
                    output.append("\n");
                }
                output.append(line);
                i++;
            }
            return output.toString();
        }
        catch (IOException e) {
            throw new RuntimeException ("Failed to unzip message", e);
        }
    }
}
