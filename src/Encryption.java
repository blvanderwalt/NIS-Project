
// NIS 2020
// Encryption Class
// -- Performs the compression and encryption services
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

//for encryption/decryption
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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

            // message.getBytes() = byte[]
            // doFinal finishes off all steps of encryption process
            encrypted =  cipher.doFinal(message.getBytes());

        }catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException e){
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        System.out.printf("The encrypted String is: %s\n", Base64.getEncoder().encodeToString(encrypted));

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt (String message, String base64PrivateKey)  {
        PrivateKey privateKey = null;
        byte[] decrypted = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;

        System.out.printf("Before decryption:       %s\n", message);

        try{
            keyFactory = keyFactory.getInstance("RSA");
        }catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        try{
            assert keyFactory != null;
            privateKey = keyFactory.generatePrivate(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // doFinal finishes off all steps of encryption process
            decrypted = cipher.doFinal(message.getBytes());

        } catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        System.out.printf("The decrypted String is: %s\n", new String(decrypted));
        return new String(decrypted);
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
