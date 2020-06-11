
// NIS 2020
// Encryption Class
// -- Performs the compression and encryption services
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

//for encryption/decryption
import org.bouncycastle.jcajce.provider.symmetric.AES;

import java.security.*;
import java.util.ArrayList;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//for (de)compression
import java.util.Arrays;
import java.util.zip.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class Encryption {
    // --- Encryptionion and Decryption --- //

    /**
     * Take in the message hash and private key
     * @return signature in a byte[]
    */
    public static byte[] extractSig(byte[] msghash, PrivateKey privateKey) {
        byte[] signed_hash = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            signed_hash = cipher.doFinal(msghash);
        }catch(NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e){
            e.printStackTrace();
        }

        return signed_hash;
    }

    /**
     * Take in the message hash and public key
     * @return signature in a byte[]
     */
    public static byte[] extractSig(byte[] msghash, PublicKey publicKey) {
        byte[] signed_hash = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            signed_hash = cipher.doFinal(msghash);
        }catch(NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e){
            e.printStackTrace();
        }

        return signed_hash;
    }

    public static byte[] encrypt(SecretKey secretKey, byte[] init_vect, PublicKey publicKey, byte[] message)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException{

        IvParameterSpec ivspec = new IvParameterSpec(init_vect);

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();

        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);
//        System.out.printf("Size of unencrypted shared key: %d\n", secretKey.getEncoded().length);
        byte[] bytes_sharedKey = cipherRSA.doFinal(secretKey.getEncoded());
//        System.out.printf("Size of encrypted shared key: %d\n", bytes_sharedKey.length);

        byteOut.write(bytes_sharedKey);
//        System.out.printf("Size of init_vector: %d\n", init_vect.length);
        byteOut.write(init_vect);

        // Encrypt File content using AES key
        Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherAES.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);

        byte[] input_buffer = new byte[1024];
        int input_len = 0;
        ByteArrayInputStream in = new ByteArrayInputStream(message);

        // in.read reads input_buffer.length # of bytes; returned as int
        while ( (input_len = in.read(input_buffer) ) != -1 ){
            byte[] out_buffer = cipherAES.update(input_buffer, 0, input_len); //Continues a multiple-part encryption
            if (out_buffer != null) {
                byteOut.write(out_buffer);
            }
        }
        byte[] AES_encryptedPayload = cipherAES.doFinal();
        if (AES_encryptedPayload!=null) {
            byteOut.write(AES_encryptedPayload);
        }

        byte[] encryptedPackage = new byte[byteOut.size()];
        encryptedPackage = byteOut.toByteArray();

//        System.out.printf("Size of unencrypted msg: %d\n", message.length);
//        System.out.printf("Size of encrypted msg: %d\n", encryptedPackage.length);

        return encryptedPackage;
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] encryptedPackage) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {

        ByteArrayInputStream bIn = new ByteArrayInputStream(encryptedPackage);

        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherRSA.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] ENshared_key = new byte[256];
        bIn.read(ENshared_key);

        byte[] shared_key = cipherRSA.doFinal(ENshared_key); //retrieves secret AES key
        SecretKey originalKey = new SecretKeySpec(shared_key, 0, shared_key.length, "AES");

        byte[] iv = new byte[128/8];
        bIn.read(iv);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherAES.init(Cipher.DECRYPT_MODE, originalKey, ivspec);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        byte[] input_buffer = new byte[1024];
        int input_len = 0;

        // in.read reads input_buffer.length # of bytes; returned as int
        while ((input_len = bIn.read(input_buffer)) != -1){ // if =-1, then end of stream is found
            byte[] out_buffer = cipherAES.update(input_buffer, 0, input_len); //Continues a multiple-part encryption
            if (out_buffer != null) {
                bOut.write(out_buffer);
            }
        }
        byte[] AES_encryptedPayload = cipherAES.doFinal();
        if (AES_encryptedPayload!=null) {
            bOut.write(AES_encryptedPayload);
        }

        byte[] plainText = new byte[bOut.size()];
        plainText = bOut.toByteArray();

        return plainText;
    }

    /**
     * Process: RSA encryption has a very low limit for data that can be encrypted. therefore to encrypt larger sets of
     * data we use symmetric encryption, AES, for encryption - THEN we encrypt the RSA for encrypting the AES key itself
     *
     * Takes a whole bunch of variables used to encryption AND the secret message
     * created a file for the encryptedAES key and plaintext.txt for the secret message
     *
     * @return the encrypted sharedKey byte array.
     */

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
