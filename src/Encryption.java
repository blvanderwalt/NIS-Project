
/**
 * Encryption Class
 * Performs the compression and encryption services
 * Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt
 */

import org.bouncycastle.jcajce.provider.symmetric.AES;
import java.security.*;
import java.util.ArrayList;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.zip.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class Encryption {

    /**
     * Encrypts the message hash with the private key using the Cipher library
     * @param msghash to extract signature from
     * @param privateKey private key for encryption
     * @return signature in a byte array
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
     * Encrypts the message hash with the public key using the Cipher library
     * @param msghash to extract signature from
     * @param publicKey public key for encryption
     * @return signature in a byte array
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
    /**
     * Encrypts the secret key with the RSA algorithm
     * Encrypts the message with the AES algorithm
     * @param secretKey secret key used for RSA encryption
     * @param init_vect initialization vector used in AES encryption
     * @param publicKey public key used for AES encryption
     * @param message plaintext message to be encrypted
     * @return the encrypted secret key, initialization vector and message in a packaged byte array
     */
    public static byte[] encrypt(SecretKey secretKey, byte[] init_vect, PublicKey publicKey, byte[] message)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException{

        IvParameterSpec ivspec = new IvParameterSpec(init_vect);

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();

        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes_sharedKey = cipherRSA.doFinal(secretKey.getEncoded());

        byteOut.write(bytes_sharedKey);
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

        return encryptedPackage;
    }

    /**
     * Decrypts the encrypted package using RSA and retires the secret key
     * Decrypts the ciphertext message using AES to retrieve the plaintext
     * @param privateKey private key used for AES encryption
     * @param encryptedPackage byte package of the encrypted shared key, initialization vector and AES encrypted payload
     * @return the plaintext message in a byte array
     */
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
    // --- Compression and Decompression --- //

    /**
     * Compresses String message with ZIP
     * @param message String message to compressed
     * @return compress message as a byte array
     */
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

    /**
     * Decompresses the byte array using Zip
     * @param compressage byte array to be decompressed
     * @return decompressed String message
     */
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
