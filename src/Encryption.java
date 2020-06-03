
// NIS 2020
// Encryption Class
// -- Performs the compression and encryption services
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

//for encryption/decryption
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
     * @return String signature
    */
    public static byte[] encrypt (String msghash, PrivateKey privateKey) {
        byte[] signed_hash = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            signed_hash = cipher.doFinal(msghash.getBytes());
        }catch(NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e){
            e.printStackTrace();
        }

        return signed_hash;
    }


    public static String decrypt(String sig, PublicKey publicKey) {



        return null;
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
    public static byte[][] fullEncryption(SecretKey sKey, byte[] init_vect, IvParameterSpec ivspec, PrivateKey privateKey,
                                          PublicKey publicKey, String message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] bytes_sharedKey = cipher.doFinal(sKey.getEncoded());

        //System.out.printf("Shared key in encryAES.enc: %s\n", Arrays.toString(bytes_sharedKey));

        byte[] sharedkey = new byte[256];
        //System.out.println(Arrays.toString(bytes_sharedKey));

        byte[] init_vec = init_vect;
        //System.out.printf("Init Vector: %s\n", Arrays.toString(init_vect));

        // Encrypt File content using AES key
        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ci.init(Cipher.ENCRYPT_MODE, sKey, ivspec);


        ArrayList<byte[]> out = new ArrayList<byte[]>();

        byte[] input_buffer = new byte[1024];
        int input_len = 0;
        ByteArrayInputStream in = new ByteArrayInputStream(message.getBytes());

        // in.read reads input_buffer.length # of bytes; returned as int
        if ((input_len = in.read(input_buffer)) != -1) { // if =-1, then end of stream is found
            do {
                byte[] out_buffer = cipher.update(input_buffer, 0, input_len); //Continues a multiple-part encryption
                if (out_buffer != null) {
                    out.add(out_buffer);
                }
            } while ((input_len = in.read(input_buffer)) != -1);
        }

        byte[] out_buffer = cipher.doFinal();
        //System.out.printf("Out buffer: %s\n", Arrays.toString(out_buffer));


        byte[][] output = new byte[3][];
        output[0] = bytes_sharedKey;
        output[1] = init_vec;
        output[2] = out_buffer;

        return output;
    }

    public static byte[] fullDecryption(PublicKey publicKey, byte[] encryptedsharedKey, byte[] init_vect,
                                          byte[]  msg) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        //FileInputStream in = new FileInputStream("encryptedAESkey.enc");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] b = new byte[256];
        b = encryptedsharedKey;

        byte[] keyb = cipher.doFinal(b); //retrieves secret AES key
        SecretKeySpec secret_key = new SecretKeySpec(keyb, "AES");

        byte[] init_vector = new byte[128/8];
        init_vector = init_vect;
        IvParameterSpec ivspec = new IvParameterSpec(init_vector);

        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ci.init(Cipher.DECRYPT_MODE, secret_key, ivspec);

        ArrayList<byte[]> out = new ArrayList<byte[]>();

        byte[] input_buffer = new byte[1024];
        input_buffer = msg;
        int input_len = 0;
        ByteArrayInputStream in = new ByteArrayInputStream(input_buffer);

        // in.read reads input_buffer.length # of bytes; returned as int
        if ((input_len = in.read(input_buffer)) != -1) { // if =-1, then end of stream is found
            do {
                byte[] out_buffer = cipher.update(input_buffer, 0, input_len); //Continues a multiple-part encryption
                if (out_buffer != null) {
                    out.add(out_buffer);
                }
            } while ((input_len = in.read(input_buffer)) != -1);
        }
        byte[] out_buffer = cipher.doFinal();

        return out_buffer;
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
        System.out.printf("Out buffer: %s\n", Arrays.toString(out_buffer));
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
