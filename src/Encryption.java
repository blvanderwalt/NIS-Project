
// NIS 2020
// Encryption Class
// -- Performs the compression and encryption services
//Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

import java.util.zip.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class Encryption {

    // --- Encryptionion and Decryption --- //
    public static String encrypt (String message, String Key) {
        return "";
    }
    // I don't think it's necessary to take in both public and private key for
    // encyption and decryption. Since each only uses one. I think you should
    // just change the inputs to message and key <--since decryption/Encryption
    // can happen with either -- Chia

    public static String decrypt (String message, String Key) {
        return "";
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
