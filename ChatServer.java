
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

public class ChatServer {
    // All client names, so we can check for duplicates upon registration.
    private static Set<String> names = new HashSet<>();
    // The set of all the print writers for all the clients, used for broadcast.
    //private static Set<PrintStream> writers = new HashSet<>();
    private static Set<ClientWriter> writers = new HashSet<>();


    public static void main(String[] args) throws Exception {
        System.out.println("The chat server is running...");
        ExecutorService pool = Executors.newFixedThreadPool(500);
        try (ServerSocket listener = new ServerSocket(59002)) {
            while (true) {
                pool.execute(new Handler(listener.accept()));
            }
        }
    }

    private static class Handler implements Runnable {
        private String name;
        private Socket socket;
        private Scanner in;
        private PrintStream out;

        public Handler(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                in = new Scanner(socket.getInputStream());
                out = new PrintStream(socket.getOutputStream(), true);
                // Keep requesting a name until we get a unique one.
                while (true) {
                    out.println("SUBMITNAME");
                    name = in.nextLine();
                    if (name == null) {
                        return;
                    }
                    synchronized (names) {
                        if (!name.equals("") && !names.contains(name)) {
                            names.add(name);
                            break;
                        }
                    }
                }

                out.println("NAMEACCEPTED " + name);
                for (ClientWriter client : writers) {
                    client.writer.println("MESSAGE " + name + " has joined");
                }

                writers.add(new ClientWriter(out,name));
                // Accept messages from this client and broadcast them.
                while (true) {
                    String input = in.nextLine();
                    if (input.toLowerCase().startsWith("/quit")) {
                        return;
                    }
                    String header = "MESSAGE ";
                    System.out.println(input); //remove
                    if (input.toLowerCase().startsWith("/accepttransfer")){
                        header = "TRANSFER INIT ";
                        String fileSender = (input.split(":")[0]).substring(15).trim();
                        String fileName = input.split(":")[1].trim();
                        out.println(header + fileSender + ":" + fileName);
                        if(!sendFile(out, fileName)){
                            out.println("MESSAGE Error sending message");
                        }
                        continue;
                    }
                    if (input.toLowerCase().startsWith("/file")){
                        header = "FILE ";
                        String fileName = input.substring(5,input.indexOf(':')).trim();
                        String filePath = input.substring(input.indexOf(':')+1).trim();
                        int size = Integer.parseInt(in.nextLine().split(":")[1].trim());
                        downloadToServer(socket, fileName, size);
                    }
                    Boolean sendToAll=false;
                    if (input.toLowerCase().startsWith("<send to all>"))
                    {
                        sendToAll=true;
                    }
                    if(sendToAll)
                    {
                        for (ClientWriter client : writers)
                        {
                            if (out == client.writer && header.equals("FILE "))
                            {
                                continue;
                            }
                            client.writer.println(header + name + ": " + input.substring(13));
                        }
                    }
                    else if (input.toLowerCase().startsWith("<send to user>"))
                    {
                        for (ClientWriter client : writers)
                        {
                            if (out == client.writer && header.equals("FILE "))
                            {
                                continue;
                            }
                            String recipient = input.substring(input.indexOf(':')+1, input.indexOf(','));
                            if (client.name.equals(recipient))
                            {

                                client.writer.println(header + name + "<to you>: " + input.substring(17+recipient.length()));
                            }
                            if (client.name.equals(name))
                            {
                                client.writer.println(header +name + "<to "+recipient+">: " + input.substring(17+recipient.length()));
                            }
                        }

                    }
                }
            } catch (Exception e) {
                /*System.out.println(*/e.printStackTrace();//);
            } finally {
                if (out != null) {
                    writers.remove(out);
                }
                if (name != null) {
                    System.out.println(name + " is leaving");
                    names.remove(name);
                    for (ClientWriter client : writers) {
                        client.writer.println("MESSAGE " + name + " has left");
                    }
                }
                try { socket.close(); } catch (IOException e) {}
            }
        }

        //filesharing - first upload to server

        void downloadToServer(Socket socket, String filePath, int size){
            System.out.println("Download initiated");
            try{
                byte[] item = new byte[size];
                for(int i = 0; i < size; ++i){socket.getInputStream().read(item,i,1);}
                FileOutputStream requestedFile = new FileOutputStream(new File("server_lib_"+filePath));
                BufferedOutputStream bostream = new BufferedOutputStream(requestedFile);
                bostream.write(item);
                bostream.close();
                requestedFile.close();
            }
            catch (IOException e){
                e.printStackTrace();
                System.out.println("Download interrupted");
            }
            System.out.println("Download complete");
        }

        //if client accepts file, commence download from server

        boolean sendFile(PrintStream ostream, String filePath){
            try{
                filePath = "server_lib_"+filePath;
                FileInputStream requestedfile = new FileInputStream(filePath);
                byte[] buffer = new byte[1];
                ostream.println("Content-Length: "+new File(filePath).length()); // for the client to receive file
                while((requestedfile.read(buffer)!=-1)){
                    System.out.print(buffer[0] + " ");	//remove
                    ostream.write(buffer,0,buffer.length);
                    ostream.flush();
                }
                requestedfile.close();
            }
            catch (IOException e){
                e.printStackTrace();
                return false;
            }

            return true;
        }

    }

}

