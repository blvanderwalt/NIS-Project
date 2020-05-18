
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.PrintStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.net.Socket;
import java.util.Scanner;
import java.awt.BorderLayout;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

 // chat client server connects to the chat server
public class ChatClient {
    String serverAddress;
    Scanner input;
    PrintStream ouput;
    JFrame UI = new JFrame("Chatter");
    JTextField txtEnter = new JTextField(50);
    JTextArea msgField = new JTextArea(16, 50);

    // takes server IP address and same port number to connect to each other
    public ChatClient(String serverAddress) {
        this.serverAddress = serverAddress;
        txtEnter.setEditable(false);
        msgField.setEditable(false);
        UI.getContentPane().add(txtEnter, BorderLayout.SOUTH);
        UI.getContentPane().add(new JScrollPane(msgField), BorderLayout.CENTER);
        UI.pack();

        // send and ready
        txtEnter.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String msg = txtEnter.getText();
                ouput.println(msg);
                txtEnter.setText("");

                if(msg.startsWith("/file"))
                {sendServerMsg(msg);}
            }
        });
    }

    private String getUsername() {
        return JOptionPane.showInputDialog(
                UI,
                "Choose a screen name:",
                "Screen name selection",
                JOptionPane.PLAIN_MESSAGE
        );
    }

    private int getDLAccess(String filePath, String sender) {
        return JOptionPane.showConfirmDialog(UI,
                "Do you want to download "+filePath+" file from "+sender,
                "Accept or Decline File Shared",
                JOptionPane.YES_NO_OPTION
        );
    }

    private void run() throws IOException {
        try {
            Socket socket = new Socket(serverAddress, 59002);
            input = new Scanner(socket.getInputStream());
            ouput = new PrintStream(socket.getOutputStream(), true);
            while (input.hasNextLine()) {
                String line = input.nextLine();
                if (line.startsWith("SUBMITNAME")) {
                    ouput.println(getUsername());
                } else if (line.startsWith("NAMEACCEPTED")) {
                    this.UI.setTitle("Chatter - " + line.substring(13));
                    txtEnter.setEditable(true);
                } else if (line.startsWith("FILE")) {
                    String fromUser = line.substring(5, line.indexOf(':'));
                    String fileName = line.split(":")[1].trim().substring(5).trim();
                    String filePath = line.split(":")[2].trim();
                    int download = getDLAccess(fileName, fromUser);
                    if(download == JOptionPane.YES_OPTION)
                    {ouput.println("/acceptTransfer "+fromUser+": "+fileName);}
                } else if (line.startsWith("TRANSFER INIT")) {
                    String fromUser = line.substring(14, line.indexOf(':')).trim();
                    String filePath = line.substring(line.indexOf(':')+1).trim();
                    String confirmationMessage = filePath + " downloaded.\n";
                    String errorMessage = filePath + "could not be downloaded.\n";

                    int size = Integer.parseInt(input.nextLine().split(":")[1].trim());
                    System.out.println(size);
                    filePath = fromUser+"_"+filePath;
                    if(dLServer(socket, size, filePath))
                    {msgField.append(confirmationMessage);}
                    else{msgField.append(errorMessage);}
                } else if (line.startsWith("MESSAGE")) {
                    msgField.append(line.substring(8) + "\n");
                }
            }
        } finally {
            UI.setVisible(false);
            UI.dispose();
        }
    }

    // server needs to receive the files
    protected void sendServerMsg(String msg){
        String filePath = msg.split(":")[1].trim();
        try{
            FileInputStream requestedfile = new FileInputStream(filePath);
            byte[] buffer = new byte[1];
            ouput.println("Content-Length: "+new File(filePath).length());
            while((requestedfile.read(buffer)!=-1)){
                ouput.write(buffer);
                ouput.flush();
            }
            requestedfile.close();
        }
        catch (IOException e){
            e.printStackTrace();
        }
    }

    protected boolean dLServer(Socket socket, int noOfBytes, String filePath){
        try{
            byte[] item = new byte[noOfBytes];
            for(int i = 0; i < noOfBytes; ++i){socket.getInputStream().read(item,i,1);}
            FileOutputStream reqFile = new FileOutputStream(new File(filePath));
            BufferedOutputStream streamBO = new BufferedOutputStream(reqFile);
            streamBO.write(item);
            streamBO.close();
            reqFile.close();
        }
        catch (IOException e){
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public static void main(String[] args) throws Exception {
        ChatClient client = new ChatClient(args[0]);
        client.UI.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        client.UI.setVisible(true);
        client.run();
    }

    public static class ClientWriter
    {
    }
}


