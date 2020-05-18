import java.io.PrintStream;

//associates a client (uniquely identified by their user name) to an output stream
public class ClientWriter
{
    public PrintStream writer;
    String name;


    public ClientWriter(PrintStream writer, String name)
    {
        this.writer = writer;
        this.name=name;
    }




}
