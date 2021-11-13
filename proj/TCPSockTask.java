public class TCPSockTask
{
    private TCPSock.State state;
    private TCPSock.Type type;
    private int seqN;

    public TCPSockTask(TCPSock.State state, TCPSock.Type type, int seqN)
    {
        this.state = state;
        this.type = type;
        this.seqN = seqN;
    }

    public TCPSock.State getState()
    {
        return this.state;
    }

    public TCPSock.Type getType()
    {
        return this.type;
    }

    public int getSeqN()
    {
        return this.seqN;
    }
}