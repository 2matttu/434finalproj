/**
 * <p>Title: CPSC 433/533 Programming Assignment</p>
 *
 * <p>Description: Fishnet TCP manager</p>
 *
 * <p>Copyright: Copyright (c) 2006</p>
 *
 * <p>Company: Yale University</p>
 *
 * @author Hao Wang
 * @version 1.0
 */
import java.util.*;

public class TCPManager {
    private Map<String, TCPSock> listenSockets = null; //server sockets (key is port they are listening on)
    private Map<String, TCPSock> connectionSockets = null; //conn. sockets (key is [localport]:[remaddr]:[remport] of remote socket)
    private boolean[] portOccupied; //lists whether each port is occupied by a listen socket
    private Node node;
    private int addr;
    private Manager manager;

    private static final byte dummy[] = new byte[0];

    public TCPManager(Node node, int addr, Manager manager) {
        this.node = node;
        this.addr = addr;
        this.manager = manager;
    }

    /**
     * Start this TCP manager
     */
    public void start() {
        this.listenSockets = new HashMap<String, TCPSock>();
        this.connectionSockets = new HashMap<String, TCPSock>();
        this.portOccupied = new boolean[256];
    }

    /*
     * Begin socket API
     */

    /**
     * Create a socket
     *
     * @return TCPSock the newly created socket, which is not yet bound to
     *                 a local port
     */
    public TCPSock socket() {
        TCPSock newSock = new TCPSock();
        newSock.config(this.addr, this.node, this);
        return newSock;
    }

    public TCPSock connSock(int localPort, int remAddr, int remPort, int seqNum, boolean isSecure)
    {
        TCPSock newSock = new TCPSock();
        newSock.config(this.addr, this.node, this);
        newSock.configConnSock(localPort, remAddr, remPort, seqNum, isSecure);
        addConnSocket(newSock, localPort, remAddr, remPort);
        return newSock;
    }

    public void receiveTransportPkt(Packet packet, int from)
    {
        Transport packetPayload = Transport.unpack(packet.getPayload());
        int packetType = packetPayload.getType();
        if (packetType == Transport.SYN) //SYN Packet
        {
            int destPort = packetPayload.getDestPort();
            if (this.listenSockets.containsKey(String.valueOf(destPort)))
            {
                TCPSock sock = this.listenSockets.get(String.valueOf(destPort));
                sock.handleSynPacket(packet, from);
            }
            return;
        }
        else if (packetType == Transport.ACK || packetType == Transport.DATA || packetType == Transport.FIN)
        {
            String key = String.valueOf(packetPayload.getDestPort()) + ":" + String.valueOf(from) + ":" + String.valueOf(packetPayload.getSrcPort());
            if (this.connectionSockets.containsKey(key))
            {
                TCPSock sock = this.connectionSockets.get(key);
                sock.handlePacket(packet);
            }
        }
    }

    public void addConnSocket(TCPSock sock, int localPort, int destAddr, int destPort)
    {
        this.connectionSockets.put(String.valueOf(localPort) + ":" + String.valueOf(destAddr) + ":" + String.valueOf(destPort), sock);
    }

    public TCPSock getConnSocket(int localPort, int destAddr, int destPort)
    {
        if (this.connectionSockets.containsKey(String.valueOf(localPort) + ":" + String.valueOf(destAddr) + ":" + String.valueOf(destPort)))
        {
            return this.connectionSockets.get(String.valueOf(localPort) + ":" + String.valueOf(destAddr) + ":" + String.valueOf(destPort));
        }
        return null;
    }

    public void addListenSocket(TCPSock sock, int port)
    {
        this.listenSockets.put(String.valueOf(port), sock);
    }

    public boolean portOccupied(int port)
    {
        if (port < 0 || port > 255)
        {
            return true;
        }
        return this.portOccupied[port];
    }

    public void setPort(int port, boolean bool)
    {
        if (port >= 0 && port < 256)
        {
            this.portOccupied[port] = bool;
        }
    }
    /*
     * End Socket API
     */
}
