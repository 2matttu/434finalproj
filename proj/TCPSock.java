/**
 * <p>Title: CPSC 433/533 Programming Assignment</p>
 *
 * <p>Description: Fishnet socket implementation</p>
 *
 * <p>Copyright: Copyright (c) 2006</p>
 *
 * <p>Company: Yale University</p>
 *
 * @author Hao Wang
 * @version 1.0
 */

import java.nio.ByteBuffer;
import java.util.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.concurrent.ThreadLocalRandom;

public class TCPSock {
    public static boolean DEBUG = false; //debug (recommend setting to false)
    public static boolean DEBUGCC = false; //debug congestion control
    // TCP socket states
    public static enum State {
        // protocol states
        INIT,
        CLOSED,
        LISTEN,
        SYN_SENT,
        SYN_ACK_SENT,
        ESTABLISHED,
        SHUTDOWN, // close requested, FIN not sent (due to unsent data in queue)
        FIN_SENT
    }
    public static enum Type {
        LISTEN,
        SENDER,
        RECEIVER
    }
    public static enum CC {
        RENO, //used by default
        CUBIC
    }
    private Type type;
    private State state;
    private CC cControl = CC.RENO;

    private int localAddr = 0;
    private int localPort = 0;
    private int remAddr = 0;
    private int remPort = 0;

    private ArrayList<byte[]> sendQueue; //buffer of data Socket receives in packet-sized byte chunks (max 107B per chunk)
    private ByteBuffer receiveBuff;

    private Node node;
    private TCPManager tcpMan;

    private int backlogSize;
    private LinkedList<TCPSock> backlog;

    private int seq = 0;
    private int base = 1; //sliding window
    private int baseOrig = 1;
    private int nextSeq = 1; //sliding window
    private int expSeq = 1; //sliding window - receiver
    private int windowSize = 600; //window size, size 600 = 600*107 = 64kB
    private int nRemoved = 0;

    private long rwnd = 0; //receive window in BYTES
    private long bytesSent = 0; //number of bytes sent
    private long bytesAck = 0; //number of bytes acked
    private long synTime; //time when SYN sent
    // private int synAckTime; //timestamp when SYN ACK received
    private long rtt; //round trip time
    private long timerMs; //timeout time in ms

    //Congestion control variables
    private static int mss = Transport.MAX_PAYLOAD_SIZE - 16; //maximum segment size
    private long cwnd; //send window
    private long ssthresh = 64000; //ssthresh
    private int dupAcks = 0;

    //CUBIC variables
    private boolean tcpFriend = true;
    private boolean fastConverge = true;
    private double beta;
    private double capC;
    private double wLastMax;
    private long epochStart;
    private double originPoint;
    private double wTCP;
    private double k;
    private int ackCnt;
    private int cwndCnt;

    //Secure Transport Stuff
    private byte[] senderDHKey;
    private byte[] receiverDHKey;
    private byte[] dhSecret;
    private byte[] dhSecret128;
    private byte[] dhSecret256;
    private static int dhPublicKeySize;
    private KeyAgreement senderKeyAgree;
    private int receivedCert;

    private boolean isSetup = false;
    private boolean isSecure = false;
    
    public TCPSock() {
        this.state = State.INIT;
        this.cControl = CC.RENO;
        this.sendQueue = new ArrayList<byte[]>();
        this.receiveBuff = ByteBuffer.allocate(0xFFFF);
        // this.receiveBuff = ByteBuffer.allocate(1000); //for flow control test (see README)
        this.cwnd = TCPSock.mss;
        this.timerMs = 1000; //default timeout time, will be changed once sender receives SYN ACK
    }

    public void config(int localAddr, Node node, TCPManager tcpMan) {
        this.localAddr = localAddr;
        this.node = node;
        this.tcpMan = tcpMan;
    }

    public void configConnSock(int localPort, int remAddr, int remPort, int startSeq, boolean isSecure)
    {
        this.localPort = localPort;
        this.remAddr = remAddr;
        this.remPort = remPort;
        this.seq = startSeq;
        this.state = State.SYN_ACK_SENT;
        this.type = Type.RECEIVER;
        this.isSecure = isSecure;
    }

    public void sendSynAck(int seq) //sends acknowledge of syn, establishing connection
    {
        // Transport tcpPacket = new Transport(this.localPort, this.remPort, Transport.ACK, recWindow(), ++this.seq, new byte[0]);
        byte[] payload = packReceiverPacket();
        Transport tcpPacket = new Transport(this.localPort, this.remPort, Transport.ACK, recWindow(), seq + 1, payload);
        this.node.sendSegment(this.localAddr, this.remAddr, Protocol.TRANSPORT_PKT, tcpPacket.pack());

        this.expSeq = seq + 1;
    }

    public void setLocalAddr(int addr)
    {
        this.localAddr = addr;
    }
    public void setRemAddr(int addr)
    {
        this.remAddr = addr;
    }
    public void setLocalPort(int port)
    {
        this.localPort = port;
    }
    public void setRemPort(int port)
    {
        this.remPort = port;
    }

    /*
     * The following are the socket APIs of TCP transport service.
     * All APIs are NON-BLOCKING.sock
     */

    /**
     * Bind a socket to a local port
     *
     * @param localPort int local port number to bind the socket to
     * @return int 0 on success, -1 otherwise
     */
    public int bind(int localPort) {
        if (this.tcpMan.portOccupied(localPort))
        {
            return -1;
        }
        this.localPort = localPort;
        this.tcpMan.setPort(localPort, true); //occupy port
        debug("binded socket to port " + localPort);
        return 0;
    }

    /**
     * Listen for connections on a socket
     * @param backlog int Maximum number of pending connections
     * @return int 0 on success, -1 otherwise
     */
    public int listen(int backlog) {
        this.state = State.LISTEN;
        this.type = Type.LISTEN;
        this.backlogSize = backlog;
        this.backlog = new LinkedList<TCPSock>();
        //register socket as listen socket
        this.tcpMan.addListenSocket(this, this.localPort);
        debug("socket listening on port " + this.localPort);
        return 0;
    }

    /**
     * Accept a connection on a socket
     *
     * @return TCPSock The first established connection on the request queue
     */
    public TCPSock accept() {
        if (this.backlog.size() > 0)
        {
            TCPSock connSock = this.backlog.getFirst();
            this.backlog.removeFirst();

            int remAddr = connSock.getRemAddr();
            int remPort = connSock.getRemPort();

            TCPSock currSock = this.tcpMan.getConnSocket(this.localPort, remAddr, remPort); //get current socket
            currSock.setState(State.ESTABLISHED);
            debug("accepted connections");
            return connSock;
        }
        return null;
    }

    public boolean isConnectionPending() {
        return (state == State.SYN_SENT);
    }

    public boolean isClosed() {
        //check status of socket
        return (state == State.CLOSED);
    }

    public boolean isConnected() {
        return (state == State.ESTABLISHED);
    }

    public boolean isClosurePending() {
        return (state == State.SHUTDOWN);
    }

    public void setup(boolean secure, byte[] publicKey, KeyAgreement senderKeyAgree) {
        this.senderDHKey = publicKey;
        this.senderKeyAgree = senderKeyAgree;
        this.isSecure = secure;
        this.isSetup = true;
    }

    public void setup(boolean secure) {
        this.isSecure = secure;
        this.isSetup = true;
    }

    public boolean isSetup() {
        return this.isSetup;
    }

    /**
     * Initiate connection to a remote socket
     *
     * @param destAddr int Destination node address
     * @param destPort int Destination port
     * @return int 0 on success, -1 otherwise
     */
    public int connect(int destAddr, int destPort) {
        this.remAddr = destAddr;
        this.remPort = destPort;
        this.state = State.SYN_SENT;

        this.tcpMan.addConnSocket(this, this.localPort, destAddr, destPort);

        //create SYN packet

        byte[] payload = packSenderPacket();
        // System.out.println("packet size: " + payload.length);
        //send SYN packet
        this.seq = ThreadLocalRandom.current().nextInt(0, 2147483647);
        this.base = this.seq + 1;
        this.baseOrig = this.base;
        this.nextSeq = this.seq + 1;
        Transport tcpPacket = new Transport(this.localPort, this.remPort, Transport.SYN, 0, this.seq, payload);
        
        debug("sending SYN...");
        this.node.sendSegment(this.localAddr, this.remAddr, Protocol.TRANSPORT_PKT, tcpPacket.pack());
        this.synTime = tcpTimestamp();
        this.node.logPacket("S");
        this.type = Type.SENDER;

        //CUBIC initialization if needed
        if (this.cControl == CC.CUBIC)
        {
            this.tcpFriend = true;
            this.fastConverge = true;
            this.beta = 0.2;
            this.capC = 0.4;
            cubicReset();
            this.cwndCnt = 0;
        }
        //timeout for sending SYN
        this.node.addTCPTimer(2000, this, new TCPSockTask(this.state, this.type, this.seq));
        return 0;
    }

    /**
     * Initiate closure of a connection (graceful shutdown)
     */
    public void close() {
        if (this.type == Type.LISTEN)
        {
            this.state = State.CLOSED;
            this.tcpMan.setPort(this.localPort, false);
            return;
        }
        if (this.sendQueue.size() == 0)
        {
            Transport tcpPacket = new Transport(this.localPort, this.remPort, Transport.FIN, 0, 0, new byte[0]);
            this.node.sendSegment(this.localAddr, this.remAddr, Protocol.TRANSPORT_PKT, tcpPacket.pack());
            this.node.logPacket("F");
            this.node.addTCPTimer(this.timerMs, this, new TCPSockTask(State.FIN_SENT, this.type, this.seq));
        }
        else
        {
            this.state = State.SHUTDOWN;
        }
    }

    /**
     * Release a connection immediately (abortive shutdown)
     */
    public void release() {
        if (this.type == Type.LISTEN)
        {
            this.state = State.CLOSED;
            this.tcpMan.setPort(this.localPort, false);
            return;
        }
        if (this.state != State.CLOSED)
        {
            Transport tcpPacket = new Transport(this.localPort, this.remPort, Transport.FIN, 0, 0, new byte[0]);
            this.node.sendSegment(this.localAddr, this.remAddr, Protocol.TRANSPORT_PKT, tcpPacket.pack());
            this.node.logPacket("F");
            this.node.addTCPTimer(this.timerMs, this, new TCPSockTask(State.FIN_SENT, this.type, this.seq));
        }
    }

    /**
     * Write to the socket up to len bytes from the buffer buf starting at
     * position pos.
     *
     * @param buf byte[] the buffer to write from
     * @param pos int starting position in buffer
     * @param len int number of bytes to write
     * @return int on success, the number of bytes written, which may be smaller
     *             than len; on failure, -1
     */
    public int write(byte[] buf, int pos, int len) {
        if (this.state == State.SHUTDOWN)
        {
            return -1;
        }
        else if (this.rwnd == 0)
        {
            return 0;
        }
        int nLeft = len;
        while (nLeft > 0 && this.sendQueue.size() < this.windowSize)
        {
            int stride = Math.min(nLeft, Transport.MAX_PAYLOAD_SIZE - 16);
            byte[] tmpArr = Arrays.copyOfRange(buf, pos, pos + stride);
            this.sendQueue.add(tmpArr);
            pos += stride;
            nLeft -= stride;
        }
        debug("wrote " + (len - nLeft) + " bytes to sendBuff");
        // debugCC("(M" + minWindow() + ")"); //for flow control test (see README)

        // if stuff in the queue AND can send more bytes (bounded by BOTH cwnd and rwnd)
        while (bytesTransit() < minWindow() && (this.nextSeq - this.base < this.sendQueue.size())) 
        {
            if (this.nextSeq - this.base >= this.sendQueue.size())
            {
                this.node.logError("ERROR: next: " + this.nextSeq + " base: " + this.base +  " size: " + this.sendQueue.size() + " rem: " + this.nRemoved);
            }
            byte[] tcpPayload = this.sendQueue.get(this.nextSeq - this.base);
            sendDataPacket(tcpPayload, this.nextSeq);
            this.node.logPacket(".");
            if (this.base == this.nextSeq && this.base == this.baseOrig)
            {
                debug("sw start timer");
                this.node.addTCPTimer(this.timerMs, this, new TCPSockTask(this.state, this.type, this.base)); //seqn irrelevant
            }
            this.nextSeq++;
            this.bytesSent += tcpPayload.length; //FLOW, CONGESTION
            debug("sent: " + this.bytesSent);
        }
        return len - nLeft;
    }

    /**
     * Read from the socket up to len bytes into the buffer buf starting at
     * position pos.
     *
     * @param buf byte[] the buffer
     * @param pos int starting position in buffer
     * @param len int number of bytes to read
     * @return int on success, the number of bytes read, which may be smaller
     *             than len; on failure, -1
     */
    public int read(byte[] buf, int pos, int len) {
        this.receiveBuff.flip(); //turn to read mode
        int nRead = 0;
        char c;
        while (len > 0 && this.receiveBuff.position() < this.receiveBuff.limit())
        {
            c = (char) this.receiveBuff.get();
            buf[pos++] = (byte) c;
            nRead++;
        }
        this.receiveBuff.compact(); //back to write mode, saving unread bytes
        return nRead;
    }

    //helper function for receiver to determine amount of free space in its receive buffer
    private int recWindow()
    {
        return this.receiveBuff.capacity() - this.receiveBuff.position();
    }

    //called after data packet is GOOD and used to check if ACK can be sent (0 yes, -1 no) based on recWindow()
    private int payloadToBuff(byte[] payload)
    {
        //buff does not accept payloads if too big for buff
        if (payload.length > recWindow()) //TODO
        {
            return -1;
        }
        this.receiveBuff.put(payload);
        return 0;
    }

    //handles all but SYN packets
    public void handlePacket(Packet packet)
    {
        Transport packetPayload = Transport.unpack(packet.getPayload());
        int packetSeq = packetPayload.getSeqNum();
        int packetType = packetPayload.getType();
        int packetWindow = packetPayload.getWindow();
        debug("TCPsock port " + this.localPort + " handling packet with type " + String.valueOf(packetType) + " and seq#" + String.valueOf(packetSeq));
        if (this.type == Type.RECEIVER && this.state == State.ESTABLISHED)
        {
            if (packetType == Transport.DATA && this.state == State.ESTABLISHED && packetSeq == this.expSeq)
            {
                byte[] tcpPayload = packetPayload.getPayload(); //extract
                byte[] decPayload = (isSecure) ? new byte[0] : tcpPayload;
                if (isSecure) {
                    try
                    {
                        decPayload = decrypt(tcpPayload, this.dhSecret256, this.dhSecret128, packetSeq);
                    }
                    catch (Exception e)
                    {
                        // printStackTrace method
                        // prints line numbers + call stack
                        // e.printStackTrace();
                    
                        // Prints what exception has been thrown
                        System.out.println(e);
                        System.out.println("Message authentication failed! Not sending ACK...");
                        return;
                    }
                }
                
                if (payloadToBuff(decPayload) == 0) //deliver data, if -1 receive buffer full
                {
                    this.node.logPacket(".");
                    this.sendAckPacket(this.expSeq); //make and send packet
                    debug("sent ack" + this.expSeq);
                    this.expSeq++; //expectedseqnum++
                    this.node.logPacket(":");
                }
                else
                {
                    debug("receive buff too full! sending exp ACK");
                    this.node.logPacket(".");
                    this.sendAckPacket(this.expSeq - 1); //re-ACK pkt with highest in-order seq #
                    this.node.logPacket("?");
                }
            }
            else if (packetType == Transport.DATA && this.state == State.ESTABLISHED && packetSeq != this.expSeq)
            {
                this.node.logPacket("!");
                this.sendAckPacket(this.expSeq - 1); //re-ACK pkt with highest in-order seq #
                this.node.logPacket("?");
            }
            else if (packetType == Transport.FIN && this.state == State.ESTABLISHED || packetType == Transport.FIN && this.state == State.SYN_ACK_SENT)
            {
                this.node.logPacket("F");
                debug("FIN received. Shutting down!");
                this.node.logOutput("FIN received. Shutting down!");
                Transport tcpPack = new Transport(this.localPort, this.remPort, Transport.FIN, 0, this.seq, new byte[0]);
                this.node.sendSegment(this.localAddr, this.remAddr, Protocol.TRANSPORT_PKT, tcpPack.pack());
                this.node.logPacket("F");
                this.node.addTCPTimer(this.timerMs, this, new TCPSockTask(State.FIN_SENT, this.type, this.seq));
            }
        }
        else //SENDER
        {
            //if ack# == seq
            // this.node.logOutput("payload length: " + packetPayload.getPayload().length);
            if (this.state == State.SYN_SENT && packetType == Transport.ACK && packetSeq == this.seq + 1) //first ack
            {
                this.node.logOutput("seq: " + this.seq);
                byte[] payload = packetPayload.getPayload();
                if (isSecure) {
                    if (payload.length == 0) {
                        System.out.println("Server does not support requested secured connection! Abort!");
                        Transport tcpPacket = new Transport(this.localPort, packetPayload.getSrcPort(), Transport.FIN, 0, 0, new byte[0]);
                        this.node.sendSegment(this.localAddr, packet.getSrc(), Protocol.TRANSPORT_PKT, tcpPacket.pack());
                        this.node.logPacket("F");
                        this.state = State.CLOSED;
                        return;
                    }
                    int receivedCert = unpackReceiverPacket(payload);
                    if (!node.validCertificate(receivedCert)) {
                        // System.out.println("CERTIFICATE: " + receivedCert);
                        System.out.println("Cert from server invalid!");
                        Transport tcpPacket = new Transport(this.localPort, packetPayload.getSrcPort(), Transport.FIN, 0, 0, new byte[0]);
                        this.node.sendSegment(this.localAddr, packet.getSrc(), Protocol.TRANSPORT_PKT, tcpPacket.pack());
                        this.node.logPacket("F");
                        this.state = State.CLOSED;
                        return;
                    }
                    else
                    {
                        System.out.println("Cert from server valid.");
                    }
                    try
                    {
                        senderDHSecretCreate();
                    }
                    catch (Exception e)
                    {
                        // printStackTrace method
                        // prints line numbers + call stack
                        e.printStackTrace();
                    
                        // Prints what exception has been thrown
                        System.out.println(e);
                    }
                }
               
                this.node.logPacket(":");
                debug("syn ack received!"); 
                this.rtt = tcpTimestamp() - this.synTime;
                this.timerMs = this.rtt * 2; //approximation for moving RTT
                this.node.logOutput("rtt: " + this.rtt);
                this.seq++;
                this.state = State.ESTABLISHED;

                this.rwnd = packetWindow; //FLOW
            }
            else if ((this.state == State.ESTABLISHED || this.state == State.SHUTDOWN) && packetType == Transport.ACK)
            {
                this.rwnd = packetWindow; //FLOW
                if (packetSeq >= this.base) //if new packets acked
                {
                    this.dupAcks = 0;
                    for (int i = 0; i < packetSeq - this.base + 1; i++)
                    {
                        int pktSize = this.sendQueue.get(0).length;

                        //CC handle ACK
                        switch (this.cControl)
                        {
                            case CUBIC:
                                if (this.cwnd < this.ssthresh)
                                {
                                    this.cwnd += pktSize;
                                }
                                else
                                {
                                    double count = cubicUpdate();
                                    if (this.cwndCnt > count)
                                    {
                                        this.cwnd += pktSize;
                                        this.cwndCnt = 0;
                                    }
                                    else
                                    {
                                        this.cwndCnt++;
                                    }
                                }
                                break;
                            default: //RENO
                                if (this.cwnd < this.ssthresh)
                                {
                                    this.cwnd += pktSize;
                                }
                                else
                                {
                                    this.cwnd += pktSize * TCPSock.mss / cwnd;
                                }
                                break;
                        }
                        debugCC("(A" + this.cwnd + ")");
                        this.base++; //advance base
                        this.node.logPacket(":");
                        this.bytesAck += pktSize;
                        this.sendQueue.remove(0);
                        this.nRemoved++;
                    }

                    for (int i = this.nextSeq - this.base; i < this.sendQueue.size(); i++)
                    {
                        byte[] toSend = this.sendQueue.get(i);
                        // debugCC("(M" + minWindow() + ")"); //for flow control test (see README)
                        if (bytesTransit() + toSend.length > minWindow())
                        {
                            break;
                        }
                        sendDataPacket(toSend, this.nextSeq);
                        this.node.logPacket(".");
                        this.nextSeq++;
                        this.bytesSent += toSend.length;
                    }
                    debug("sw start timer");
                    this.node.addTCPTimer(this.timerMs, this, new TCPSockTask(this.state, this.type, this.base));
                }
                else
                {
                    this.node.logPacket("?");
                    this.dupAcks++;
                    if (this.dupAcks == 3)
                    {
                        //CC Handle duplicate ACK (packet loss)
                        switch (this.cControl)
                        {
                            case CUBIC:
                                this.epochStart = 0;
                                if (this.cwnd < this.wLastMax && this.fastConverge)
                                {
                                    this.wLastMax = this.cwnd * ((2 - this.beta) / 2);
                                }
                                else
                                {
                                    this.wLastMax = cwnd;
                                }
                                this.cwnd = Math.max(TCPSock.mss, Math.round(this.cwnd * (1 - this.beta)));
                                this.ssthresh = this.cwnd;
                                break;
                            default: //RENO
                                this.cwnd = Math.max(TCPSock.mss, cwnd / 2); //don't go below MSS
                                this.ssthresh = this.cwnd;
                        }

                        //TCP Fast Retransfer
                        sendDataPacket(this.sendQueue.get(0), this.base);
                        debugCC("(D" + this.cwnd + ")");
                        debugCC("f"); //for log
                    }
                }
                if (this.base == this.nextSeq)
                {
                    if (state == State.SHUTDOWN && this.sendQueue.size() == 0)
                    {
                        debug("sw sending fin");
                        Transport tcpPack = new Transport(this.localPort, this.remPort, Transport.FIN, 0, this.seq, new byte[0]);
                        this.node.sendSegment(this.localAddr, this.remAddr, Protocol.TRANSPORT_PKT, tcpPack.pack());
                        this.node.logPacket("F");
                        this.node.addTCPTimer(this.timerMs, this, new TCPSockTask(State.FIN_SENT, this.type, this.seq));
                    }
                }
            }
            else if ((this.state == State.SHUTDOWN || this.state == State.SYN_SENT || this.state == State.SYN_ACK_SENT) && packetType == Transport.FIN)
            {
                this.node.logPacket("F");
                this.state = State.CLOSED;
                this.tcpMan.setPort(this.localPort, false);
            }
        }
    }

    public void handleSynPacket(Packet packet, int from)
    {
        debug("handleSynPacket");
        this.node.logPacket("S");
        if (this.type == Type.LISTEN && this.state == State.LISTEN && this.backlog.size() < this.backlogSize)
        {
            //setup new connection socket
            int addr = from;
            Transport packetPayload = Transport.unpack(packet.getPayload());
            int port = packetPayload.getSrcPort();
            int seq = packetPayload.getSeqNum();
            TCPSock connSock = this.tcpMan.connSock(this.localPort, addr, port, seq, this.isSecure);
            // System.out.println("HHH");
            byte[] payload = packetPayload.getPayload();
            // System.out.println("size of Alice's public key:" + senderDHKey.length);
            // System.out.println("Alice's public key: " + toHexString(senderDHKey));
            if (payload.length == 0 && isSecure) {
                System.out.println("Client attempting to initiate unsecure connection on a secured server!");
                Transport tcpPacket = new Transport(this.localPort, packetPayload.getSrcPort(), Transport.FIN, 0, 0, new byte[0]);
                this.node.sendSegment(this.localAddr, from, Protocol.TRANSPORT_PKT, tcpPacket.pack());
                this.node.logPacket("F");
                return;
            }
            if (isSecure)
            {
                int receivedCert = connSock.unpackSenderPacket(payload);
                if (!node.validCertificate(receivedCert)) {
                    System.out.println("Cert from client invalid!");
                    Transport tcpPacket = new Transport(this.localPort, packetPayload.getSrcPort(), Transport.FIN, 0, 0, new byte[0]);
                    this.node.sendSegment(this.localAddr, from, Protocol.TRANSPORT_PKT, tcpPacket.pack());
                    this.node.logPacket("F");
                    return;
                }
                else
                {
                    System.out.println("Cert from client valid.");
                }

                try
                {
                    connSock.receiverDHKeyCreate();
                }
                catch (Exception e)
                {
                    // printStackTrace method
                    // prints line numbers + call stack
                    e.printStackTrace();
                
                    // Prints what exception has been thrown
                    System.out.println(e);
                }
            }
            connSock.sendSynAck(seq);
            this.node.logOutput("setup connSock and sent ACK");

            String addrPort = String.valueOf(addr) + ":" + String.valueOf(port);
            if (this.backlog.size() < this.backlogSize)
            {
                this.backlog.addLast(connSock);
                debug("added " + addr + ":" + port + " to backlog");
            }
        }
    }

    public void handleTimeout(TCPSockTask task)
    {
        debug("TIMEOUT " + task.getSeqN());
        if (task.getState() == State.SYN_SENT && this.state == State.SYN_SENT)
        {
            //resend SYN packet
            this.node.logOutput("resending SYN...");
            //create SYN packet

            byte[] payload = packSenderPacket();
            // System.out.println("packet size: " + payload.length);
            //send SYN packet
            this.seq = ThreadLocalRandom.current().nextInt(0, 2147483647);
            // this.node.logOutput("timout seq: " + this.seq);
            this.base = this.seq + 1; 
            this.baseOrig = this.base;
            this.nextSeq = this.seq + 1;
            Transport tcpPacket = new Transport(this.localPort, this.remPort, Transport.SYN, 0, 0, payload);
            this.synTime = tcpTimestamp();
            this.node.sendSegment(this.localAddr, this.remAddr, Protocol.TRANSPORT_PKT, tcpPacket.pack());
            this.node.logPacket("!");
            this.node.addTCPTimer(2000, this, new TCPSockTask(this.state, this.type, this.seq));
        }
        else if ((task.getState() == State.ESTABLISHED || task.getState() == State.SHUTDOWN) && (this.state == State.ESTABLISHED || this.state == State.SHUTDOWN) && task.getSeqN() == this.base)
        {
            debug("sw timeout" + String.valueOf(this.seq));
            if (this.base == this.nextSeq) //no need to resend packets
            {
                debug("base == nextseq, no need to add timer");
            }
            else
            {
                if (this.nextSeq - this.base > this.sendQueue.size())
                {
                    this.node.logError("ERROR");
                }
                for (int i = 0; i < this.nextSeq - this.base; i++)
                {
                    this.sendDataPacket(this.sendQueue.get(i), this.base + i);
                    this.node.logPacket("!");
                    debug("resent seq" + (this.base + i));
                }
                this.node.addTCPTimer(this.timerMs, this, new TCPSockTask(this.state, this.type, this.base));

                //CC handle timeout
                switch (this.cControl)
                {
                    case CUBIC:
                        cubicReset();
                        break;
                    default: //RENO
                        this.ssthresh = Math.max(TCPSock.mss, this.cwnd / 2);
                        this.cwnd = TCPSock.mss;
                        break;
                }
                debugCC("(T" + this.cwnd + ")");
            }
        }
        else if (task.getState() == State.FIN_SENT)
        {
            this.state = State.CLOSED;
            this.tcpMan.setPort(this.localPort, false);
        }
        else
        {
            debug("task already done!");
            debug("oldseq: " + String.valueOf(task.getSeqN()) + " newseq: " + this.seq);
        }
    }

    public void sendDataPacket(byte[] tcpPayload, int seqNum)
    {
        byte[] encPayload = (isSecure) ? new byte[0] : tcpPayload;
        // byte[] decPayload = new byte[0];
        if (isSecure)
        {
            try
            {
                encPayload = encrypt(tcpPayload, this.dhSecret256, this.dhSecret128, seqNum);
                // decPayload = decrypt(encPayload, this.dhSecret256, this.dhSecret128, seqNum);
            }
            catch (Exception e)
            {
                    // printStackTrace method
                    // prints line numbers + call stack
                    e.printStackTrace();
                
                    // Prints what exception has been thrown
                    System.out.println(e);
            }
        }
        
        Transport tcpPacket = new Transport(this.localPort, this.remPort, Transport.DATA, 0, seqNum, encPayload);
        this.node.sendSegment(this.localAddr, this.remAddr, Protocol.TRANSPORT_PKT, tcpPacket.pack());
    }

    public void sendAckPacket(int seqNum) //sends ACK with receive Window
    {
        Transport ackPacket = new Transport(this.localPort, this.remPort, Transport.ACK, recWindow(), seqNum, new byte[0]);
        this.node.sendSegment(this.localAddr, this.remAddr, Protocol.TRANSPORT_PKT, ackPacket.pack());
    }

    public void setState(State state)
    {
        this.state = state;
    }

    private long bytesTransit()
    {
        return this.bytesSent - this.bytesAck;
    }

    private long minWindow()
    {
        return Math.max(Math.min(this.cwnd, this.rwnd), TCPSock.mss);
    }

    public int getLocalPort()
    {
        return this.localPort;
    }

    public int getLocalAddr()
    {
        return this.localAddr;
    }

    public int getRemPort()
    {
        return this.remPort;
    }

    public int getRemAddr()
    {
        return this.remAddr;
    }

    private long tcpTimestamp() //for RTT calculation and CUBIC
    {
        return Utility.fishTime() / 1000;
    }

    private void debug(String message)
    {
        if (TCPSock.DEBUG)
        {
            this.node.logOutput("DEBUG: " + message);
        }
    }

    private void debugCC(String message)
    {
        if (TCPSock.DEBUGCC)
        {
            this.node.logPacket(message);
        }
    }

    public void setCCAlgorithm(int type)
    {
        if (type == 1)
        {
            this.cControl = CC.CUBIC;
            this.node.logOutput("Using TCP Cubic");
        }
        else
        {
            this.cControl = CC.RENO;
            this.node.logOutput("Using TCP Reno");
        }
    }

    private void cubicReset()
    {
        this.wLastMax = 0;
        this.epochStart = 0;
        this.originPoint = 0;
        this.wTCP = 0;
        this.k = 0;
        this.ackCnt = 0;
    }

    private double cubicUpdate()
    {
        double count;
        this.ackCnt += 1;
        if (this.epochStart <= 0)
        {
            this.epochStart = tcpTimestamp();
            if (this.cwnd < this.wLastMax)
            {
                this.k = Math.cbrt((this.wLastMax - this.cwnd) / this.capC);
                this.originPoint = this.wLastMax;
            }
            else
            {
                this.k = 0;
                this.originPoint = this.cwnd;
            }
            this.ackCnt = TCPSock.mss;
            this.wTCP = this.cwnd;
        }
        long t = this.tcpTimestamp() + this.rtt - this.epochStart;
        double target = this.originPoint + this.capC * Math.pow(t - this.k, 3);
        if (target > this.cwnd)
        {
            count = this.cwnd / (target - this.cwnd);
        }
        else
        {
            count = 100 * cwnd;
        }
        if (tcpFriend)
        {
            //begin CUBIC TCP Friendliness
            this.wTCP = this.wTCP + ((3 * this.beta / (2 - this.beta)) * this.ackCnt / this.cwnd);
            this.ackCnt = 0;
            if (this.wTCP > this.cwnd)
            {
                double maxCount = this.cwnd / (this.wTCP - this.cwnd);
                if (count > maxCount)
                {
                    count = maxCount;
                }
            }
        }
        return count;
    }

    private byte[] encrypt(byte[] plaintext, byte[] key, byte[] IV, int seqNum) throws Exception
    {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        byte[] newIV = ivXOR(IV, seqNum);
        
        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, newIV);
        
        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        
        // Perform Encryption
        byte[] cipherText = cipher.doFinal(plaintext);

        // System.out.println("Inflation: " + (cipherText.length - plaintext.length));
        return cipherText;
    }

    private byte[] decrypt(byte[] cipherText, byte[] key, byte[] IV, int seqNum) throws Exception
    {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        byte[] newIV = ivXOR(IV, seqNum);
        
        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, newIV);
        
        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        
        // Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);
        
        return decryptedText;
    }

    private byte[] ivXOR(byte[] IV, int seqNum)
    {
        BigInteger bigInt = BigInteger.valueOf(seqNum);      
        byte[] intByteArray = bigInt.toByteArray();
        byte[] newIV = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            newIV[i] = (byte) (IV[i] ^ intByteArray[i % 4]);
        }
        return newIV;
    }

    private byte[] toSHA(byte[] dhSecret) throws NoSuchAlgorithmException
    {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(dhSecret);
    }

    private void senderDHKeyCreate() throws Exception
    {
        /*
         * Alice creates her own DH key pair with 2048-bit key size
         */
        System.out.println("Sender: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(2048);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
        
        // Alice creates and initializes her DH KeyAgreement object
        System.out.println("Sender: Initialization ...");
        this.senderKeyAgree = KeyAgreement.getInstance("DH");
        this.senderKeyAgree.init(aliceKpair.getPrivate());
        
        // Alice encodes her public key, and sends it over to Bob.
        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();
        // System.out.println("size of Sender's public key:" + alicePubKeyEnc.length);
        // System.out.println("Sender's public key: " + toHexString(alicePubKeyEnc));
        this.senderDHKey = alicePubKeyEnc;
    }

    private void senderDHSecretCreate() throws Exception
    {
        /*
         * Alice uses Bob's public key for the first (and only) phase
         * of her version of the DH
         * protocol.
         * Before she can do so, she has to instantiate a DH public key
         * from Bob's encoded key material.
         */
        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(this.receiverDHKey);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
        // System.out.println("ALICE: Execute PHASE1 ...");
        this.senderKeyAgree.doPhase(bobPubKey, true);
        this.dhSecret = this.senderKeyAgree.generateSecret();
        // System.out.println("Alice secret: " + toHexString(this.dhSecret));
        MessageDigest md = MessageDigest.getInstance("MD5");
        this.dhSecret128 = md.digest(this.dhSecret);
        // System.out.println("Alice secret128: " + toHexString(this.dhSecret128));
        md = MessageDigest.getInstance("SHA-256");
        this.dhSecret256 = md.digest(this.dhSecret);
        // System.out.println("Alice secret256: " + toHexString(this.dhSecret256));

    }

    private void receiverDHKeyCreate() throws Exception
    {
        /*
         * Let's turn over to Bob. Bob has received Alice's public key
         * in encoded format.
         * He instantiates a DH public key from the encoded key material.
         */
        KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(this.senderDHKey);

        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

        /*
         * Bob gets the DH parameters associated with Alice's public key.
         * He must use the same parameters when he generates his own key
         * pair.
         */
        DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey)alicePubKey).getParams();

        // Bob creates his own DH key pair
        // System.out.println("BOB: Generate DH keypair ...");
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamFromAlicePubKey);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();

        // Bob creates and initializes his DH KeyAgreement object
        // System.out.println("BOB: Initialization ...");
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());

        // Bob encodes his public key, and sends it over to Alice.
        this.receiverDHKey = bobKpair.getPublic().getEncoded();
        // System.out.println("size of Bob's public key:" + this.receiverDHKey.length);
        // System.out.println("Bob's public key: " + toHexString(this.receiverDHKey));

        /*
         * Bob uses Alice's public key for the first (and only) phase
         * of his version of the DH
         * protocol.
         */
        // System.out.println("BOB: Execute PHASE1 ...");
        bobKeyAgree.doPhase(alicePubKey, true);
        this.dhSecret = bobKeyAgree.generateSecret();
        // System.out.println("Bob secret: " + toHexString(this.dhSecret));
        MessageDigest md = MessageDigest.getInstance("MD5");
        this.dhSecret128 = md.digest(this.dhSecret);
        // System.out.println("Bob secret128: " + toHexString(this.dhSecret128));
        md = MessageDigest.getInstance("SHA-256");
        this.dhSecret256 = md.digest(this.dhSecret);
        // System.out.println("Bob secret256: " + toHexString(this.dhSecret256));
    }

    private byte[] packSenderPacket()
    {
        // this.node.logOutput("isSecure: " + this.isSecure);
        if (!isSecure)
        {
            return new byte[0];
        }
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        byteStream.write((byte) this.node.getAddr());
        // byteStream.write(HEADER_SIZE + this.payload.length);	
        byte[] dhKeySizeByteArray = (BigInteger.valueOf(this.senderDHKey.length)).toByteArray();
        int paddingLength = 4 - dhKeySizeByteArray.length;
        for(int i = 0; i < paddingLength; i++) {
            byteStream.write(0);
        }
        byteStream.write(dhKeySizeByteArray, 0, Math.min(dhKeySizeByteArray.length, 4));
        byteStream.write(this.senderDHKey, 0, this.senderDHKey.length);
        return byteStream.toByteArray();
        // TODO: write byte for certificate
    }

    private byte[] packReceiverPacket()
    {
        if (!isSecure)
        {
            return new byte[0];
        }
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        byteStream.write((byte) this.node.getAddr());
        // byteStream.write(HEADER_SIZE + this.payload.length);	
        byte[] dhKeySizeByteArray = (BigInteger.valueOf(this.receiverDHKey.length)).toByteArray();
        int paddingLength = 4 - dhKeySizeByteArray.length;
        for(int i = 0; i < paddingLength; i++) {
            byteStream.write(0);
        }
        byteStream.write(dhKeySizeByteArray, 0, Math.min(dhKeySizeByteArray.length, 4));
        byteStream.write(this.receiverDHKey, 0, this.receiverDHKey.length);
        // TODO: write certificate stuff
        return byteStream.toByteArray();
    }

    private int unpackSenderPacket(byte[] packet)
    {
        // System.out.println("packet size: " + packet.length);
        ByteArrayInputStream byteStream = new ByteArrayInputStream(packet);
        int cert = byteStream.read();
        // System.out.println("CERT UNPACK SENDER PACKET: " + cert);
        receivedCert = cert;
        byte[] sizeByteArray = new byte[4];
	    byteStream.read(sizeByteArray, 0, 4);
        int senderDHKeySize = (new BigInteger(sizeByteArray)).intValue();
        // System.out.println("Alice Key Size: " + senderDHKeySize);
        this.senderDHKey = new byte[senderDHKeySize];
        byteStream.read(this.senderDHKey, 0, senderDHKeySize);
        return cert;
        // TODO: read byte for certificate
    }

    private int unpackReceiverPacket(byte[] packet)
    {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(packet);
        int cert = byteStream.read();
        // System.out.println("CERT UNPACK RECEIVER PACKET: " + cert);
        receivedCert = cert;
        byte[] sizeByteArray = new byte[4];
	    byteStream.read(sizeByteArray, 0, 4);
        int receiverDHKeySize = (new BigInteger(sizeByteArray)).intValue();
        // System.out.println("Bob Key Size: " + receiverDHKeySize);
        this.receiverDHKey = new byte[receiverDHKeySize];
        byteStream.read(this.receiverDHKey, 0, receiverDHKeySize);
        // System.out.println("Bob key: " + toHexString(this.receiverDHKey));
        // TODO: read certificate stuff
        return cert;
    }

    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }

    /*
     * End of socket API
     */
}
