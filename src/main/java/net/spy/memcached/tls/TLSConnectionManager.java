package net.spy.memcached.tls;

import net.spy.memcached.compat.log.Logger;
import net.spy.memcached.compat.log.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class TLSConnectionManager implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(TLSConnectionManager.class);

    private final SSLEngine sslEngine;

    private SSLSession currentSession;

    private ByteBuffer appOutBuffer; // Holds the data we are preparing to send out
    private ByteBuffer appInBuffer; // Holds the data we have received and unwrapped
    private ByteBuffer networkOutBuffer; // Holds the data we are sending across the wire
    private ByteBuffer networkInBuffer; // Holds the data we have received from the wire

    ExecutorService executor = Executors.newSingleThreadExecutor();

    public TLSConnectionManager(SSLContext sslContext) {
        this.sslEngine = sslContext.createSSLEngine();

        configureSslEngine();
    }

    private void configureSslEngine() {
        // We are the client, not the server
        sslEngine.setUseClientMode(true);
    }

    private void initBuffers(SSLSession session) {
        // allocateDirect() to keep all bytes contiguous in memory
        appOutBuffer = ByteBuffer.allocateDirect(session.getApplicationBufferSize());
        appInBuffer = ByteBuffer.allocateDirect(session.getApplicationBufferSize());
        networkOutBuffer = ByteBuffer.allocateDirect(session.getPacketBufferSize());
        networkInBuffer = ByteBuffer.allocateDirect(session.getPacketBufferSize());
    }

    public boolean doHandshake(SocketChannel socketChannel) throws IOException {
        LOG.info("{} - Beginning handshake.", socketChannel.getRemoteAddress());
        try {
            sslEngine.beginHandshake();
            currentSession = sslEngine.getSession();
            initBuffers(currentSession);

            HandshakeStatus handshakeStatus = sslEngine.getHandshakeStatus();
            while (!Thread.currentThread().isInterrupted()
                    && handshakeStatus != HandshakeStatus.FINISHED
                    && handshakeStatus != HandshakeStatus.NOT_HANDSHAKING) {
                LOG.info("{} - Handshake status: {}", socketChannel.getRemoteAddress(), handshakeStatus.name());
                switch (handshakeStatus) {
                    case NEED_TASK:
                        // we need to finish these tasks for the handshake to continue
                        List<Future<?>> tasks = new ArrayList<>();
                        Runnable currentTask = sslEngine.getDelegatedTask();
                        while(currentTask != null) {
                            tasks.add(executor.submit(currentTask));
                            currentTask = sslEngine.getDelegatedTask();
                        }
                        for (Future<?> task : tasks) {
                            try {
                                task.get();
                            } catch (ExecutionException e) {
                                // TODO make this more clear
                                throw new RuntimeException(e);
                            }
                        }
                        break;
                    case NEED_WRAP:
                        // We're about to send something to the server, but it needs to be wrapped first
                        networkOutBuffer.clear();
                        SSLEngineResult wrapResult = sslEngine.wrap(appOutBuffer, networkOutBuffer);
                        handleHandshakeWrapResult(socketChannel, wrapResult);
                        break;
                    case NEED_UNWRAP:
                        // We need to receive a message from the server, but it needs to be unwrapped first
                        if (socketChannel.read(networkInBuffer) < 0) {
                            // The message was empty
                            if (sslEngine.isInboundDone() && sslEngine.isOutboundDone()) {
                                // SSL Engine closed before handshake could complete
                                return false;
                            }
                            // We're done with the handshake, signal that we aren't going to be sending or receiving any more data
                            sslEngine.closeInbound();
                            sslEngine.closeOutbound();
                            break;
                        }
                        networkInBuffer.flip();
                        SSLEngineResult unwrapResult = sslEngine.unwrap(networkInBuffer, appInBuffer);
                        networkInBuffer.compact(); // Leaves any unread bytes while creating more room in the buffer
                        if (unwrapResult.getStatus() == SSLEngineResult.Status.CLOSED) {
                            return false; // Server closed session before handshake completed
                        }
                        handleHandshakeUnwrapResult(socketChannel, unwrapResult);
                        break;
                    case NEED_UNWRAP_AGAIN:
                        throw new UnsupportedOperationException("DTLS not supported");
                    default:
                        throw new IllegalStateException("Invalid SSL status: " + handshakeStatus);
                }

                handshakeStatus = sslEngine.getHandshakeStatus();
            }

            // If we were interrupted, get out
            if (Thread.currentThread().isInterrupted()) {
                this.close();
                throw new InterruptedException("Thread interrupted while completing SSL Handshake");
            }


        } catch (SSLException | InterruptedException e) {
            throw new RuntimeException("Caught exception during SSL Handshake", e);
        }
        return true;
    }

    @Override
    public void close() throws IOException {
        sslEngine.setEnableSessionCreation(false);
        sslEngine.closeOutbound();
        sslEngine.closeInbound();
    }

    private void handleHandshakeWrapResult(SocketChannel socketChannel, SSLEngineResult result) throws SSLException {
        switch (result.getStatus()) {
            case BUFFER_UNDERFLOW:
                // We should not get here
                throw new SSLException("Buffer underflow occurred after wrap");
            case BUFFER_OVERFLOW:
                // If networkOutBuffer is too small to contain the response
                networkOutBuffer = enlargeBuffer(networkOutBuffer, sslEngine.getSession().getPacketBufferSize());
                // Try again with new larger buffer
                break;
            case OK:
                sendNetworkBuffer(socketChannel);
                break;
            case CLOSED:
                // We need to tell the server we're closing
                sendNetworkBuffer(socketChannel);
                // The next status will be NEED_UNWRAP and we'll need to pre-emptively clear the input network data
                networkInBuffer.clear();
                break;
        }
    }

    private void handleHandshakeUnwrapResult(SocketChannel socketChannel, SSLEngineResult result) throws SSLException {
        switch (result.getStatus()) {
            case BUFFER_UNDERFLOW:
                // If the network buffer is too small
                networkInBuffer = enlargeBuffer(networkInBuffer, sslEngine.getSession().getPacketBufferSize());
                break;
            case BUFFER_OVERFLOW:
                // if networkInBuffer is larger than appInBuffer
                appInBuffer = enlargeBuffer(appInBuffer, sslEngine.getSession().getApplicationBufferSize());
                // try again with larger buffer
                break;
            case OK:
            case CLOSED:
                break;
        }
    }

    private static ByteBuffer enlargeBuffer(ByteBuffer buffer, int suggestedCapacity) {
        if (suggestedCapacity > buffer.capacity()) {
            return ByteBuffer.allocate(suggestedCapacity);
        } else {
            // If the suggested capacity is still too small, double the size
            return ByteBuffer.allocate(buffer.capacity() * 2);
        }
    }

    private void sendNetworkBuffer(SocketChannel socketChannel) throws SSLException {
        networkOutBuffer.flip(); // Change from read to write
        // Send data over the wire
        while(networkOutBuffer.hasRemaining()) {
            try {
                socketChannel.write(networkOutBuffer);
            } catch (IOException e) {
                throw new SSLException("Failed to write wrapped buffer.", e);
            }
        }
    }

    public static ArrayList<Byte> extractByteBuffer(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        ArrayList<Byte> bytes = new ArrayList<>();
        for(int i = 0; i < duplicate.remaining(); i++) {
            bytes.add(duplicate.get());
        }
        return bytes;
    }
}
