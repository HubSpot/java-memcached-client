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
import java.util.concurrent.Future;

public class TLSConnectionManager implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(TLSConnectionManager.class);

    private final SSLContext sslContext;
    private SSLEngine sslEngine;

    private SSLSession currentSession;

    private ByteBuffer appOutBuffer; // Holds the data we are preparing to send out
    private ByteBuffer appInBuffer; // Holds the data we have received and unwrapped
    private ByteBuffer networkOutBuffer; // Holds the data we are sending across the wire
    private ByteBuffer networkInBuffer; // Holds the data we have received from the wire

    public TLSConnectionManager(SSLContext sslContext) {
        this.sslContext = sslContext;
    }

    private void initSSLEngine() {
        // We are the client, not the server
        if (sslEngine != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Resetting SSL Engine");
            }
            closeSslEngine();
        }
        sslEngine = sslContext.createSSLEngine();
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
        if (LOG.isDebugEnabled()) {
            LOG.debug("%s - Beginning handshake.", socketChannel.getRemoteAddress());
        }

        try {
            initSSLEngine();
            sslEngine.beginHandshake();
            currentSession = sslEngine.getSession();
            initBuffers(currentSession);

            HandshakeStatus handshakeStatus = sslEngine.getHandshakeStatus();
            if (LOG.isDebugEnabled()) {
                LOG.debug("%s - Handshake status: %s", socketChannel.getRemoteAddress(), handshakeStatus.name());
            }
            while (!Thread.currentThread().isInterrupted()
                    && handshakeStatus != HandshakeStatus.FINISHED
                    && handshakeStatus != HandshakeStatus.NOT_HANDSHAKING) {

                switch (handshakeStatus) {
                    case NEED_TASK:
                        // we need to finish these tasks for the handshake to continue
                        List<Runnable> tasks = new ArrayList<>();
                        Runnable currentTask = sslEngine.getDelegatedTask();
                        while(currentTask != null) {
                            tasks.add(currentTask);
                            currentTask = sslEngine.getDelegatedTask();
                        }
                        for (Runnable task : tasks) {
                            task.run();
                        }
                        break;
                    case NEED_WRAP:
                        // We're about to send something to the server, but it needs to be wrapped first
                        networkOutBuffer.clear();
                        SSLEngineResult wrapResult = sslEngine.wrap(appOutBuffer, networkOutBuffer);
                        handleHandshakeWrapResult(socketChannel, wrapResult);
                        break;
                    case NEED_UNWRAP:
                        networkInBuffer.clear();
                        // We need to receive a message from the server, but it needs to be unwrapped first
                        if (socketChannel.read(networkInBuffer) < 0) {
                            // The message was empty
                            if (sslEngine.isInboundDone() && sslEngine.isOutboundDone()) {
                                // SSL Engine closed before handshake could complete
                                return false;
                            }
                            // We're done with the handshake, signal that we aren't going to be sending or receiving any more data
                            try {
                                sslEngine.closeInbound();
                            } catch (SSLException e) {
                                if (LOG.isDebugEnabled()) {
                                    // This doesn't seem to be critical, but it could be nice to know about
                                    LOG.warn("{} - tried to close inbound traffic but has not received a TLS close notification yet due to end of stream.", socketChannel.getRemoteAddress(), e);
                                }
                            }
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
                if (LOG.isDebugEnabled()) {
                    LOG.debug("%s - Handshake status: %s", socketChannel.getRemoteAddress(), handshakeStatus.name());
                }
            }

            // If we were interrupted, get out
            if (Thread.currentThread().isInterrupted()) {
                this.close();
                throw new InterruptedException("Thread interrupted while completing SSL Handshake");
            }


        } catch (SSLException | InterruptedException e) {
            throw new RuntimeException("Caught exception during SSL Handshake", e);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("%s - Handshake complete.", socketChannel.getRemoteAddress());
        }
        return true;
    }

    @Override
    public void close() throws IOException {
        closeSslEngine();
    }

    private void closeSslEngine() {
        sslEngine.setEnableSessionCreation(false);
        sslEngine.closeOutbound();
        try {
            sslEngine.closeInbound();
        } catch (SSLException e) {
            if (LOG.isDebugEnabled()) {
                // This doesn't seem to be critical, but it could be nice to know about
                LOG.warn("Tried to close inbound traffic but has not received a TLS close notification yet due to end of stream.", e);
            }
        }
        sslEngine = null;
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
        networkOutBuffer.flip(); // Change from reading to writing
        // Send data over the wire
        while(networkOutBuffer.hasRemaining()) {
            try {
                socketChannel.write(networkOutBuffer);
            } catch (IOException e) {
                throw new SSLException("Failed to write wrapped buffer.", e);
            }
        }
    }
}
