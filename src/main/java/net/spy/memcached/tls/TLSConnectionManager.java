package net.spy.memcached.tls;

import net.spy.memcached.compat.log.Logger;
import net.spy.memcached.compat.log.LoggerFactory;

import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class TLSConnectionManager implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(TLSConnectionManager.class);

    private final SSLContext sslContext;
    private SSLEngine sslEngine;

    public static final int WRAP_STATUS_BUFFER_UNDERFLOW = -1;
    public static final int WRAP_STATUS_BUFFER_OVERFLOW = -2;


    private SSLSession currentSession;

    private ByteBuffer appOutBuffer; // Holds the data we are preparing to send out
    private ByteBuffer appInBuffer; // Holds the data we have received and unwrapped
    private ByteBuffer networkOutBuffer; // Holds the data we are sending across the wire
    private ByteBuffer networkInBuffer; // Holds the data we have received from the wire

    private CountDownLatch handshakeSuccessful;

    public TLSConnectionManager(SSLContext sslContext) {
        this.sslContext = sslContext;
        this.handshakeSuccessful = new CountDownLatch(1);
    }

    private void initSslEngine() {
        ensureSslEngineInitialized(true);
    }

    private void ensureSslEngineInitialized(boolean forceReset) {
        // We are the client, not the server
        if (sslEngine != null) {
            if (forceReset) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Resetting SSL Engine");
                }
                closeSslEngine();
            } else {
                return;
            }
        }
        sslEngine = sslContext.createSSLEngine();
        sslEngine.setUseClientMode(true);
    }

    private void initBuffers(SSLSession session) {
        clearBuffers();
        appOutBuffer = allocateAppBuffer();
        appInBuffer = allocateAppBuffer();
        networkOutBuffer = allocateNetworkBuffer();
        networkInBuffer = allocateNetworkBuffer();
    }

    private void clearBuffers() {
        if(appOutBuffer != null) {
            appOutBuffer = null; 
            LOG.info("Released appOutBuffer");
        }
        if(appInBuffer != null) {
            appInBuffer = null; 
            LOG.info("Released appInBuffer");
        }
        if(networkOutBuffer != null) {
            networkOutBuffer = null;
            LOG.info("Released networkOutBuffer");
        }
        if(networkInBuffer != null) {
            networkInBuffer = null;
            LOG.info("Released networkInBuffer");
        }
    }

    public boolean doHandshake(SocketChannel socketChannel) throws IOException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("%s - Beginning handshake.", socketChannel.getRemoteAddress());
        }

        try {
            initSslEngine();
            sslEngine.beginHandshake();
            currentSession = sslEngine.getSession();
            initBuffers(currentSession);

            HandshakeStatus handshakeStatus = sslEngine.getHandshakeStatus();
            if (LOG.isDebugEnabled()) {
                LOG.info("%s - Handshake status: %s", socketChannel.getRemoteAddress(), handshakeStatus.name());
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
                        // We need to receive a message from the server, but it needs to be unwrapped first
                        if (socketChannel.read(networkInBuffer) < 0) {
                            // The message hit the end of the stream
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
                                    LOG.warn("%s - tried to close inbound traffic but has not received a TLS close notification yet due to end of stream.", socketChannel.getRemoteAddress(), e);
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
        handshakeSuccessful.countDown();
        return true;
    }

    /**
     * Uses the keys stored in the SSLEngine to encrypt bytes to send to the server
     * @param appOutBuffer The buffer containing the unencrypted data to send. Should be at least sslEngine.getApplicationBufferSize() in length.
     * @param networkOutBuffer The buffer to write to, should be at least sslEngine.getPacketBuffer() in length
     * @return If the wrap succeeds, the number of bytes produced by the wrap.
     *         If a Buffer Overflow happened, TLSConnectionManager.WRAP_STATUS_BUFFER_OVERFLOW
     *         If a Buffer Underflow happened, TLSConnectionManager.WRAP_STATUS_BUFFER_UNDERFLOW
     * @throws SSLException from the call to SSLEngine::wrap if any occurred
     */
    public int wrapBufferForSend(ByteBuffer appOutBuffer, ByteBuffer networkOutBuffer) throws SSLException {
        SSLEngineResult wrap = sslEngine.wrap(appOutBuffer, networkOutBuffer);
        switch (wrap.getStatus()) {
            case BUFFER_UNDERFLOW:
                return WRAP_STATUS_BUFFER_UNDERFLOW;
            case BUFFER_OVERFLOW:
                return WRAP_STATUS_BUFFER_OVERFLOW;
            case OK:
                return wrap.bytesProduced();
            case CLOSED:
                throw new RuntimeException(sslEngine.getPeerHost() + " - TLS Connection is closed");
            default:
                // This might get hit if the Status enum ever gets expanded, but for now, we should not hit this. Case
                // required to make the Java compiler happy.
                throw new IllegalStateException("Invalid SSL status: " + wrap.getStatus());
        }
    }

    public UnwrapResult unwrapReceivedBuffer (ByteBuffer networkInBuffer) throws IOException {
        appInBuffer.clear();
        while(!Thread.currentThread().isInterrupted()) {
            SSLEngineResult unwrapResult = sslEngine.unwrap(networkInBuffer, appInBuffer);
            switch (unwrapResult.getStatus()) {
                case BUFFER_OVERFLOW:
                    // Application buffer is too small, set it to the correct size
                    enlargeBuffer(appInBuffer, sslEngine.getSession().getApplicationBufferSize());
                    break;
                case BUFFER_UNDERFLOW:
                    // We aren't done reading the response yet
                    return new UnwrapResult(null, unwrapResult);
                case OK:
                    appInBuffer.flip();
                    return new UnwrapResult(appInBuffer, unwrapResult);
                case CLOSED:
                    String peerHost = sslEngine.getPeerHost();  // Capture host before closing
                    this.close();
                    throw new IOException(peerHost + " - TLS Connection is closed");
                default:
                    // This might get hit if the Status enum ever gets expanded, but for now, we should not hit this. Case
                    // required to make the Java compiler happy.
                    throw new IllegalStateException("Invalid SSL status: " + unwrapResult.getStatus());
            }
        }
        throw new RuntimeException(sslEngine.getPeerHost() + " - Interrupted while unwrapping read buffer");
    }

    @Override
    public void close() throws IOException {
        clearBuffers();
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

    public ByteBuffer allocateAppBuffer() {
        return allocateAppBuffer(0);
    }

    public ByteBuffer allocateAppBuffer(int suggestedSize) {
        ensureSslEngineInitialized(false);
        int requiredSize = Math.max(sslEngine.getSession().getApplicationBufferSize(), suggestedSize);
        // allocateDirect() to keep all bytes contiguous in memory
        return ByteBuffer.allocateDirect(requiredSize);
    }

    public ByteBuffer allocateNetworkBuffer() {
        return ByteBuffer.allocateDirect(0);
    }

    public ByteBuffer allocateNetworkBuffer(int suggestedSize) {
        ensureSslEngineInitialized(false);
        int requiredSize = Math.max(sslEngine.getSession().getPacketBufferSize(), suggestedSize);
        // allocateDirect() to keep all bytes contiguous in memory
        return ByteBuffer.allocateDirect(requiredSize);
    }

    private static ByteBuffer enlargeBuffer(ByteBuffer buffer, int suggestedCapacity) {
        if (suggestedCapacity > buffer.capacity()) {
            return ByteBuffer.allocateDirect(suggestedCapacity);
        } else {
            // If the suggested capacity is still too small, double the size
            return ByteBuffer.allocateDirect(buffer.capacity() * 2);
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

    public static class UnwrapResult {
        private final ByteBuffer dataBuffer;
        private final SSLEngineResult result;

        private UnwrapResult(ByteBuffer dataBuffer, SSLEngineResult result) {
            this.dataBuffer = dataBuffer;
            this.result = result;
        }

        public ByteBuffer getDataBuffer() {
            return dataBuffer;
        }

        public SSLEngineResult getResult() {
            return result;
        }
    }

    public boolean wasHandshakeSuccessful() {
        return handshakeSuccessful.getCount() == 0;
    }

    public boolean awaitHandshake(long msToWait) throws InterruptedException {
        return handshakeSuccessful.await(msToWait, TimeUnit.MILLISECONDS);
    }

    public void resetHandshakeStatus() {
        handshakeSuccessful = new CountDownLatch(1);
    }
}
