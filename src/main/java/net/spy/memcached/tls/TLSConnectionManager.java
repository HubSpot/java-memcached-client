package net.spy.memcached.tls;

import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;
import net.spy.memcached.compat.log.Logger;
import net.spy.memcached.compat.log.LoggerFactory;
import javax.net.ssl.SSLContext;
import java.io.Closeable;
import java.io.IOException;
import java.nio.channels.SocketChannel;

public class TLSConnectionManager implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(TLSConnectionManager.class);

    private final SSLContext sslContext;

    private SSLSocket socket = null;

    public TLSConnectionManager(SSLContext sslContext) {
        this.sslContext = sslContext;
    }

    /**
     * Running
     */
    public SocketChannel createSslChannel(SocketChannel socketChannel) throws IOException {
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket(socketChannel.socket(), null, socketChannel.socket().getPort(), false);
        return socket.getChannel();
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

}
