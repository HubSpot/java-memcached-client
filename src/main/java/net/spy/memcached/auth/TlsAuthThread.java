package net.spy.memcached.auth;

import net.spy.memcached.MemcachedConnection;
import net.spy.memcached.MemcachedNode;
import net.spy.memcached.OperationFactory;
import net.spy.memcached.compat.SpyThread;

import java.util.concurrent.atomic.AtomicBoolean;

public class TlsAuthThread extends SpyThread {

    private final MemcachedConnection connection;
    private final AuthDescriptor authDescriptor;
    private final MemcachedNode node;

    public TlsAuthThread(MemcachedConnection connection, AuthDescriptor authDescriptor, MemcachedNode node) {
        this.connection = connection;
        this.authDescriptor = authDescriptor;
        this.node = node;

        start();
    }


    @Override
    public void run() {
        final AtomicBoolean done = new AtomicBoolean(false);
        long startTime = System.nanoTime();

        int retries = 0;
        while (!done.get() && !connection.isShutDown() && !authDescriptor.authThresholdReached()) {
            boolean handshakeResult = node.executeTlsHandshake();

            if (handshakeResult) {
                long endTime = System.nanoTime();
                getLogger().info("Completed handshake in " + (endTime - startTime) / 1000000 + " ms");
                node.authComplete();
                done.set(true);
            } else {
                getLogger().warn("Failed handshake attempt {}", retries);
            }
        }
    }
}
