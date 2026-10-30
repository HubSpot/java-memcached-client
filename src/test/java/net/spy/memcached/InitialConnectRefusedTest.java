package net.spy.memcached;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public class InitialConnectRefusedTest {

  @Test
  public void testClientBuildsWhenInitialConnectIsRefused() throws Exception {
    // Connecting to the broadcast address is refused by the kernel inside the
    // connect() call itself, before the constructor has finished, which is the
    // same shape as a ClusterIP with no ready endpoints failing a connect
    // synchronously. Construction used to NPE in queueReconnect for this case
    // because the metrics field was assigned after createConnections.
    List<InetSocketAddress> addrs = AddrUtil.getAddresses("255.255.255.255:11211");

    MemcachedClient client = new MemcachedClient(new DefaultConnectionFactory(), addrs);
    try {
      assertTrue(client.getAvailableServers().isEmpty());
      assertEquals(1, client.getUnavailableServers().size());
    } finally {
      client.shutdown();
    }
  }

  @Test
  public void testOpenChannelsAreClosedWhenConstructionFails() throws Exception {
    // An unresolved address fails outside the SocketException handler, so
    // construction aborts part-way through the list. Every channel created up
    // to that point must be closed before the exception propagates.
    final List<SocketChannel> created = new ArrayList<SocketChannel>();
    ConnectionFactory cf = new DefaultConnectionFactory() {
      @Override
      public MemcachedNode createMemcachedNode(SocketAddress sa, SocketChannel ch,
          int bufSize) {
        created.add(ch);
        return super.createMemcachedNode(sa, ch, bufSize);
      }
    };

    List<InetSocketAddress> addrs =
        new ArrayList<InetSocketAddress>(AddrUtil.getAddresses("255.255.255.255:11211"));
    addrs.add(InetSocketAddress.createUnresolved("memcached-no-such-host.invalid", 11211));

    try {
      new MemcachedClient(cf, addrs);
      fail("Construction should have failed on the unresolved address");
    } catch (IllegalArgumentException expected) {
      // UnresolvedAddressException: expected, construction must still fail.
    }
    for (SocketChannel ch : created) {
      assertFalse("channel should be closed after failed construction", ch.isOpen());
    }
  }
}

