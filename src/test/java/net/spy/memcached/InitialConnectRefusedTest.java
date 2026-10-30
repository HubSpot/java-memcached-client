package net.spy.memcached;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.InetSocketAddress;
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
}
