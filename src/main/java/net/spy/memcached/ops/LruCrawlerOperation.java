package net.spy.memcached.ops;

public interface LruCrawlerOperation extends Operation {
    interface Callback extends OperationCallback {
        /**
         * Invoked once for every stat returned from the server.
         *
         * @param key key value
         * @param exp expiration time
         * @param la last access time
         * @param cas check and set value
         * @param fetch has the value been fetched
         * @param slabClass slab class id
         * @param size size of the value
         */
        void gotCacheEntry(String key, long exp, long la, long cas, boolean fetch, int slabClass, long size);
    }
}
