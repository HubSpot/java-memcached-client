package net.spy.memcached.internal;

public class CacheEntry {
    private final String key;
    private final long exp;
    private final long la;
    private final long cas;
    private final boolean fetch;
    private final int slabClass;
    private final long size;

    public CacheEntry(String key, long exp, long la, long cas, boolean fetch, int slabClass, long size){
        this.key = key;
        this.exp = exp;
        this.la = la;
        this.cas = cas;
        this.fetch = fetch;
        this.slabClass = slabClass;
        this.size = size;
    }

    public String getKey() {
        return key;
    }

    public long getExp() {
        return exp;
    }

    public long getLa() {
        return la;
    }

    public long getCas() {
        return cas;
    }

    public boolean isFetch() {
        return fetch;
    }

    public int getSlabClass() {
        return slabClass;
    }

    public long getSize() {
        return size;
    }
}
