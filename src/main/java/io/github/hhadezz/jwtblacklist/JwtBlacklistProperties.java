package io.github.hhadezz.jwtblacklist;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Settings under {@code jwt.blacklist.*}. Redis itself is configured with {@code spring.data.redis.*}. */
@ConfigurationProperties(prefix = "jwt.blacklist")
public class JwtBlacklistProperties {

    /** Where revoked tokens are kept. */
    public enum Store {
        /** Redis, shared by every instance of your app. */
        REDIS,
        /** This JVM only. For tests and local development; lost on restart. */
        MEMORY
    }

    /** What a check does when the store can't be reached. */
    public enum FailMode {
        /** Treat the token as revoked: requests are rejected until Redis is back. */
        CLOSED,
        /** Treat the token as valid: requests keep working, but sign-outs aren't enforced meanwhile. */
        OPEN
    }

    /** Whether to create the {@link TokenBlacklist} bean. */
    private boolean enabled = true;

    /** Where revoked tokens are kept. */
    private Store store = Store.REDIS;

    /** Prefix for every Redis key this library writes. */
    private String keyPrefix = "jwt:blacklist:";

    /**
     * The longest lifetime your app gives a token. Used as the TTL of "sign out everywhere" entries,
     * and for tokens revoked without an expiry time. Set it to your JWT expiration.
     */
    private Duration maxTokenLifetime = Duration.ofHours(24);

    /** What a check does when Redis can't be reached. */
    private FailMode failMode = FailMode.CLOSED;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Store getStore() {
        return store;
    }

    public void setStore(Store store) {
        this.store = store;
    }

    public String getKeyPrefix() {
        return keyPrefix;
    }

    public void setKeyPrefix(String keyPrefix) {
        this.keyPrefix = keyPrefix;
    }

    public Duration getMaxTokenLifetime() {
        return maxTokenLifetime;
    }

    public void setMaxTokenLifetime(Duration maxTokenLifetime) {
        this.maxTokenLifetime = maxTokenLifetime;
    }

    public FailMode getFailMode() {
        return failMode;
    }

    public void setFailMode(FailMode failMode) {
        this.failMode = failMode;
    }
}
