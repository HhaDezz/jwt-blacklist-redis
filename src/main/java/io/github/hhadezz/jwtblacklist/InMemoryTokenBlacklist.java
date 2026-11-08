package io.github.hhadezz.jwtblacklist;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * {@link TokenBlacklist} kept in this JVM. Same behaviour as {@link RedisTokenBlacklist}, but not
 * shared between instances and lost on restart: use it for tests and local development
 * ({@code jwt.blacklist.store=memory}).
 */
public class InMemoryTokenBlacklist implements TokenBlacklist {

    private static final int SWEEP_EVERY = 256;

    private final Map<String, Instant> tokens = new ConcurrentHashMap<>();
    private final Map<String, Entry> subjects = new ConcurrentHashMap<>();
    private final AtomicInteger writes = new AtomicInteger();
    private final JwtBlacklistProperties properties;
    private final Clock clock;

    private record Entry(long cutoffEpochSecond, Instant expiresAt) {
    }

    public InMemoryTokenBlacklist(JwtBlacklistProperties properties) {
        this(properties, Clock.systemUTC());
    }

    public InMemoryTokenBlacklist(JwtBlacklistProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    public void revoke(String token, Duration timeToLive) {
        String hash = TokenHashing.sha256Hex(token);
        if (timeToLive == null || timeToLive.isZero() || timeToLive.isNegative()) {
            return;
        }
        tokens.put(hash, clock.instant().plus(timeToLive));
        maybeSweep();
    }

    @Override
    public void revoke(String token, Instant expiresAt) {
        Duration ttl = expiresAt == null
                ? properties.getMaxTokenLifetime()
                : Duration.between(clock.instant(), expiresAt);
        revoke(token, ttl);
    }

    @Override
    public boolean isRevoked(String token) {
        String hash = TokenHashing.sha256Hex(token);
        Instant expiresAt = tokens.get(hash);
        if (expiresAt == null) {
            return false;
        }
        if (!clock.instant().isBefore(expiresAt)) {
            tokens.remove(hash, expiresAt);
            return false;
        }
        return true;
    }

    @Override
    public void revokeAllForSubject(String subject) {
        requireSubject(subject);
        Instant now = clock.instant();
        subjects.put(subject, new Entry(now.getEpochSecond(), now.plus(properties.getMaxTokenLifetime())));
        maybeSweep();
    }

    @Override
    public boolean isRevoked(String token, String subject, Instant issuedAt) {
        if (isRevoked(token)) {
            return true;
        }
        if (subject == null || issuedAt == null) {
            return false;
        }
        Entry entry = subjects.get(requireSubject(subject));
        if (entry == null) {
            return false;
        }
        if (!clock.instant().isBefore(entry.expiresAt())) {
            subjects.remove(subject, entry);
            return false;
        }
        return issuedAt.getEpochSecond() < entry.cutoffEpochSecond();
    }

    /** Number of live entries (tokens plus subjects). For tests and diagnostics. */
    public int size() {
        sweep();
        return tokens.size() + subjects.size();
    }

    private void maybeSweep() {
        if (writes.incrementAndGet() % SWEEP_EVERY == 0) {
            sweep();
        }
    }

    private void sweep() {
        Instant now = clock.instant();
        tokens.values().removeIf(expiresAt -> !now.isBefore(expiresAt));
        subjects.values().removeIf(entry -> !now.isBefore(entry.expiresAt()));
    }

    private static String requireSubject(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be blank");
        }
        return subject;
    }
}
