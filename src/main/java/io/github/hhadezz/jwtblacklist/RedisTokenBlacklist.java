package io.github.hhadezz.jwtblacklist;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.function.BooleanSupplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Redis-backed {@link TokenBlacklist}.
 *
 * <ul>
 *   <li>A revoked token is a key {@code <prefix>t:<sha256>} whose TTL is the token's remaining
 *       lifetime, so Redis removes it on its own. No clean-up job is needed.</li>
 *   <li>"Sign out everywhere" is a key {@code <prefix>s:<subject>} holding the cut-off time in epoch
 *       seconds. Tokens whose {@code iat} is earlier are revoked.</li>
 *   <li>{@link #isRevoked(String, String, Instant)} reads both keys with one {@code MGET}.</li>
 * </ul>
 *
 * <p>Checks follow {@link JwtBlacklistProperties#getFailMode()} when Redis is unreachable. Writes
 * (revocations) always throw, so a failed sign-out is never reported as a success.
 */
public class RedisTokenBlacklist implements TokenBlacklist {

    private static final Logger log = LoggerFactory.getLogger(RedisTokenBlacklist.class);
    private static final String REVOKED = "1";

    private final StringRedisTemplate redis;
    private final JwtBlacklistProperties properties;
    private final Clock clock;

    public RedisTokenBlacklist(StringRedisTemplate redis, JwtBlacklistProperties properties) {
        this(redis, properties, Clock.systemUTC());
    }

    public RedisTokenBlacklist(StringRedisTemplate redis, JwtBlacklistProperties properties, Clock clock) {
        this.redis = redis;
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    public void revoke(String token, Duration timeToLive) {
        String key = tokenKey(token);
        if (timeToLive == null || timeToLive.isZero() || timeToLive.isNegative()) {
            return;
        }
        redis.opsForValue().set(key, REVOKED, timeToLive);
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
        String key = tokenKey(token);
        return guarded(() -> Boolean.TRUE.equals(redis.hasKey(key)));
    }

    @Override
    public void revokeAllForSubject(String subject) {
        // JWT iat has one-second precision. Truncating keeps a token issued in this same second
        // (for example the new token handed out after a password change) valid.
        long cutoff = clock.instant().getEpochSecond();
        redis.opsForValue().set(subjectKey(subject), Long.toString(cutoff), properties.getMaxTokenLifetime());
    }

    @Override
    public boolean isRevoked(String token, String subject, Instant issuedAt) {
        if (subject == null || issuedAt == null) {
            return isRevoked(token);
        }
        List<String> keys = Arrays.asList(tokenKey(token), subjectKey(subject));
        return guarded(() -> {
            List<String> values = redis.opsForValue().multiGet(keys);
            if (values == null) {
                return false;
            }
            if (values.get(0) != null) {
                return true;
            }
            String cutoff = values.get(1);
            return cutoff != null && issuedAt.getEpochSecond() < Long.parseLong(cutoff);
        });
    }

    String tokenKey(String token) {
        return properties.getKeyPrefix() + "t:" + TokenHashing.sha256Hex(token);
    }

    String subjectKey(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be blank");
        }
        return properties.getKeyPrefix() + "s:" + subject;
    }

    private boolean guarded(BooleanSupplier check) {
        try {
            return check.getAsBoolean();
        } catch (DataAccessException e) {
            boolean revoked = properties.getFailMode() == JwtBlacklistProperties.FailMode.CLOSED;
            log.warn("Token blacklist unavailable ({}); treating token as {} (jwt.blacklist.fail-mode={})",
                    e.getMessage(), revoked ? "revoked" : "valid", properties.getFailMode());
            return revoked;
        }
    }
}
