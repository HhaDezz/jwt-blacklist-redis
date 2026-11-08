package io.github.hhadezz.jwtblacklist;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Runs against a real Redis at REDIS_HOST:REDIS_PORT (default localhost:6379).
 * Skipped, with a message, when no Redis is reachable. CI starts one as a service.
 */
class RedisTokenBlacklistIntegrationTest {

    private static final String PREFIX = "jwt-blacklist-test:";

    private static LettuceConnectionFactory factory;
    private static StringRedisTemplate redis;

    private JwtBlacklistProperties properties;
    private RedisTokenBlacklist blacklist;

    @BeforeAll
    static void connect() {
        String host = System.getenv().getOrDefault("REDIS_HOST", "localhost");
        int port = Integer.parseInt(System.getenv().getOrDefault("REDIS_PORT", "6379"));
        factory = new LettuceConnectionFactory(new RedisStandaloneConfiguration(host, port));
        factory.afterPropertiesSet();
        factory.start();
        redis = new StringRedisTemplate(factory);
        try {
            redis.execute(connection -> connection.ping(), true);
        } catch (DataAccessException e) {
            factory.destroy();
            Assumptions.abort("No Redis at " + host + ":" + port + " (set REDIS_HOST / REDIS_PORT): " + e.getMessage());
        }
    }

    @AfterAll
    static void disconnect() {
        if (factory != null) {
            factory.destroy();
        }
    }

    @BeforeEach
    void setUp() {
        Set<String> leftovers = redis.keys(PREFIX + "*");
        if (leftovers != null && !leftovers.isEmpty()) {
            redis.delete(leftovers);
        }
        properties = new JwtBlacklistProperties();
        properties.setKeyPrefix(PREFIX);
        properties.setMaxTokenLifetime(Duration.ofHours(8));
        blacklist = new RedisTokenBlacklist(redis, properties);
    }

    @Test
    void revokedTokenIsRejectedAndOthersAreNot() {
        blacklist.revoke("header.payload.signature", Duration.ofMinutes(15));
        assertThat(blacklist.isRevoked("header.payload.signature")).isTrue();
        assertThat(blacklist.isRevoked("another.token.here")).isFalse();
    }

    @Test
    void storesOnlyTheHashWithTheRemainingLifetimeAsTtl() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.c2lnbmF0dXJl";
        blacklist.revoke(token, Duration.ofMinutes(15));

        Set<String> keys = redis.keys(PREFIX + "*");
        assertThat(keys).containsExactly(PREFIX + "t:" + TokenHashing.sha256Hex(token));
        assertThat(keys.iterator().next()).doesNotContain(token);
        Long ttl = redis.getExpire(keys.iterator().next());
        assertThat(ttl).isBetween(14 * 60L, 15 * 60L);
    }

    @Test
    void redisExpiresTheEntryOnItsOwn() throws InterruptedException {
        blacklist.revoke("short-lived", Duration.ofMillis(1200));
        assertThat(blacklist.isRevoked("short-lived")).isTrue();
        Thread.sleep(1600);
        assertThat(blacklist.isRevoked("short-lived")).isFalse();
    }

    @Test
    void expiredTokensAreNotWritten() {
        blacklist.revoke("expired", Instant.now().minusSeconds(10));
        blacklist.revoke("zero", Duration.ZERO);
        assertThat(redis.keys(PREFIX + "*")).isEmpty();
    }

    @Test
    void signOutEverywhereRevokesTokensIssuedBefore() {
        Instant before = Instant.now().minusSeconds(120);
        blacklist.revokeAllForSubject("user-42");

        assertThat(blacklist.isRevoked("old-token", "user-42", before)).isTrue();
        assertThat(blacklist.isRevoked("fresh-token", "user-42", Instant.now().plusSeconds(1))).isFalse();
        assertThat(blacklist.isRevoked("old-token", "user-7", before)).isFalse();

        Long ttl = redis.getExpire(PREFIX + "s:user-42");
        assertThat(ttl).isBetween(8 * 3600L - 5, 8 * 3600L);
    }

    @Test
    void combinedCheckAlsoCatchesIndividuallyRevokedTokens() {
        blacklist.revoke("token-1", Duration.ofMinutes(5));
        assertThat(blacklist.isRevoked("token-1", "user-42", Instant.now())).isTrue();
        assertThat(blacklist.isRevoked("token-2", "user-42", Instant.now())).isFalse();
    }

    @Test
    void failsClosedOrOpenWhenRedisIsDown() {
        LettuceConnectionFactory dead = new LettuceConnectionFactory(new RedisStandaloneConfiguration("localhost", 1));
        dead.afterPropertiesSet();
        dead.start();
        try {
            StringRedisTemplate unreachable = new StringRedisTemplate(dead);

            properties.setFailMode(JwtBlacklistProperties.FailMode.CLOSED);
            RedisTokenBlacklist closed = new RedisTokenBlacklist(unreachable, properties);
            assertThat(closed.isRevoked("any")).isTrue();
            assertThat(closed.isRevoked("any", "user-42", Instant.now())).isTrue();

            JwtBlacklistProperties openProps = new JwtBlacklistProperties();
            openProps.setFailMode(JwtBlacklistProperties.FailMode.OPEN);
            RedisTokenBlacklist open = new RedisTokenBlacklist(unreachable, openProps);
            assertThat(open.isRevoked("any")).isFalse();

            // a sign-out that can't be stored must fail loudly
            assertThatThrownBy(() -> closed.revoke("any", Duration.ofMinutes(1)))
                    .isInstanceOf(DataAccessException.class);
        } finally {
            dead.destroy();
        }
    }
}
