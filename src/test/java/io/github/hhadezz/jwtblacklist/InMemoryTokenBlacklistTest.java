package io.github.hhadezz.jwtblacklist;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class InMemoryTokenBlacklistTest {

    private static final Instant START = Instant.parse("2026-11-08T10:00:00.500Z");

    private MutableClock clock;
    private InMemoryTokenBlacklist blacklist;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(START);
        JwtBlacklistProperties properties = new JwtBlacklistProperties();
        properties.setMaxTokenLifetime(Duration.ofHours(1));
        blacklist = new InMemoryTokenBlacklist(properties, clock);
    }

    @Test
    void revokedTokenIsRejectedUntilItExpires() {
        blacklist.revoke("token-1", Duration.ofMinutes(10));
        assertThat(blacklist.isRevoked("token-1")).isTrue();
        assertThat(blacklist.isRevoked("token-2")).isFalse();

        clock.advance(Duration.ofMinutes(10));
        assertThat(blacklist.isRevoked("token-1")).isFalse();
        assertThat(blacklist.size()).isZero();
    }

    @Test
    void revokeUntilInstantUsesRemainingLifetime() {
        blacklist.revoke("token-1", START.plus(Duration.ofSeconds(30)));
        clock.advance(Duration.ofSeconds(29));
        assertThat(blacklist.isRevoked("token-1")).isTrue();
        clock.advance(Duration.ofSeconds(1));
        assertThat(blacklist.isRevoked("token-1")).isFalse();
    }

    @Test
    void alreadyExpiredTokensAreNotStored() {
        blacklist.revoke("token-1", Duration.ZERO);
        blacklist.revoke("token-2", START.minusSeconds(5));
        assertThat(blacklist.size()).isZero();
    }

    @Test
    void missingExpiryFallsBackToMaxTokenLifetime() {
        blacklist.revoke("token-1", (Instant) null);
        clock.advance(Duration.ofMinutes(59));
        assertThat(blacklist.isRevoked("token-1")).isTrue();
        clock.advance(Duration.ofMinutes(1));
        assertThat(blacklist.isRevoked("token-1")).isFalse();
    }

    @Test
    void signOutEverywhereRevokesOlderTokensOnly() {
        Instant oldIssuedAt = START.minusSeconds(60);
        blacklist.revokeAllForSubject("42");

        assertThat(blacklist.isRevoked("old", "42", oldIssuedAt)).isTrue();
        // issued in the same second as the cut-off (e.g. the new token after a password change)
        assertThat(blacklist.isRevoked("new", "42", START.plusMillis(300))).isFalse();
        assertThat(blacklist.isRevoked("other-user", "7", oldIssuedAt)).isFalse();
        // without subject/iat only the token itself is checked
        assertThat(blacklist.isRevoked("old")).isFalse();
    }

    @Test
    void signOutEverywhereExpiresAfterMaxTokenLifetime() {
        blacklist.revokeAllForSubject("42");
        clock.advance(Duration.ofHours(1));
        assertThat(blacklist.isRevoked("old", "42", START.minusSeconds(60))).isFalse();
    }

    @Test
    void combinedCheckStillCatchesIndividuallyRevokedTokens() {
        blacklist.revoke("token-1", Duration.ofMinutes(5));
        assertThat(blacklist.isRevoked("token-1", "42", START)).isTrue();
    }
}
