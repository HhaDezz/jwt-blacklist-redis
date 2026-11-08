package io.github.hhadezz.jwtblacklist;

import java.time.Duration;
import java.time.Instant;

/**
 * Remembers signed-out JWTs until they would have expired anyway, so a stateless token can be
 * revoked before its {@code exp}.
 *
 * <p>Tokens are never stored as-is: implementations key them by a SHA-256 hash, so whoever can read
 * the store can't reuse a live token.
 */
public interface TokenBlacklist {

    /**
     * Revokes a token for as long as it has left to live. Does nothing if {@code timeToLive} is zero
     * or negative, because an expired token is already rejected by signature validation.
     *
     * @param token      the raw JWT (without the {@code Bearer } prefix)
     * @param timeToLive how long the token remains valid, e.g. {@code exp - now}
     */
    void revoke(String token, Duration timeToLive);

    /**
     * Revokes a token until its expiry time ({@code exp} claim).
     *
     * @param token     the raw JWT
     * @param expiresAt when the token expires; {@code null} uses {@code jwt.blacklist.max-token-lifetime}
     */
    void revoke(String token, Instant expiresAt);

    /** Returns {@code true} if this exact token has been revoked. */
    boolean isRevoked(String token);

    /**
     * Revokes every token issued to {@code subject} up to now ("sign out everywhere"), for example
     * after a password change. Tokens issued afterwards stay valid. Check them with
     * {@link #isRevoked(String, String, Instant)}.
     *
     * @param subject the user the tokens belong to, usually the {@code sub} claim
     */
    void revokeAllForSubject(String subject);

    /**
     * Returns {@code true} if the token itself was revoked, or if it was issued before the last
     * {@link #revokeAllForSubject(String)} for its subject. Both checks take a single round trip.
     *
     * @param token    the raw JWT
     * @param subject  the token's subject ({@code sub}); {@code null} skips the per-user check
     * @param issuedAt the token's {@code iat}; {@code null} skips the per-user check
     */
    boolean isRevoked(String token, String subject, Instant issuedAt);
}
