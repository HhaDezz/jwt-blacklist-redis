# JWT Blacklist for Spring Boot (Redis)

Real sign-out for stateless JWTs. When a user signs out, their token is remembered in Redis until it would have expired anyway, and every request checks it with one fast lookup.

- **Fast:** one Redis `EXISTS` per request, or one `MGET` when you also use "sign out everywhere".
- **Nothing to clean up:** each entry's Redis TTL is the token's remaining lifetime, so Redis deletes it when the token would have expired.
- **No usable tokens at rest:** keys are SHA-256 hashes of the token, so whoever can read Redis can't replay a live JWT.
- **Sign out everywhere:** revoke every token a user holds (after a password change, say) without tracking them one by one.
- **Your choice when Redis is down:** fail closed (reject requests, the default) or fail open (keep serving).
- **Zero setup:** auto-configured from your existing `spring.data.redis.*` settings. An in-memory store is included for tests.

Works with any JWT library: you pass the raw token and its expiry.

## Requirements

Java 17+, Spring Boot 4 (also works on Spring Boot 3), and a Redis server.

## Install

Build and install it into your local Maven repository:

```bash
./mvnw install
```

Then add it to your app's `pom.xml`:

```xml
<dependency>
    <groupId>io.github.hhadezz</groupId>
    <artifactId>jwt-blacklist-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

It brings `spring-boot-starter-data-redis` with it, and connects with your usual settings:

```properties
spring.data.redis.host=localhost
spring.data.redis.port=6379
spring.data.redis.password=...

# Optional: match this to your JWT lifetime
jwt.blacklist.max-token-lifetime=8h
```

## Use it

Inject `TokenBlacklist`.

**Sign out** (revoke one token):

```java
public void logout(String token) {
    Date expiresAt = jwtUtil.extractExpiration(token);   // the token's exp claim
    tokenBlacklist.revoke(token, expiresAt.toInstant());
}
```

Or pass the time it has left: `tokenBlacklist.revoke(token, Duration.ofMillis(remainingMs))`.

**Check every request**, in your JWT filter, before trusting the token:

```java
if (tokenBlacklist.isRevoked(token)) {
    throw new BadCredentialsException("Token is invalid or expired");
}
```

**Sign out everywhere** (revoke all of a user's tokens issued until now):

```java
tokenBlacklist.revokeAllForSubject(user.getEmail());   // whatever you put in "sub"
```

To enforce it, check with the subject and issue time. It's still a single Redis round trip:

```java
Claims claims = jwtUtil.parse(token);
if (tokenBlacklist.isRevoked(token, claims.getSubject(), claims.getIssuedAt().toInstant())) {
    throw new BadCredentialsException("Token is invalid or expired");
}
```

A token issued in the same second as the cut-off stays valid, so the fresh token you hand out right after a password change keeps working. JWT `iat` only has one-second precision.

## Configuration

| Property | Default | What it does |
| --- | --- | --- |
| `jwt.blacklist.enabled` | `true` | Create the `TokenBlacklist` bean |
| `jwt.blacklist.store` | `redis` | `redis`, or `memory` for tests and local development (one JVM only, lost on restart) |
| `jwt.blacklist.key-prefix` | `jwt:blacklist:` | Prefix for every key this library writes |
| `jwt.blacklist.max-token-lifetime` | `24h` | TTL of "sign out everywhere" entries, and of tokens revoked without an expiry. Set it to your JWT lifetime |
| `jwt.blacklist.fail-mode` | `closed` | When Redis can't be reached during a check: `closed` treats the token as revoked (requests fail), `open` treats it as valid (requests work, but sign-outs aren't enforced until Redis is back) |

Revocations (writes) always throw if Redis is down, so a failed sign-out is never reported as a success.

To replace the implementation, define your own `TokenBlacklist` bean.

## What's stored in Redis

| Key | Value | TTL |
| --- | --- | --- |
| `jwt:blacklist:t:<sha256 of token>` | `1` | Token's remaining lifetime |
| `jwt:blacklist:s:<subject>` | Cut-off time (epoch seconds) | `max-token-lifetime` |

## Migrating from a hand-rolled Redis blacklist

Many apps start with a small service that stores the raw token in Redis, along these lines:

```java
redisTemplate.opsForValue().set("blacklist:" + token, "blacklisted", remainingMs, TimeUnit.MILLISECONDS);
Boolean.TRUE.equals(redisTemplate.hasKey("blacklist:" + token));
```

To switch:

1. Add the dependency above, and set `jwt.blacklist.max-token-lifetime` to your JWT lifetime.
2. Delete the old service and inject `TokenBlacklist` wherever it was used.
3. Replace the calls:

   | Before | After |
   | --- | --- |
   | `blacklistToken(token, remainingMs)` | `tokenBlacklist.revoke(token, Duration.ofMillis(remainingMs))` |
   | `isBlacklisted(token)` | `tokenBlacklist.isRevoked(token)` |

The new keys (`jwt:blacklist:t:…`) don't overlap the old ones, so tokens signed out before the switch work again until they expire. To avoid that window, deploy when nobody is signed in, or keep the old check alongside for one token lifetime.

## Develop

```bash
docker run -d -p 6379:6379 redis:7     # or any local redis-server
./mvnw verify
```

The Redis integration tests use `REDIS_HOST` / `REDIS_PORT` (default `localhost:6379`) and are skipped, with a message, when no Redis is reachable. GitHub Actions runs them against a Redis service on every push.

## License

MIT, see [LICENSE](LICENSE).
