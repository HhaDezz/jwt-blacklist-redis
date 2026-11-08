package io.github.hhadezz.jwtblacklist;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.connection.RedisConnectionFactory;

class JwtBlacklistAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JwtBlacklistAutoConfiguration.class));

    @Test
    void usesRedisWhenAConnectionFactoryExists() {
        runner.withBean(RedisConnectionFactory.class, () -> mock(RedisConnectionFactory.class))
                .run(context -> assertThat(context).hasSingleBean(TokenBlacklist.class)
                        .getBean(TokenBlacklist.class).isInstanceOf(RedisTokenBlacklist.class));
    }

    @Test
    void createsNothingWithoutRedis() {
        runner.run(context -> assertThat(context).doesNotHaveBean(TokenBlacklist.class));
    }

    @Test
    void inMemoryStoreNeedsNoRedis() {
        runner.withPropertyValues("jwt.blacklist.store=memory")
                .run(context -> assertThat(context).getBean(TokenBlacklist.class)
                        .isInstanceOf(InMemoryTokenBlacklist.class));
    }

    @Test
    void canBeDisabled() {
        runner.withPropertyValues("jwt.blacklist.enabled=false")
                .withBean(RedisConnectionFactory.class, () -> mock(RedisConnectionFactory.class))
                .run(context -> assertThat(context).doesNotHaveBean(TokenBlacklist.class));
    }

    @Test
    void yourOwnBeanWins() {
        TokenBlacklist custom = new InMemoryTokenBlacklist(new JwtBlacklistProperties());
        runner.withBean(TokenBlacklist.class, () -> custom)
                .withBean(RedisConnectionFactory.class, () -> mock(RedisConnectionFactory.class))
                .run(context -> assertThat(context.getBean(TokenBlacklist.class)).isSameAs(custom));
    }

    @Test
    void bindsProperties() {
        runner.withPropertyValues("jwt.blacklist.store=memory", "jwt.blacklist.key-prefix=myapp:bl:",
                        "jwt.blacklist.max-token-lifetime=2h", "jwt.blacklist.fail-mode=open")
                .run(context -> {
                    JwtBlacklistProperties p = context.getBean(JwtBlacklistProperties.class);
                    assertThat(p.getKeyPrefix()).isEqualTo("myapp:bl:");
                    assertThat(p.getMaxTokenLifetime()).isEqualTo(Duration.ofHours(2));
                    assertThat(p.getFailMode()).isEqualTo(JwtBlacklistProperties.FailMode.OPEN);
                });
    }
}
