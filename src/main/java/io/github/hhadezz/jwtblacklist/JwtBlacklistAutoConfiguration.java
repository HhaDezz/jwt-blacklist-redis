package io.github.hhadezz.jwtblacklist;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Creates a {@link TokenBlacklist} bean: Redis by default (using the app's
 * {@code spring.data.redis.*} connection), or in-memory with {@code jwt.blacklist.store=memory}.
 * Define your own {@code TokenBlacklist} bean to replace it.
 */
@AutoConfiguration(afterName = {
        // Spring Boot 4
        "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration",
        // Spring Boot 3
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration"
})
@ConditionalOnProperty(prefix = "jwt.blacklist", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(JwtBlacklistProperties.class)
public class JwtBlacklistAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(TokenBlacklist.class)
    @ConditionalOnProperty(prefix = "jwt.blacklist", name = "store", havingValue = "memory")
    public InMemoryTokenBlacklist inMemoryTokenBlacklist(JwtBlacklistProperties properties) {
        return new InMemoryTokenBlacklist(properties);
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(StringRedisTemplate.class)
    @ConditionalOnProperty(prefix = "jwt.blacklist", name = "store", havingValue = "redis", matchIfMissing = true)
    static class RedisStoreConfiguration {

        @Bean
        @ConditionalOnMissingBean(TokenBlacklist.class)
        @ConditionalOnBean(RedisConnectionFactory.class)
        public RedisTokenBlacklist redisTokenBlacklist(RedisConnectionFactory connectionFactory,
                                                       JwtBlacklistProperties properties) {
            return new RedisTokenBlacklist(new StringRedisTemplate(connectionFactory), properties);
        }
    }
}
