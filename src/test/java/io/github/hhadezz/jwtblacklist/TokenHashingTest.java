package io.github.hhadezz.jwtblacklist;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import org.junit.jupiter.api.Test;

class TokenHashingTest {

    @Test
    void hashesToKnownSha256Hex() {
        // echo -n "abc" | shasum -a 256
        assertThat(TokenHashing.sha256Hex("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void sameTokenSameHashDifferentTokenDifferentHash() {
        assertThat(TokenHashing.sha256Hex("a.b.c")).isEqualTo(TokenHashing.sha256Hex("a.b.c"))
                .isNotEqualTo(TokenHashing.sha256Hex("a.b.d")).hasSize(64);
    }

    @Test
    void rejectsBlankTokens() {
        assertThatIllegalArgumentException().isThrownBy(() -> TokenHashing.sha256Hex(" "));
        assertThatIllegalArgumentException().isThrownBy(() -> TokenHashing.sha256Hex(null));
    }
}
