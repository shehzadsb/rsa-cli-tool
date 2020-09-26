
package com.rsa.test;


import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.common.collect.ImmutableMap;
import com.rsa.shamir.Scheme;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Collections;
import org.junit.jupiter.api.Test;


class SchemeTest {
	
 
  @Test
  void hasProperties() {
    final Scheme scheme = new Scheme(new SecureRandom(), 5, 3);

    assertThat(scheme.n()).isEqualTo(5);
    assertThat(scheme.k()).isEqualTo(3);
  }

  //public Scheme(SecureRandom random, int n, int k) 
  @Test
  void tooManyShares() {
    assertThatThrownBy(() -> new Scheme(new SecureRandom(), 2000, 3))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void thresholdTooLow() {
    assertThatThrownBy(() -> new Scheme(new SecureRandom(), 1, 1))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void thresholdTooHigh() {
    assertThatThrownBy(() -> new Scheme(new SecureRandom(), 1, 2))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void joinEmptyParts() {
    assertThatThrownBy(() -> new Scheme(new SecureRandom(), 3, 2).join(Collections.emptyMap()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void joinIrregularParts() {
    final byte[] one = new byte[] {1};
    final byte[] two = new byte[] {1, 2};

    assertThatThrownBy(
            () -> new Scheme(new SecureRandom(), 3, 2).join(ImmutableMap.of(1, one, 2, two)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void splitAndJoinSingleByteSecret() {
    final Scheme scheme = new Scheme(new SecureRandom(), 8, 3);
    final byte[] secret = "x".getBytes(StandardCharsets.UTF_8);

    assertThat(scheme.join(scheme.split(secret))).containsExactly(secret);
  }

  @Test
  void splitAndJoinMoreThanByteMaxValueParts() {
    final Scheme scheme = new Scheme(new SecureRandom(), 200, 3);
    final byte[] secret = "x".getBytes(StandardCharsets.UTF_8);

    assertThat(scheme.join(scheme.split(secret))).containsExactly(secret);
  }

 
}
