
package com.rsa.test;

import java.util.Arrays;
import org.quicktheories.core.Gen;
import org.quicktheories.impl.Constraint;

public interface Generators {

  static Gen<Byte> bytes(int minValue, int maxValue) {
    return prng -> ((byte) prng.next(Constraint.between(minValue, maxValue)));
  }

  static Gen<Byte> bytes() {
    return bytes(0, 255);
  }

  static Gen<byte[]> byteArrays(int minSize, int maxSize) {
    final Gen<byte[]> gen =
        prng -> {
          final byte[] bytes = new byte[(int) prng.next(Constraint.between(minSize, maxSize))];
          for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) prng.next(Constraint.between(0, 255));
          }
          return bytes;
        };
    return gen.describedAs(Arrays::toString);
  }
}
