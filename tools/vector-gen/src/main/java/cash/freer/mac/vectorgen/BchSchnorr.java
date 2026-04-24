package cash.freer.mac.vectorgen;

import org.bitcoinj.core.Utils;

import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * BCH-2019 Schnorr signature — the variant freecashj ships and FC-AJDK uses
 * (see FC-AJDK/.../core/fch/SchnorrSignature.java). Pre-dates BIP-340; not
 * interoperable with it.
 *
 * Sign:
 *   k0 = SHA-256(d || m) mod n
 *   R  = k0 · G
 *   k  = (jacobi(R.y) == 1) ? k0 : (n - k0)
 *   e  = SHA-256(R.x || P_compressed_33 || m) mod n
 *   s  = (e·d + k) mod n
 *   sig = R.x(32) || s(32)
 *
 * Verify:
 *   r,s from sig
 *   e  = SHA-256(r || P_compressed_33 || m) mod n
 *   R  = s·G + (n - e)·P
 *   valid iff jacobi(R.y) == 1 and r == R.x
 *
 * Naive textbook EC math via BigInteger — slow but faithful to the
 * reference. Used only for test-vector generation.
 */
public final class BchSchnorr {

    public static final BigInteger P = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    public static final BigInteger N = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    public static final BigInteger[] G = {
            new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    };
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    public static byte[] sign(byte[] msg, BigInteger seckey) {
        if (msg.length != 32) {
            throw new IllegalArgumentException("msg must be 32 bytes");
        }
        if (seckey.signum() <= 0 || seckey.compareTo(N.subtract(BigInteger.ONE)) > 0) {
            throw new IllegalArgumentException("seckey out of range");
        }

        try {
            byte[] nonceInput = new byte[64];
            System.arraycopy(to32(seckey), 0, nonceInput, 0, 32);
            System.arraycopy(msg, 0, nonceInput, 32, 32);
            BigInteger k0 = toBigInt(sha256(nonceInput)).mod(N);
            if (k0.signum() == 0) {
                throw new IllegalStateException("k0 == 0 (negligible probability)");
            }

            BigInteger[] rPoint = pointMul(G, k0);
            BigInteger k = jacobi(rPoint[1]).equals(BigInteger.ONE) ? k0 : N.subtract(k0);

            byte[] rxBytes = to32(rPoint[0]);
            byte[] challengeInput = new byte[32 + 33 + 32];
            System.arraycopy(rxBytes, 0, challengeInput, 0, 32);
            System.arraycopy(compressPoint(pointMul(G, seckey)), 0, challengeInput, 32, 33);
            System.arraycopy(msg, 0, challengeInput, 65, 32);
            BigInteger e = toBigInt(sha256(challengeInput)).mod(N);

            byte[] out = new byte[64];
            System.arraycopy(rxBytes, 0, out, 0, 32);
            System.arraycopy(to32(e.multiply(seckey).add(k).mod(N)), 0, out, 32, 32);
            return out;
        } catch (Exception e) {
            throw new RuntimeException("schnorr_sign failed", e);
        }
    }

    public static boolean verify(byte[] msg, byte[] pubkey, byte[] sig) {
        if (msg.length != 32 || pubkey.length != 33 || sig.length != 64) {
            throw new IllegalArgumentException("bad lengths");
        }
        BigInteger[] point = decompressPoint(pubkey);
        if (point == null) return false;
        BigInteger r = toBigInt(sig, 0, 32);
        BigInteger s = toBigInt(sig, 32, 32);
        if (r.compareTo(P) >= 0 || s.compareTo(N) >= 0) return false;

        try {
            byte[] challengeInput = new byte[32 + 33 + 32];
            System.arraycopy(sig, 0, challengeInput, 0, 32);
            System.arraycopy(compressPoint(point), 0, challengeInput, 32, 33);
            System.arraycopy(msg, 0, challengeInput, 65, 32);
            BigInteger e = toBigInt(sha256(challengeInput)).mod(N);

            BigInteger[] rPoint = pointAdd(pointMul(G, s), pointMul(point, N.subtract(e)));
            return rPoint != null
                    && jacobi(rPoint[1]).equals(BigInteger.ONE)
                    && r.equals(rPoint[0]);
        } catch (Exception e) {
            throw new RuntimeException("schnorr_verify failed", e);
        }
    }

    // --- EC math --------------------------------------------------------

    public static BigInteger[] pointAdd(BigInteger[] a, BigInteger[] b) {
        if (a == null) return b;
        if (b == null) return a;
        if (a[0].equals(b[0]) && !a[1].equals(b[1])) return null;

        BigInteger lam;
        if (a[0].equals(b[0]) && a[1].equals(b[1])) {
            lam = THREE.multiply(a[0]).multiply(a[0])
                    .multiply(TWO.multiply(a[1]).modPow(P.subtract(TWO), P)).mod(P);
        } else {
            lam = b[1].subtract(a[1])
                    .multiply(b[0].subtract(a[0]).modPow(P.subtract(TWO), P)).mod(P);
        }
        BigInteger x3 = lam.multiply(lam).subtract(a[0]).subtract(b[0]).mod(P);
        BigInteger y3 = lam.multiply(a[0].subtract(x3)).subtract(a[1]).mod(P);
        return new BigInteger[]{x3, y3};
    }

    public static BigInteger[] pointMul(BigInteger[] p, BigInteger k) {
        BigInteger[] r = null;
        BigInteger[] cur = p;
        for (int i = 0; i < 256; i++) {
            if (k.shiftRight(i).and(BigInteger.ONE).equals(BigInteger.ONE)) {
                r = pointAdd(r, cur);
            }
            cur = pointAdd(cur, cur);
        }
        return r;
    }

    public static BigInteger jacobi(BigInteger x) {
        return x.modPow(P.subtract(BigInteger.ONE).divide(TWO), P);
    }

    public static byte[] compressPoint(BigInteger[] point) {
        byte[] out = new byte[33];
        out[0] = point[1].testBit(0) ? (byte) 0x03 : (byte) 0x02;
        System.arraycopy(to32(point[0]), 0, out, 1, 32);
        return out;
    }

    public static BigInteger[] decompressPoint(byte[] b) {
        if (b[0] != 0x02 && b[0] != 0x03) return null;
        boolean odd = (b[0] == 0x03);
        BigInteger x = toBigInt(b, 1, 32);
        BigInteger ySq = x.modPow(THREE, P).add(BigInteger.valueOf(7)).mod(P);
        BigInteger y0 = ySq.modPow(P.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), P);
        if (!ySq.equals(y0.modPow(TWO, P))) return null;
        BigInteger y = (y0.testBit(0) != odd) ? P.subtract(y0) : y0;
        return new BigInteger[]{x, y};
    }

    // --- utilities ------------------------------------------------------

    private static byte[] to32(BigInteger value) {
        return Utils.bigIntegerToBytes(value, 32);
    }

    private static BigInteger toBigInt(byte[] data) {
        return new BigInteger(1, data);
    }

    private static BigInteger toBigInt(byte[] data, int offset, int len) {
        byte[] slice = new byte[len];
        System.arraycopy(data, offset, slice, 0, len);
        return new BigInteger(1, slice);
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private BchSchnorr() {}
}
