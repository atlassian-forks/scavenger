package com.navercorp.scavenger.util;

import org.apache.commons.codec.digest.MurmurHash3;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashGenerator {

    public static class DefaultHash {
        public static String from(String signature) {
            return Murmur.from(signature);
        }
    }

    private static class Murmur {
        private static String from(String signature) {
            long[] x64hash = MurmurHash3.hash128x64(signature.getBytes(StandardCharsets.UTF_8));
            return Long.toHexString(x64hash[0]) + Long.toHexString(x64hash[1]);
        }
    }

    private static class Sha256 {
        private static final MessageDigest md;

        static {
            try {
                md = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        private static String from(String signature) {
            md.update(signature.getBytes(StandardCharsets.UTF_8));
            return String.format("%x", new BigInteger(1, md.digest()));
        }
    }

    private static class Md5 {
        private static final MessageDigest md;

        static {
            try {
                md = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        private static String from(String signature) {
            md.update(signature.getBytes(StandardCharsets.UTF_8));
            return String.format("%x", new BigInteger(1, md.digest()));
        }
    }
}
