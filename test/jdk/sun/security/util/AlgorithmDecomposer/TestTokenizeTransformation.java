/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 */

/*
 * @test
 * @bug 8359388 8368984
 * @summary Tests AlgorithmDecomposer.tokenizeTransformation parsing
 * @modules java.base/sun.security.util
 * @run main/othervm
 *      --add-exports=java.base/sun.security.util=ALL-UNNAMED
 *      TestTokenizeTransformation
 */

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import sun.security.util.AlgorithmDecomposer;

public class TestTokenizeTransformation {

    public static void main(String[] args) {

        // Positive tests: valid forms

        // algorithm only
        assertTokens("AES", "AES");
        assertTokens("  AES  ", "AES");

        // algorithm/mode
        assertTokens("AES/CBC", "AES", "CBC");
        assertTokens(" AES / CBC ", "AES", "CBC");

        // algorithm/mode/padding
        assertTokens("AES/CBC/PKCS5Padding", "AES", "CBC", "PKCS5Padding");
        assertTokens(" AES / CBC / PKCS5Padding ", "AES", "CBC", "PKCS5Padding");
        assertTokens("AES/ CBC/PKCS5Padding  ", "AES", "CBC", "PKCS5Padding");
        assertTokens("AES/CBC / PKCS5Padding", "AES", "CBC", "PKCS5Padding");

        // SHA512/2xx algorithm name handling
        assertTokens("SHA512/224", "SHA512/224");
        assertTokens("SHA512/256", "SHA512/256");

        assertTokens("SHA512/224/CFB/NoPadding", "SHA512/224", "CFB", "NoPadding");
        assertTokens("HmacSHA512/256/CBC/PKCS5Padding", "HmacSHA512/256", "CBC", "PKCS5Padding");

        // Preserve original casing
        assertTokens("sHa512/256/cFb/nOpAdDiNg", "sHa512/256", "cFb", "nOpAdDiNg");

        // Negative tests: invalid forms

        // Empty / missing algorithm
        expectNSAE("");
        expectNSAE("   ");

        // Missing or empty mode
        expectNSAE("AES/");
        expectNSAE("AES/ ");
        expectNSAE("AES/ /");

        // Empty mode or padding
        expectNSAE("AES//");
        expectNSAE("AES//PKCS5Padding");
        expectNSAE("AES/CBC/");
        expectNSAE("AES/CBC/ ");

        // SHA512/2xx empty components (both dashed and non-dashed)
        expectNSAE("SHA512/224/");
        expectNSAE("SHA512/224//");
        expectNSAE("SHA512/224/CBC/");
        expectNSAE("SHA-512/256/ ");
        expectNSAE("SHA-512/256//NoPadding");

        // Extra separators
        expectNSAE("AES/CBC/PKCS5Padding/EXTRA");
        expectNSAE("SHA512/256/CBC/PKCS5Padding/EXTRA");
        expectNSAE("AES/GCM/NoPadding///");

        // Null handling
        expectNPE();
    }

    private static void assertTokens(String transformation, String... expected) {
        try {
            String[] actual = AlgorithmDecomposer.tokenizeTransformation(transformation);
            if (!Arrays.equals(actual, expected)) {
                throw new AssertionError(
                        "Unexpected tokens for '" + printable(transformation) + "'.\n" +
                                "Expected: " + Arrays.toString(expected) + "\n" +
                                "Actual:   " + Arrays.toString(actual));
            }
        } catch (NoSuchAlgorithmException unexpected) {
            throw new AssertionError(
                    "Did not expect NoSuchAlgorithmException for '" +
                            printable(transformation) + "'",
                    unexpected);
        }
    }

    private static void expectNSAE(String transformation) {
        try {
            AlgorithmDecomposer.tokenizeTransformation(transformation);
            throw new AssertionError(
                    "Expected NoSuchAlgorithmException for '" +
                            printable(transformation) + "'");
        } catch (NoSuchAlgorithmException expected) {
            // OK
        }
    }

    private static void expectNPE() {
        try {
            AlgorithmDecomposer.tokenizeTransformation(null);
            throw new AssertionError("Expected NullPointerException for null input");
        } catch (NullPointerException expected) {
            // OK
        } catch (NoSuchAlgorithmException unexpected) {
            throw new AssertionError(
                    "Did not expect NoSuchAlgorithmException for null input",
                    unexpected);
        }
    }

    private static String printable(String s) {
        return s == null
                ? "null"
                : s.replace("\n", "\\n")
                        .replace("\r", "\\r")
                        .replace("\t", "\\t");
    }
}