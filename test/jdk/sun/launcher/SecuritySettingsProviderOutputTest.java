/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * @test
 * @bug 0000000
 * @summary Verify -XshowSettings:security provider output prints aliases and NOT allowed services via SharedSecrets
 * @run main/othervm SecuritySettingsProviderOutputTest
 */

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigestSpi;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.TimeUnit;

public class SecuritySettingsProviderOutputTest {

    public static final class DummyDigest extends MessageDigestSpi {
        @Override
        protected void engineUpdate(byte input) {
        }

        @Override
        protected void engineUpdate(byte[] input, int offset, int len) {
        }

        @Override
        protected byte[] engineDigest() {
            return new byte[0];
        }

        @Override
        protected void engineReset() {
        }
    }

    public static final class TestProvider extends Provider {
        public TestProvider() {
            super("TestSecuritySettingsProvider", "1.0",
                    "Test provider for SecuritySettings output");
            put("MessageDigest.FOO", DummyDigest.class.getName());
            put("Alg.Alias.MessageDigest.BAR", "FOO");
        }
    }

    public static void main(String[] args) throws Exception {
        // Create a security properties snippet that APPENDS to the master file.
        // -Djava.security.properties=<file> appends/overrides keys from the master
        // file,
        // while -Djava.security.properties==<file> would completely override it.
        // [1](https://bugs.java.com/bugdatabase/view_bug?bug_id=7133344)
        Path secProps = Files.createTempFile("securitysettings-provider", ".props");
        secProps.toFile().deleteOnExit();

        // Provider list is defined as security.provider.1, security.provider.2, ... in
        // order.
        // [2](https://docs.oracle.com/en/java/javase/11/security/security-properties-file.html)
        // Add our provider at the next contiguous index to ensure it is loaded.
        int nextIndex = Security.getProviders().length + 1;
        String providerClass = TestProvider.class.getName();

        Files.writeString(secProps,
                "security.provider." + nextIndex + "=" + providerClass + "\n",
                StandardCharsets.UTF_8);

        String javaHome = System.getProperty("test.jdk", System.getProperty("java.home"));
        String javaBin = Path.of(javaHome, "bin", "java").toString();

        String testClasses = System.getProperty("test.classes");
        if (testClasses == null) {
            // jtreg normally sets this; keep a safe fallback.
            testClasses = System.getProperty("java.class.path", ".");
        }

        Process p = new ProcessBuilder(
                javaBin,
                "-cp", testClasses,
                "-Djava.security.properties=" + secProps.toString(),
                "-XshowSettings:security",
                "-version").redirectErrorStream(true).start();

        if (!p.waitFor(60, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new AssertionError("Timed out waiting for child JVM");
        }

        String out = readAll(p.getInputStream());

        // Strong sanity check that the property made it into the child's security
        // properties dump.
        assertContains(out, "security.provider." + nextIndex + "=" + providerClass);

        // Now verify that the provider is present in the provider configuration output.
        String block = extractProviderBlock(out, "TestSecuritySettingsProvider");
        if (block == null) {
            throw new AssertionError("Did not find provider block for TestSecuritySettingsProvider.\n" +
                    "Full output:\n" + out);
        }

        assertContains(block, "Provider name: TestSecuritySettingsProvider");
        assertContains(block, "Provider services allowed");
        assertContains(block, "Provider services NOT allowed");

        // Our service should be listed in allowed services.
        assertContains(block, "MessageDigest.FOO");

        // Alias list should be printed (via SharedSecrets accessor in
        // SecuritySettings).
        assertContains(block, "aliases:");
        assertContains(block, "BAR");

        // Current behavior (placeholder filter): nothing is disallowed.
        assertContains(block, "<none>");
    }

    private static String readAll(InputStream in) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        in.transferTo(baos);
        return baos.toString(StandardCharsets.UTF_8);
    }

    private static void assertContains(String text, String needle) {
        if (!text.contains(needle)) {
            throw new AssertionError("Expected output to contain: '" + needle + "'\n" +
                    "Actual text:\n" + text);
        }
    }

    /**
     * Extract provider section beginning at "Provider name: <name>" and ending
     * before the next separator line or end-of-output.
     */
    private static String extractProviderBlock(String out, String providerName) {
        String marker = "Provider name: " + providerName;
        int start = out.indexOf(marker);
        if (start < 0) {
            return null;
        }

        String sep = "----------------------------------------";
        int next = out.indexOf(sep, start);
        if (next < 0) {
            return out.substring(start);
        }
        return out.substring(start, next);
    }
}