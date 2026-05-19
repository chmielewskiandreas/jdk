/*
 * Copyright (c) 2026, Red Hat, Inc.
 *
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
* @bug 8315487
 * @summary Verify that ProvidersFilter correctly evaluates Cipher transformations when service
 *          algorithms and aliases include transformation components
 * @run main/othervm -enablesystemassertions CipherAliasTest
 */

import javax.crypto.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import jdk.test.lib.process.Proc;
import sun.security.util.KnownOIDs;

public class CipherAliasTest {
    private static final String SEC_FILTER_PROP = "jdk.security.providers.filter";
    private static final String PROVIDER_NAME = "MyProvider";
    private static final String AES_OID_ESC = KnownOIDs.AES.value().replace(".", "\\\\.");
    private static final String FILTER = "*.Cipher." + AES_OID_ESC + "/CBC/PKCS5Padding; " + // allow alias
            "!*.Cipher.AES/CBC/PKCS5Padding; " + // deny original
            "!*";

    public static class DummyCipherSpi extends CipherSpi {
        @Override
        protected void engineSetMode(String mode) {
        }

        @Override
        protected void engineSetPadding(String padding) {
        }

        @Override
        protected int engineGetBlockSize() {
            return 16;
        }

        @Override
        protected int engineGetOutputSize(int inputLen) {
            return inputLen;
        }

        @Override
        protected byte[] engineGetIV() {
            return null;
        }

        @Override
        protected AlgorithmParameters engineGetParameters() {
            return null;
        }

        @Override
        protected void engineInit(int opmode, Key key, SecureRandom random) {
        }

        @Override
        protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
                        SecureRandom random) {
        }

        @Override
        protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                        SecureRandom random) {
        }

        @Override
        protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
            return input;
        }

        @Override
        protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
                int outputOffset) {
            return inputLen;
        }

        @Override
        protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
            return input;
        }

        @Override
        protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                byte[] output, int outputOffset) {
            return inputLen;
        }
    }

    public static class MyProvider extends Provider {
        public MyProvider() {
            super(PROVIDER_NAME, 1.0, "Test provider");

            put("Cipher.AES/CBC", DummyCipherSpi.class.getName());
            put("Alg.Alias.Cipher." + KnownOIDs.AES.value() + "/CBC", "AES/CBC");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            Proc p = Proc.create(CipherAliasTest.class.getName()).args("child");
            p.env("JDK_JAVA_OPTIONS", "-enablesystemassertions");
            p.secprop(SEC_FILTER_PROP, FILTER);
            p.inheritIO();
            p.start().waitFor(0);

            System.out.println("TEST PASS - OK");
            return;
        }

        Security.getProviders();
        runTest();
    }

    private static void runTest() throws Exception {
        Provider provider = new MyProvider();
        Security.addProvider(provider);

        try {
            assertAllowed("AES/CBC/PKCS5Padding");
        } finally {
            Security.removeProvider(PROVIDER_NAME);
        }
    }

    private static void assertAllowed(String transformation) throws Exception {
        if (!canGetCipher(transformation)) {
            throw new Exception("Expected allowed: " + transformation);
        }
    }

    private static boolean canGetCipher(String transformation) {
        try {
            Cipher.getInstance(transformation, PROVIDER_NAME);
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}