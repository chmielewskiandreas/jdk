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
* @summary Test filtering of all service types
* @modules java.base/sun.security.jca
*          java.base/sun.security.util
* @library /test/lib
* @compile Helper.java
* @run main/othervm/timeout=600 -enablesystemassertions AllServicesTest
*/

import java.nio.file.Files;
import javax.xml.crypto.dsig.Transform;

public class AllServicesTest {

    private static final String SUCCESS_FILTER = "*.AlgorithmParameterGenerator.DiffieHellman; " +
            "*.AlgorithmParameters.PBES2; " +
            "*.CertificateFactory.X\\.509; " +
            "*.CertPathBuilder.PKIX; " +
            "*.CertPathValidator.PKIX; " +
            "*.CertStore.Collection; " +
            "*.Configuration.JavaLoginConfig; " +
            "*.KEM.DHKEM; " +
            "*.KeyAgreement.ECDH; " +
            "*.KeyFactory.DiffieHellman; " +
            "*.KeyGenerator.HmacSHA3-512; " +
            "*.KeyInfoFactory.DOM; " +
            "*.KeyManagerFactory.NewSunX509; " +
            "*.KeyPairGenerator.DiffieHellman; " +
            "*.KeyStore.PKCS12; " +
            "*.Mac.HmacSHA512; " +
            "*.MessageDigest.SHA-512; " +
            "*.SaslClientFactory.EXTERNAL; " +
            "*.SaslServerFactory.CRAM-MD5; " +
            "*.SecretKeyFactory.PBEWithHmacSHA512/256AndAES_256; " +
            "*.SecureRandom.SHA1PRNG; " +
            "*.MessageDigest.SHA-1; " +
            "*.Signature.EdDSA; " +
            "*.SSLContext.TLSv1\\.3; " +
            "*.TerminalFactory.PC/SC; " +
            "*.TransformService." +
            Transform.XPATH.replace(".", "\\.").replace(":", "\\:") + "; " +
            "*.TrustManagerFactory.PKIX; " +
            "*.XMLSignatureFactory.DOM";

    private static final String FAIL_FILTER = "!*.";

    private static final String[][] TESTED_SERVICES = {
            { "SunJCE", "AlgorithmParameterGenerator", "DiffieHellman" },
            { "SunJCE", "AlgorithmParameters", "PBES2" },
            { "SUN", "CertificateFactory", "X.509" },
            { "SUN", "CertPathBuilder", "PKIX" },
            { "SUN", "CertPathValidator", "PKIX" },
            { "SUN", "CertStore", "Collection" },
            { "SUN", "Configuration", "JavaLoginConfig" },
            { "SUN", "MessageDigest", "SHA-512" },
            { "SUN", "SecureRandom", "SHA1PRNG" },
            { "SunJCE", "KEM", "DHKEM" },
            { "SunEC", "KeyAgreement", "ECDH" },
            { "SunJCE", "KeyFactory", "DiffieHellman" },
            { "SunJCE", "KeyGenerator", "HmacSHA3-512" },
            { "SunJCE", "KeyPairGenerator", "DiffieHellman" },
            { "SunJSSE", "KeyManagerFactory", "NewSunX509" },
            { "SunJSSE", "KeyStore", "PKCS12" },
            { "SunJSSE", "SSLContext", "TLSv1.3" },
            { "SunJSSE", "TrustManagerFactory", "PKIX" },
            { "XMLDSig", "KeyInfoFactory", "DOM" },
            { "XMLDSig", "TransformService", Transform.XPATH },
            { "XMLDSig", "XMLSignatureFactory", "DOM" },
            { "SunJCE", "Mac", "HmacSHA512" },
            { "SunSASL", "SaslClientFactory", "EXTERNAL" },
            { "SunSASL", "SaslServerFactory", "CRAM-MD5" },
            { "SunJCE", "SecretKeyFactory", "PBEWithHmacSHA512/256AndAES_256" },
            { "SunEC", "Signature", "EdDSA" },
            { "SunPCSC", "TerminalFactory", "PC/SC" }
    };

    public static void main(String[] args) throws Throwable {

        if (args.length == 4) {
            Helper.mainChild(args[0], args[1], args[2], args[3]);
            return;
        }

        if (args.length != 0) {
            throw new Exception("Unexpected number of arguments: " + args.length);
        }

        try {
            Helper.workspace = Files.createTempDirectory(null);
            Helper.testMainClass = AllServicesTest.class.getName();

            Helper.TestExecutor t = new Helper.TestExecutor();

            runExpecedTests();

            runNotExpecedTests();
        } finally {
            Helper.cleanupWorkspace();
        }

        System.out.println("TEST PASS - OK");
    }

    private static void runExpecedTests() throws Throwable {
        Helper.TestExecutor t = new Helper.TestExecutor();

        t.setFilter(SUCCESS_FILTER);

        for (String[] svc : TESTED_SERVICES) {
            t.addExpectedService(svc[0], svc[1], svc[2]);
        }

        t.execute();
    }

    private static void runNotExpecedTests() throws Throwable {
        Helper.TestExecutor t = new Helper.TestExecutor();

        t.setFilter(FAIL_FILTER);

        for (String[] svc : TESTED_SERVICES) {
            t.addNotExpectedService(svc[0], svc[1], svc[2]);
        }

        t.execute();
    }
}
