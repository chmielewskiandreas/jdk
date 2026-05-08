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

            t.setFilter(
                    "*.AlgorithmParameterGenerator.DiffieHellman; " +
                            "*.AlgorithmParameters.PBES2;" +
                            "*.CertStore.Collection; " +
                            "*.KeyAgreement.ECDH; " +
                            "*.KeyFactory.DiffieHellman; " +
                            "*.KeyGenerator.HmacSHA3-512; " +
                            "*.KeyManagerFactory.NewSunX509; " +
                            "*.KeyPairGenerator.DiffieHellman; " +
                            "*.KeyStore.PKCS12; " +
                            "*.Mac.HmacSHA512; " +
                            "*.MessageDigest.SHA-512; " +
                            "*.SaslClientFactory.EXTERNAL; " +
                            "*.SaslServerFactory.CRAM-MD5; " +
                            "*.SecretKeyFactory.PBEWithHmacSHA512/256AndAES_256; " +
                            "*.SecureRandom.SHA1PRNG; *.MessageDigest.SHA-1; " +
                            "*.Signature.EdDSA; " +
                            "*.SSLContext.TLSv1\\.3; " +
                            "*.TransformService." +
                            Transform.XPATH.replace(".", "\\.").replace(":", "\\:") + "; " +
                            "*.TrustManagerFactory.PKIX");

            t.addExpectedService("SunJCE", "AlgorithmParameterGenerator", "DiffieHellman");
            t.addExpectedService("SunJCE", "AlgorithmParameters", "PBES2");
            t.addExpectedService("SUN", "CertStore", "Collection");
            t.addExpectedService("SunEC", "KeyAgreement", "ECDH");
            t.addExpectedService("SunJCE", "KeyFactory", "DiffieHellman");
            t.addExpectedService("SunJCE", "KeyGenerator", "HmacSHA3-512");
            t.addExpectedService("SunJSSE", "KeyManagerFactory", "NewSunX509");
            t.addExpectedService("SunJCE", "KeyPairGenerator", "DiffieHellman");
            t.addExpectedService("SunJSSE", "KeyStore", "PKCS12");
            t.addExpectedService("SunJCE", "Mac", "HmacSHA512");
            t.addExpectedService("SUN", "MessageDigest", "SHA-512");
            t.addExpectedService("SunSASL", "SaslClientFactory", "EXTERNAL");
            t.addExpectedService("SunSASL", "SaslServerFactory", "CRAM-MD5");
            t.addExpectedService("SunJCE", "SecretKeyFactory", "PBEWithHmacSHA512/256AndAES_256");
            t.addExpectedService("SUN", "SecureRandom", "SHA1PRNG");
            t.addExpectedService("SunEC", "Signature", "EdDSA");
            t.addExpectedService("SunJSSE", "SSLContext", "TLSv1.3");
            t.addExpectedService("XMLDSig", "TransformService", Transform.XPATH);
            t.addExpectedService("SunJSSE", "TrustManagerFactory", "PKIX");

            t.addNotExpectedService("SUN", "AlgorithmParameterGenerator", "DSA");
            t.addNotExpectedService("SUN", "AlgorithmParameters", "DSA");
            t.addNotExpectedService("SUN", "CertificateFactory", "X.509");
            t.addNotExpectedService("SUN", "CertPathBuilder", "PKIX");
            t.addNotExpectedService("SUN", "CertPathValidator", "PKIX");
            t.addNotExpectedService("JdkLDAP", "CertStore", "LDAP");
            t.addNotExpectedService("SUN", "Configuration", "JavaLoginConfig");
            t.addNotExpectedService("SunJCE", "KEM", "DHKEM");
            t.addNotExpectedService("SunEC", "KeyAgreement", "X25519");
            t.addNotExpectedService("SUN", "KeyFactory", "DSA");
            t.addNotExpectedService("SunJCE", "KeyGenerator", "Blowfish");
            t.addNotExpectedService("XMLDSig", "KeyInfoFactory", "DOM");
            t.addNotExpectedService("SunJSSE", "KeyManagerFactory", "SunX509");
            t.addNotExpectedService("SUN", "KeyPairGenerator", "DSA");
            t.addNotExpectedService("SUN", "KeyStore", "JKS");
            t.addNotExpectedService("SunJCE", "Mac", "HmacSHA1");
            t.addNotExpectedService("SUN", "MessageDigest", "MD5");
            t.addNotExpectedService("SunSASL", "SaslClientFactory", "PLAIN");
            t.addNotExpectedService("SunSASL", "SaslServerFactory", "DIGEST-MD5");
            t.addNotExpectedService("SunJCE", "SecretKeyFactory", "DES");
            t.addNotExpectedService("SUN", "SecureRandom", "DRBG");
            t.addNotExpectedService("SUN", "Signature", "SHA1withDSA");
            t.addNotExpectedService("SunJSSE", "SSLContext", "TLSv1.2");
            t.addNotExpectedService("SunPCSC", "TerminalFactory", "PC/SC");
            t.addNotExpectedService("XMLDSig", "TransformService", Transform.ENVELOPED);
            t.addNotExpectedService("SunJSSE", "TrustManagerFactory", "SunX509");
            t.addNotExpectedService("XMLDSig", "XMLSignatureFactory", "DOM");

            t.execute();

        } finally {
            Helper.cleanupWorkspace();
        }

        System.out.println("TEST PASS - OK");
    }
}
