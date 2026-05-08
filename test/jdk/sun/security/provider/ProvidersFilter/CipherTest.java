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
 * @summary Test ProvidersFilter Cipher behavior
 * @modules java.base/sun.security.jca
 *          java.base/sun.security.util
 * @library /test/lib
 * @compile Helper.java
 * @run main/othervm/timeout=600 -enablesystemassertions CipherTest
 */

import java.nio.file.Files;
import sun.security.util.KnownOIDs;

public class CipherTest {

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
            Helper.testMainClass = CipherTest.class.getName();

            Helper.TestExecutor t = new Helper.TestExecutor();

            t.setFilter(
                    "!*.Cipher.AES; " +
                            "*.Cipher.AES/CBC/PKCS5Padding; " +
                            "*.Cipher." + KnownOIDs.AES.value().replace(".", "\\.") + "/OFB/NoPadding; " +
                            "*.Cipher.AES_128/CBC/*; " +
                            "*.Cipher.PBEWithHmacSHA512/256AndAES_128/CBC/PKCS5Padding;");

            t.addExpectedService("SunJCE", "Cipher", "AES/CBC/PKCS5Padding");
            t.addExpectedService("SunJCE", "Cipher", "AES/OFB/NoPadding");
            t.addExpectedService("SunJCE", "Cipher", "AES_128/CBC/NoPadding");
            t.addExpectedService("SunJCE", "Cipher", KnownOIDs.AES.value() + "/CBC/PKCS5Padding");
            t.addExpectedService("SunJCE", "Cipher", KnownOIDs.AES.value() + "/OFB/NoPadding");
            t.addExpectedService("SunJCE", "Cipher", KnownOIDs.AES_128$CBC$NoPadding.value());
            t.addExpectedService("SunJCE", "Cipher", "PBEWithHmacSHA512/256AndAES_128/CBC/PKCS5Padding");

            t.addNotExpectedService("SunJCE", "Cipher", "AES");
            t.addNotExpectedService("SunJCE", "Cipher", KnownOIDs.AES.value());
            t.addNotExpectedService("SunJCE", "Cipher", "AES/CBC/NoPadding");
            t.addNotExpectedService("SunJCE", "Cipher", "PBEWithHmacSHA512/256AndAES_128");

            t.execute();

        } finally {
            Helper.cleanupWorkspace();
        }

        System.out.println("TEST PASS - OK");
    }
}