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
* @summary Test basic ProviderFilder behavior
* @modules java.base/sun.security.jca
*          java.base/sun.security.util
* @library /test/lib
* @compile Helper.java
* @run main/othervm/timeout=600 -enablesystemassertions BasicTest
*/

import java.nio.file.Files;
import java.util.List;

public class BasicTest {

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
            Helper.testMainClass = BasicTest.class.getName();

            runBasicFiltering();

            runBasicFilteringUnregistered();

        } finally {
            Helper.cleanupWorkspace();
        }

        System.out.println("TEST PASS - OK");
    }

    private static void runBasicFiltering() throws Throwable {
        Helper.TestExecutor t = new Helper.TestExecutor();

        t.setFilter(
                "SunJCE.Mac.HmacSHA512; SUN.MessageDigest.SHA-512  ;" +
                        "!*.*.*WeaK*;MyProvider.*.myStrongAlgorithm*; " +
                        "!NonExistentProvider");

        t.addExpectedService("SunJCE", "Mac", "HmacSHA512");
        t.addExpectedDynamicService("MyProvider", "MyStrongAlgorithm");
        t.addExpectedDynamicService("MyProvider", "MyStrongAlgorithm2");

        t.addNotExpectedService("SunJCE", "KeyGenerator", "HmacSHA3-512");
        t.addNotExpectedDynamicService("MyProvider", "MyWeakAlgorithm");

        t.execute();
    }

    private static void runBasicFilteringUnregistered() throws Throwable {
        Helper.TestExecutor t = new Helper.TestExecutor();

        t.setFilter(
                "R1_MyProvider.*.strong; !R1_MyProvider;" +
                        "!R2_MyProvider.*.weak; R2_MyProvider");

        t.addExpectedDynamicService("R1_MyProvider", "strong", List.of(), null);
        t.addExpectedDynamicService("R2_MyProvider", "Algo", List.of(), null);

        t.addNotExpectedDynamicService("R1_MyProvider", "Algo", List.of(), null);
        t.addNotExpectedDynamicService("R2_MyProvider", "weak", List.of(), null);

        t.execute();
    }
}