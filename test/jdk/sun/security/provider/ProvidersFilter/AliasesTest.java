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
 * @summary Test ProvidersFilter alias handling
 * @modules java.base/sun.security.jca
 *          java.base/sun.security.util
 * @library /test/lib
 * @compile Helper.java
 * @run main/othervm/timeout=600 -enablesystemassertions AliasesTest
 */

import java.nio.file.Files;
import java.util.List;

public class AliasesTest {

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
            Helper.testMainClass = AliasesTest.class.getName();

            runAliases(false); // current provider
            runAliases(true); // legacy provider
            runAliases(null); // unregistered provider

        } finally {
            Helper.cleanupWorkspace();
        }

        System.out.println("TEST PASS - OK");
    }

    private static void runAliases(Boolean legacy) throws Throwable {
        Helper.TestExecutor t = new Helper.TestExecutor();

        aliasesCommon(t, legacy);

        t.execute();
    }

    private static void aliasesCommon(Helper.TestExecutor t, Boolean legacy) throws Throwable {
        t.setFilter(
                "R1_MyProvider.*.Alias; !R1_MyProvider.*.Algo; " +
                        "!R2_MyProvider.*.Alias; R2_MyProvider.*.Algo;" +
                        "R3_MyProvider.*.Algo; !R3_MyProvider.*.Alias;" +
                        "!R4_MyProvider.*.Algo; R4_MyProvider.*.Alias;" +
                        "R5_MyProvider.*.ALIAS1; !R5_MyProvider.*.ALIAS2");

        t.addExpectedDynamicService("R1_MyProvider", "Algo", List.of("Alias"), legacy);
        t.addExpectedDynamicService("R3_MyProvider", "Algo", List.of("Alias"), legacy);
        t.addExpectedDynamicService("R5_MyProvider", "Algo", List.of("Alias1", "Alias2"), legacy);

        t.addNotExpectedDynamicService("R2_MyProvider", "Algo", List.of("Alias"), legacy);
        t.addNotExpectedDynamicService("R4_MyProvider", "Algo", List.of("Alias"), legacy);
    }
}
