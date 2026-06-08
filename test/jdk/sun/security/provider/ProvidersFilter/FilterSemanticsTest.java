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
 * @summary ProvidersFilter semantics tests (escaping, wildcard, precedence)
 * @modules java.base/sun.security.jca
 *          java.base/sun.security.util
 * @library /test/lib
 * @compile Helper.java
 * @run main/othervm/timeout=600 -enablesystemassertions FilterSemanticsTest
 */

import java.nio.file.Files;
import java.util.List;

public class FilterSemanticsTest {

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
            Helper.testMainClass = FilterSemanticsTest.class.getName();

            run(FilterSemanticsTest::testCharsEscaping);
            run(FilterSemanticsTest::testWildcardGreediness);
            run(FilterSemanticsTest::testLeftPrecedence);

        } finally {
            Helper.cleanupWorkspace();
        }

        System.out.println("TEST PASS - OK");
    }

    private static void run(TestCase tc) throws Throwable {
        Helper.TestExecutor t = new Helper.TestExecutor();
        tc.apply(t);
        t.execute();
    }

    @FunctionalInterface
    private interface TestCase {
        void apply(Helper.TestExecutor t) throws Throwable;
    }

    private static void testCharsEscaping(Helper.TestExecutor t) throws Throwable {
        t.setFilter(
                "R1_\\M\\!\\ \\.Pr\\*\\\\/\\;der \t; " +
                        "R2_My\\\\E\\.\\\\QProvider;" +
                        "\\!R3_M\\:Pr\\\tvi\\,de\u2014r.*;");

        t.addExpectedDynamicService("R1_M! .Pr*\\/;der", "Algo");
        t.addExpectedDynamicService("R2_My\\E.\\QProvider", "Algo");
        t.addExpectedDynamicService("!R3_M:Pr\tvi,de\u2014r", "Algo");

        t.addNotExpectedDynamicService("R1_\\M! .Pr*\\/;der", "Algo");
        t.addNotExpectedDynamicService("R1_M! .Pro\\/;der", "Algo");
        t.addNotExpectedDynamicService("R1_M! .Pr*/;der", "Algo");
        t.addNotExpectedDynamicService("R1_M! .Pr*\\/", "Algo");
        t.addNotExpectedDynamicService("R1_M! .Pr*\\/\\", "Algo");
        t.addNotExpectedDynamicService("R2_MyXProvider", "Algo");
    }

    private static void testWildcardGreediness(Helper.TestExecutor t) throws Throwable {
        t.setFilter(
                "R1_MyProvider*; R2_MyProviderA**B**C; " +
                        "R3_MyProvider*ABC");

        t.addExpectedDynamicService("R1_MyProvider", "Algo");
        t.addExpectedDynamicService("R1_MyProviderX", "Algo");
        t.addExpectedDynamicService("R1_MyProviderXX", "Algo");

        t.addExpectedDynamicService("R2_MyProviderABC", "Algo");
        t.addExpectedDynamicService("R2_MyProviderABCDC", "Algo");
        t.addExpectedDynamicService("R2_MyProviderABCCCC", "Algo");

        t.addExpectedDynamicService("R3_MyProviderABC", "Algo");
        t.addExpectedDynamicService("R3_MyProviderABCABC", "Algo");

        t.addNotExpectedDynamicService("R2_MyProviderA", "Algo");
    }

    private static void testLeftPrecedence(Helper.TestExecutor t) throws Throwable {
        t.setFilter(
                "R1_MyProvider; !R1_MyProvider; !R2_MyProvider; " +
                        "R2_MyProvider; !R3_*; R3_MyProvider; !R4_*.*.AES; " +
                        "R4_*.*.RSA");

        t.addExpectedDynamicService("R1_MyProvider", "Algo");
        t.addExpectedDynamicService("R4_MyProvider", "RSA");

        t.addNotExpectedDynamicService("R2_MyProvider", "Algo");
        t.addNotExpectedDynamicService("R3_MyProvider", "Algo");
        t.addNotExpectedDynamicService("R4_MyProvider", "AES");
        t.addNotExpectedDynamicService("R4_MyProvider", "*");
    }
}