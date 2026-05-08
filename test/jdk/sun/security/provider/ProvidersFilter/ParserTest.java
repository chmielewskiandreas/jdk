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
 * @summary ProvidersFilter parser tests
 * @modules java.base/sun.security.jca
 *          java.base/sun.security.util
 * @library /test/lib
 * @compile Helper.java
 * @run main/othervm/timeout=600 -enablesystemassertions ParserTest
 */

import java.nio.file.Files;

public class ParserTest {

    private static final String FILTER_EXCEPTION_HDR = " * Filter string: ";
    private static final String FILTER_EXCEPTION_MORE = "(...)";
    private static final int FILTER_EXCEPTION_MAX_LINE = 80;

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
            Helper.testMainClass = ParserTest.class.getName();

            run(ParserTest::testWhitespacesOnlyInFilter);
            run(ParserTest::testWhitespacesOnlyInRule);
            run(ParserTest::testDenyOnly);
            run(ParserTest::testTooManyLevels);
            run(ParserTest::testMissingSecurityProvider);
            run(ParserTest::testDenyMissingSecurityProvider);
            run(ParserTest::testMissingServiceType);
            run(ParserTest::testMissingServiceType2);
            run(ParserTest::testMissingAlgorithm);

            run(ParserTest::testUnescapedSpaceInProvider);
            run(ParserTest::testUnescapedSpaceInServiceType);
            run(ParserTest::testUnescapedExclamationMark);
            run(ParserTest::testUnescapedColonInProvider);
            run(ParserTest::testUnescapedCommaInProvider);

            run(ParserTest::testFilterEndsInEscape);
            run(ParserTest::testProviderEndsInEscape);

            run(ParserTest::testParserExceptionLineMoreRight);
            run(ParserTest::testParserExceptionLineMoreLeft);
            run(ParserTest::testParserExceptionLineMoreBoth);

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

    private static void testWhitespacesOnlyInFilter(Helper.TestExecutor t)
            throws Throwable {
        t.setFilter("\t\t\t", Helper.TestExecutor.FilterPropertyType.SYSTEM);
        t.addExpectedFilterException("\t\t\t", 17);
    }

    private static void testWhitespacesOnlyInRule(Helper.TestExecutor t) {
        t.setFilter("*;    ;");
        t.addExpectedFilterException("*;    ;", 21);
    }

    private static void testDenyOnly(Helper.TestExecutor t) {
        t.setFilter("!");
        t.addExpectedFilterException("!", 15);
    }

    private static void testTooManyLevels(Helper.TestExecutor t) {
        t.setFilter("*.*.*.*");
        t.addExpectedFilterException("*.*.*.*", 20);
    }

    private static void testMissingSecurityProvider(Helper.TestExecutor t) {
        t.setFilter(".*.*");
        t.addExpectedFilterException(".*.*", 15);
    }

    private static void testDenyMissingSecurityProvider(Helper.TestExecutor t) {
        t.setFilter("!.*");
        t.addExpectedFilterException("!.*", 16);
    }

    private static void testMissingServiceType(Helper.TestExecutor t) {
        t.setFilter("*.");
        t.addExpectedFilterException("*.", 16);
    }

    private static void testMissingServiceType2(Helper.TestExecutor t) {
        t.setFilter("*..*");
        t.addExpectedFilterException("*..*", 17);
    }

    private static void testMissingAlgorithm(Helper.TestExecutor t) {
        t.setFilter("*.*.");
        t.addExpectedFilterException("*.*.", 18);
    }

    private static void testUnescapedSpaceInProvider(Helper.TestExecutor t) {
        t.setFilter("My Provider");
        t.addExpectedFilterException("My Provider", 18);
    }

    private static void testUnescapedSpaceInServiceType(Helper.TestExecutor t) {
        t.setFilter("MyProvider. MyService");
        t.addExpectedFilterException("MyProvider. MyService", 26);
    }

    private static void testUnescapedExclamationMark(Helper.TestExecutor t) {
        t.setFilter("My!Provider");
        t.addExpectedFilterException("My!Provider", 17);
    }

    private static void testUnescapedColonInProvider(Helper.TestExecutor t) {
        t.setFilter("My:Provider");
        t.addExpectedFilterException("My:Provider", 17);
    }

    private static void testUnescapedCommaInProvider(Helper.TestExecutor t) {
        t.setFilter("My,Provider");
        t.addExpectedFilterException("My,Provider", 17);
    }

    private static void testFilterEndsInEscape(Helper.TestExecutor t) {
        t.setFilter("\\");
        t.addExpectedFilterException("\\", 15);
    }

    private static void testProviderEndsInEscape(Helper.TestExecutor t) {
        t.setFilter("MyProvider\\");
        t.addExpectedFilterException("MyProvider\\", 25);
    }

    private static void testParserExceptionLineMoreRight(Helper.TestExecutor t) {
        t.setFilter("." + ";".repeat(FILTER_EXCEPTION_MAX_LINE + 10));
        t.addExpectedFilterException("." + ";".repeat(
                FILTER_EXCEPTION_MAX_LINE - FILTER_EXCEPTION_HDR.length() - 1 - FILTER_EXCEPTION_MORE.length() - 1)
                + " " + FILTER_EXCEPTION_MORE, 15);
    }

    private static void testParserExceptionLineMoreLeft(Helper.TestExecutor t) {
        t.setFilter("*".repeat(FILTER_EXCEPTION_MAX_LINE + 10) + "!");
        t.addExpectedFilterException(FILTER_EXCEPTION_MORE + " " + "*".repeat(
                FILTER_EXCEPTION_MAX_LINE - FILTER_EXCEPTION_HDR.length() - 1 - FILTER_EXCEPTION_MORE.length() - 1)
                + "!", 76);
    }

    private static void testParserExceptionLineMoreBoth(Helper.TestExecutor t) {
        t.setFilter("*".repeat(FILTER_EXCEPTION_MAX_LINE + 10) + "!" +
                "*".repeat(FILTER_EXCEPTION_MAX_LINE + 10));
        float halfWildcards = (FILTER_EXCEPTION_MAX_LINE -
                FILTER_EXCEPTION_HDR.length() - (FILTER_EXCEPTION_MORE.length() + 1) * 2 - 1) / 2.0f;
        int preWildcards = (int) halfWildcards;
        int postWildcards = (int) (halfWildcards + 0.5f);
        t.addExpectedFilterException(FILTER_EXCEPTION_MORE + " " + "*".repeat(
                preWildcards) + "!" + "*".repeat(postWildcards) + " " + FILTER_EXCEPTION_MORE, 45);
    }
}
