/*
 * @test
 * @bug 8315487
 * @summary Verifies that ProvidersFilter reflects dynamic changes in legacy Provider.put()
 *          registrations when aliases are added and removed (allowed → denied → allowed).
 * @modules java.base/sun.security.jca
 *          java.base/sun.security.util
 * @library /test/lib
 * @run main/othervm/timeout=300 -enablesystemassertions LegacyAliasTest
 */

import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.Map;

import jdk.test.lib.process.Proc;

public class LegacyAliasTest {

    private static final String SEC_FILTER_PROP = "jdk.security.providers.filter";
    private static final String FILTER = "!R1_MyProvider.*.Alias; R1_MyProvider.*.Algo; !*";
    private static final String PROVIDER_NAME = "R1_MyProvider";
    private static final String TYPE = "TestServiceType";
    private static final String ALGO = "Algo";
    private static final String ALIAS = "Alias";

    public static final class TestServiceSpi {
    }

    private static final class LegacyProvider extends Provider {
        LegacyProvider() {
            super(PROVIDER_NAME, "1.0", "legacy provider");
        }
    }

    private static void assertAllowed(String algorithm) throws Exception {
        if (!isAvailable(algorithm)) {
            throw new Exception("Expected allowed: " + TYPE + "." + algorithm);
        }
    }

    private static void assertDenied(String algorithm) throws Exception {
        if (isAvailable(algorithm)) {
            throw new Exception("Expected denied: " + TYPE + "." + algorithm);
        }
    }

    private static boolean isAvailable(String algorithm) {
        String filter = TYPE + "." + algorithm;

        Provider[] providers = Security.getProviders(filter);
        if (providers == null) {
            return false;
        }

        for (Provider p : providers) {
            if (p.getName().equals(PROVIDER_NAME)) {
                return true;
            }
        }
        return false;
    }

    public static void main(String[] args) throws Throwable {
        if (args.length == 0) {
            Proc p = Proc.create(ParseLegacyAliasTest.class.getName()).args("child");
            p.env("JDK_JAVA_OPTIONS", "-enablesystemassertions");
            p.secprop(SEC_FILTER_PROP, FILTER);
            p.inheritIO();
            p.prop("java.security.debug", "jca");
            p.debug("ParseLegacyAliasTest");
            p.start().waitFor(0);

            System.out.println("TEST PASS - OK");
            return;
        }

        Security.getProviders(); // force filter initialization

        runLegacy();
    }

    private static void runLegacy() throws Throwable {
        Provider provider = new LegacyProvider();
        Security.addProvider(provider);

        try {
            provider.put(TYPE + "." + ALGO, TestServiceSpi.class.getName());

            assertAllowed(ALGO);

            provider.put("Alg.Alias." + TYPE + "." + ALIAS, ALGO);

            assertDenied(ALGO);

            assertDenied(ALIAS);

            provider.remove("Alg.Alias." + TYPE + "." + ALIAS);

            assertAllowed(ALGO);

        } finally {
            Security.removeProvider(PROVIDER_NAME);
        }
    }
}