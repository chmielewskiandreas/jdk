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

import java.io.*;
import java.lang.reflect.Method;
import java.nio.CharBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.Provider.Service;
import java.security.cert.*;
import java.util.*;
import javax.crypto.*;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.Configuration;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;
import javax.smartcardio.TerminalFactory;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;

import sun.security.jca.GetInstance;
import sun.security.util.KnownOIDs;

import jdk.test.lib.process.Proc;
import jdk.test.lib.util.FileUtils;

public final class Helper {

    private static final boolean DEBUG = false;

    private static final String SEC_FILTER_PROP = "jdk.security.providers.filter";

    private static final String FILTER_EXCEPTION_HDR = " * Filter string: ";

    private static final String FILTER_EXCEPTION_MORE = "(...)";

    private static final int FILTER_EXCEPTION_MAX_LINE = 80;

    public static Path workspace;

    private static final String TEST_SERVICE_TYPE = "TestServiceType";

    public static String testMainClass;

    /*
     * Class used as a service SPI for services added by security providers
     * installed dynamically.
     */
    public static final class TestServiceSpi {
    }

    @FunctionalInterface
    private interface ServiceChecker {
        boolean check(ServiceData svcData);
    }

    @FunctionalInterface
    private interface ServiceOp {
        void doOp() throws Throwable;
    }

    private static boolean serviceCheck(ServiceOp serviceOp) {
        try {
            serviceOp.doOp();
            return true;
        } catch (Throwable t) {
            if (DEBUG) {
                t.printStackTrace();
            }
            return false;
        }
    }

    private static final Map<String, ServiceChecker> serviceCheckers = new HashMap<>();

    static {
        serviceCheckers.put("AlgorithmParameterGenerator",
                (ServiceData d) -> serviceCheck(() -> AlgorithmParameterGenerator
                        .getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("AlgorithmParameters",
                (ServiceData d) -> serviceCheck(() -> AlgorithmParameters
                        .getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("CertificateFactory",
                (ServiceData d) -> serviceCheck(() -> CertificateFactory.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("CertPathBuilder", (ServiceData d) -> serviceCheck(
                () -> CertPathBuilder.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("CertPathValidator",
                (ServiceData d) -> serviceCheck(() -> CertPathValidator.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("CertStore", (ServiceData d) -> serviceCheck(
                () -> {
                    if (d.svcAlgo.equals("Collection")) {
                        CertStore.getInstance(d.svcAlgo,
                                new CollectionCertStoreParameters(),
                                d.provider);
                    } else {
                        try {
                            CertStore.getInstance(d.svcAlgo,
                                    new LDAPCertStoreParameters(),
                                    d.provider);
                        } catch (InvalidAlgorithmParameterException ignored) {
                            // The InitialDirContext could not be created as there is not a server in
                            // localhost but this is an indication that the service is available:
                            // NoSuchAlgorithmException would have been thrown otherwise.
                        }
                    }
                }));
        serviceCheckers.put("Cipher", (ServiceData d) -> serviceCheck(
                () -> Cipher.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("Configuration", (ServiceData d) -> serviceCheck(() -> Configuration
                .getInstance(d.svcAlgo, null, d.provider)));
        serviceCheckers.put("KDF", (ServiceData d) -> serviceCheck(
                () -> KDF.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("KEM", (ServiceData d) -> serviceCheck(
                () -> KEM.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("KeyAgreement", (ServiceData d) -> serviceCheck(
                () -> KeyAgreement.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("KeyFactory", (ServiceData d) -> serviceCheck(
                () -> KeyFactory.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("KeyGenerator", (ServiceData d) -> serviceCheck(
                () -> KeyGenerator.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("KeyInfoFactory", (ServiceData d) -> serviceCheck(() -> KeyInfoFactory
                .getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("KeyManagerFactory",
                (ServiceData d) -> serviceCheck(() -> KeyManagerFactory.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("KeyPairGenerator", (ServiceData d) -> serviceCheck(
                () -> KeyPairGenerator.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("KeyStore", (ServiceData d) -> serviceCheck(
                () -> KeyStore.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("Mac", (ServiceData d) -> serviceCheck(
                () -> Mac.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("MessageDigest", (ServiceData d) -> serviceCheck(
                () -> MessageDigest.getInstance(d.svcAlgo, d.provider)));
        final CallbackHandler saslCallbackHandler = callbacks -> {
            for (Callback cb : callbacks) {
                if (cb instanceof PasswordCallback) {
                    ((PasswordCallback) cb).setPassword(
                            "password".toCharArray());
                } else if (cb instanceof NameCallback) {
                    ((NameCallback) cb).setName("username");
                }
            }
        };
        serviceCheckers.put("SaslClientFactory", (ServiceData d) -> serviceCheck(() -> {
            SaslClient c = Sasl.createSaslClient(
                    new String[] { d.svcAlgo }, "username",
                    "ldap", "server1", Collections.emptyMap(),
                    saslCallbackHandler);
            if (c == null) {
                throw new NoSuchAlgorithmException();
            }
        }));
        serviceCheckers.put("SaslServerFactory", (ServiceData d) -> serviceCheck(() -> {
            SaslServer s = Sasl.createSaslServer(
                    d.svcAlgo, "ldap", "server1",
                    Collections.emptyMap(), saslCallbackHandler);
            if (s == null) {
                throw new NoSuchAlgorithmException();
            }
        }));
        serviceCheckers.put("SecretKeyFactory", (ServiceData d) -> serviceCheck(
                () -> SecretKeyFactory.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("SecureRandom", (ServiceData d) -> serviceCheck(
                () -> SecureRandom.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("Signature", (ServiceData d) -> serviceCheck(
                () -> Signature.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("SSLContext", (ServiceData d) -> serviceCheck(
                () -> SSLContext.getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("TerminalFactory", (ServiceData d) -> serviceCheck(() -> TerminalFactory
                .getInstance(d.svcAlgo, null, d.provider)));
        serviceCheckers.put("TransformService", (ServiceData d) -> serviceCheck(() -> TransformService
                .getInstance(d.svcAlgo, "DOM", d.provider)));
        serviceCheckers.put("TrustManagerFactory", (ServiceData d) -> serviceCheck(() -> TrustManagerFactory
                .getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put("XMLSignatureFactory", (ServiceData d) -> serviceCheck(() -> XMLSignatureFactory
                .getInstance(d.svcAlgo, d.provider)));
        serviceCheckers.put(TEST_SERVICE_TYPE,
                (ServiceData d) -> serviceCheck(() -> GetInstance.getInstance(
                        TEST_SERVICE_TYPE, TestServiceSpi.class, d.svcAlgo,
                        d.provider)));
    }

    private static sealed class ServiceData implements Serializable
            permits DynamicServiceData {
        @Serial
        private static final long serialVersionUID = -351065619007499507L;
        protected final String provider;
        private final String svcType;
        protected final String svcAlgo;

        private ServiceData(String provider, String svcType, String svcAlgo) {
            this.provider = provider;
            this.svcType = svcType;
            this.svcAlgo = svcAlgo;
        }

        @Override
        public String toString() {
            return provider + " / " + svcType + " / " + svcAlgo;
        }
    }

    private static final class DynamicServiceData extends ServiceData {
        @Serial
        private static final long serialVersionUID = 6156428473910912042L;
        final List<String> aliases;
        final Boolean legacy;

        DynamicServiceData(String provider, String svcType, String svcAlgo, List<String> aliases,
                Boolean legacy) {
            super(provider, svcType, svcAlgo);
            if (aliases != null) {
                this.aliases = aliases;
            } else {
                this.aliases = List.of();
            }
            this.legacy = legacy;
        }

        @Override
        public String toString() {
            return super.toString() + (aliases != null ? " / aliases: " + aliases : "") +
                    " / legacy: " + (legacy == null ? "unregistered" : legacy);
        }
    }

    private record ExpectedExceptionData(String exceptionClass, String filterLine,
            String underliningLine) implements Serializable {
    }

    public static final class TestExecutor {
        public enum FilterPropertyType {
            SYSTEM, SECURITY
        }

        @FunctionalInterface
        private interface AssertionDataLoader {
            void apply(TestExecutor testExecutor, String provider, String svcType, String svcAlgo)
                    throws Throwable;
        }

        private final List<DynamicServiceData> dynamicServices = new ArrayList<>();
        private final List<ServiceData> expected = new ArrayList<>();
        private final List<ServiceData> notExpected = new ArrayList<>();
        private ExpectedExceptionData expectedException = null;
        private String filterStr;
        private FilterPropertyType propertyType;

        public void setFilter(String filterStr) {
            setFilter(filterStr, FilterPropertyType.SECURITY);
        }

        public void setFilter(String filterStr, FilterPropertyType propertyType) {
            if (propertyType == FilterPropertyType.SECURITY) {
                StringBuilder sb = new StringBuilder(filterStr.length());
                CharBuffer cb = CharBuffer.wrap(filterStr);
                while (cb.hasRemaining()) {
                    char c = cb.get();
                    if (c == '\\') {
                        sb.append('\\');
                    }
                    if (Character.UnicodeBlock.of(c) == Character.UnicodeBlock.BASIC_LATIN) {
                        sb.append(c);
                    } else {
                        sb.append("\\u%04x".formatted((int) c));
                    }
                }
                this.filterStr = sb.toString();
            } else {
                this.filterStr = filterStr;
            }
            this.propertyType = propertyType;
            if (DEBUG) {
                System.out.println("Filter: " + filterStr);
            }
        }

        private void addDynamicService(String provider, String svcAlgo, List<String> aliases,
                Boolean legacy, AssertionDataLoader assertionDataLoader) throws Throwable {
            DynamicServiceData svcData = new DynamicServiceData(provider,
                    TEST_SERVICE_TYPE, svcAlgo, aliases, legacy);
            dynamicServices.add(svcData);
            // Sanity check: install the dynamic security provider without a filter.
            DynamicProvider dynamicProvider = DynamicProvider.install(svcData);
            dynamicProvider.putAlgo(svcData);
            assertionDataLoader.apply(this, provider, TEST_SERVICE_TYPE, svcAlgo);
        }

        public void addExpectedDynamicService(String provider, String svcAlgo) throws Throwable {
            addExpectedDynamicService(provider, svcAlgo, null, false);
        }

        public void addExpectedDynamicService(String provider, String svcAlgo,
                List<String> aliases, Boolean legacy) throws Throwable {
            addDynamicService(provider, svcAlgo, aliases, legacy, TestExecutor::addExpectedService);
        }

        public void addExpectedService(String provider, String svcType, String svcAlgo)
                throws Throwable {
            expected.add(checkSvcAvailable(new ServiceData(provider, svcType, svcAlgo)));
        }

        public void addNotExpectedDynamicService(String provider, String svcAlgo) throws Throwable {
            addNotExpectedDynamicService(provider, svcAlgo, null, false);
        }

        public void addNotExpectedDynamicService(String provider, String svcAlgo,
                List<String> aliases, Boolean legacy) throws Throwable {
            addDynamicService(provider, svcAlgo, aliases, legacy, TestExecutor::addNotExpectedService);
        }

        public void addNotExpectedService(String provider, String svcType, String svcAlgo)
                throws Throwable {
            notExpected.add(checkSvcAvailable(new ServiceData(provider, svcType, svcAlgo)));
        }

        /*
         * Sanity check: services must be available without a filter.
         */
        private ServiceData checkSvcAvailable(ServiceData svcData) throws Throwable {
            if (!serviceCheckers.get(svcData.svcType).check(svcData)) {
                throw new Exception("The service " + svcData + " is not available without a filter.");
            }
            return svcData;
        }

        void addExpectedFilterException(String filterLine, int underliningSpaces) {
            String underliningLine = " ".repeat(underliningSpaces) + "---^---";
            underliningLine = underliningLine.substring(0, Math.min(
                    underliningLine.length(), FILTER_EXCEPTION_MAX_LINE));
            expectedException = new ExpectedExceptionData("sun.security.jca" +
                    ".ProvidersFilter$Filter$ParserException",
                    FILTER_EXCEPTION_HDR + filterLine, underliningLine);
        }

        public void execute() throws Throwable {
            String testClassName = (Helper.testMainClass != null)
                    ? Helper.testMainClass
                    : getClass().getEnclosingClass().getName();
            Path dynamicServicesPath = getSvcDataFile(dynamicServices,
                    "Dynamically installed services");
            Path expectedPath = getSvcDataFile(expected, "Expected");
            Path notExpectedPath = getSvcDataFile(notExpected, "Not expected");
            Path expectedExceptionPath = serializeObject(expectedException);
            if (DEBUG) {
                System.out.println("=========================================");
            }
            Proc p = Proc.create(testClassName).args(
                    dynamicServicesPath.toString(), expectedPath.toString(),
                    notExpectedPath.toString(),
                    (expectedExceptionPath == null ? "" : expectedExceptionPath.toString()));
            p.env("JDK_JAVA_OPTIONS", "-enablesystemassertions");
            if (propertyType == FilterPropertyType.SECURITY) {
                p.secprop(SEC_FILTER_PROP, filterStr);
            } else {
                p.prop(SEC_FILTER_PROP, filterStr);
            }
            if (DEBUG) {
                p.inheritIO();
                p.prop("java.security.debug", "jca");
                p.debug(testClassName);
            } else {
                p.nodump();
            }
            p.start().waitFor(0);
            for (ServiceData svcData : dynamicServices) {
                Security.removeProvider(svcData.provider);
            }
        }
    }

    private static Path getSvcDataFile(Object svcData, String title) throws Throwable {
        assert svcData != null : "Service data cannot be null.";
        Path svcDataFilePath = serializeObject(svcData);
        showFileContent(svcDataFilePath, title);
        return svcDataFilePath;
    }

    private static List<ServiceData> getSvcData(Path svcDataPath) throws Throwable {
        return (List<ServiceData>) deserializeObject(svcDataPath);
    }

    private static Path serializeObject(Object obj) throws Throwable {
        if (obj == null) {
            return null;
        }
        Path objFilePath = Files.createTempFile(workspace, null, null);
        try (FileOutputStream fos = new FileOutputStream(objFilePath.toFile())) {
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(obj);
            oos.flush();
        }
        return objFilePath;
    }

    private static Object deserializeObject(Path filePath) throws Throwable {
        try (FileInputStream fos = new FileInputStream(filePath.toFile())) {
            ObjectInputStream ois = new ObjectInputStream(fos);
            return ois.readObject();
        }
    }

    private static void showFileContent(Path filePath, String title) throws Throwable {
        if (DEBUG) {
            System.out.println("-----------------------------------------");
            System.out.println(title + " assertion data (" + filePath + "):");
            for (ServiceData svcData : getSvcData(filePath)) {
                System.out.println(svcData);
            }
        }
    }

    public static void mainChild(String dynamicServicesPath, String expectedPropsPath,
            String notExpectedPropsPath, String expectedExceptionPath) throws Throwable {

        if (!expectedExceptionPath.isEmpty()) {
            ExpectedExceptionData expectedException = (ExpectedExceptionData) deserializeObject(
                    Paths.get(expectedExceptionPath));
            try {
                // Force the filter to be loaded.
                Security.getProviders();
            } catch (Throwable t) {
                if (DEBUG) {
                    System.out.println("Filter line expected: " + expectedException.filterLine);
                    System.out.println("Filter underlining line expected: " +
                            expectedException.underliningLine);
                    t.printStackTrace();
                }
                Throwable ultimateCause = t.getCause();
                while (ultimateCause.getCause() != null) {
                    ultimateCause = ultimateCause.getCause();
                }
                if (ultimateCause.getClass().getName().equals(expectedException.exceptionClass)) {
                    String[] lines = ultimateCause.getMessage().split("\\R");
                    for (int i = 0; i < lines.length; i++) {
                        if (lines[i].startsWith(FILTER_EXCEPTION_HDR)) {
                            if (lines[i].equals(expectedException.filterLine) &&
                                    i < lines.length - 1 && lines[i + 1].equals(
                                            expectedException.underliningLine)) {
                                return;
                            }
                            break;
                        }
                    }
                }
            }
            throw new Exception("Expected filter exception could not be verified.");
        }
        installDynamicServices(dynamicServicesPath);
        if (DEBUG) {
            System.out.println("Security Providers installed:");
            for (Provider provider : Security.getProviders()) {
                System.out.println("Provider: " + provider);
            }
        }
        perSvcDataDo(expectedPropsPath,
                (ServiceData data, boolean available) -> {
                    if (!available) {
                        throw new Exception("The service '" + data + "' is not " +
                                "available when it was expected.");
                    }
                });
        perSvcDataDo(notExpectedPropsPath,
                (ServiceData data, boolean available) -> {
                    if (available) {
                        throw new Exception("The service '" + data + "' is " +
                                "available when it was not expected.");
                    }
                });
    }

    private interface SvcDataConsumer {
        void consume(ServiceData data, boolean available) throws Throwable;
    }

    private static void perSvcDataDo(String svcDataPath, SvcDataConsumer svcDataDo)
            throws Throwable {
        for (ServiceData svcData : getSvcData(Paths.get(svcDataPath))) {
            Provider p = getProviderByName(svcData.provider);
            ServiceChecker checker = serviceCheckers.get(svcData.svcType);
            boolean availableInCryptoCheckers = checker.check(svcData);
            svcDataDo.consume(svcData, availableInCryptoCheckers);
        }
    }

    private static Provider getProviderByName(String providerName) {
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            if (p.getName().equals(providerName)) {
                return p;
            }
        }
        return null;
    }

    private static abstract sealed class DynamicProvider extends Provider
            permits DynamicProviderCurrent, DynamicProviderLegacy, DynamicProviderUnregistered {
        @Serial
        private static final long serialVersionUID = 6088341396620902983L;

        static DynamicProvider install(DynamicServiceData svcData)
                throws Throwable {
            DynamicProvider dynamicProvider;
            if (Security.getProvider(svcData.provider) instanceof DynamicProvider dP) {
                dynamicProvider = dP;
            } else {
                if (svcData.legacy == null) {
                    dynamicProvider = new DynamicProviderUnregistered(svcData);
                } else if (svcData.legacy) {
                    dynamicProvider = new DynamicProviderLegacy(svcData);
                } else {
                    dynamicProvider = new DynamicProviderCurrent(svcData);
                }
                if (Security.addProvider(dynamicProvider) == -1) {
                    throw new Exception("Could not install dynamic provider.");
                }
            }
            return dynamicProvider;
        }

        DynamicProvider(ServiceData svcData) {
            super(svcData.provider, "", svcData.toString());
        }

        abstract void putAlgo(DynamicServiceData svcData);
    }

    private static final class DynamicProviderCurrent extends DynamicProvider {
        @Serial
        private static final long serialVersionUID = 7754296009615868997L;

        DynamicProviderCurrent(DynamicServiceData svcData) {
            super(svcData);
        }

        @Override
        void putAlgo(DynamicServiceData svcData) {
            putService(new Service(this, TEST_SERVICE_TYPE, svcData.svcAlgo,
                    TestServiceSpi.class.getName(), svcData.aliases, null));
        }
    }

    private static final class DynamicProviderLegacy extends DynamicProvider {
        @Serial
        private static final long serialVersionUID = 1859892951118353404L;

        DynamicProviderLegacy(DynamicServiceData svcData) {
            super(svcData);
        }

        @Override
        void putAlgo(DynamicServiceData svcData) {
            put(TEST_SERVICE_TYPE + "." + svcData.svcAlgo,
                    TestServiceSpi.class.getName());
            for (String alias : svcData.aliases) {
                put("Alg.Alias." + TEST_SERVICE_TYPE + "." + alias,
                        svcData.svcAlgo);
            }
        }
    }

    private static final class DynamicProviderUnregistered extends DynamicProvider {
        @Serial
        private static final long serialVersionUID = 4421847184357342760L;
        private final Map<String, Service> services = new HashMap<>();

        DynamicProviderUnregistered(DynamicServiceData svcData) {
            super(svcData);
        }

        @Override
        void putAlgo(DynamicServiceData svcData) {
            Provider.Service s = new Service(this, TEST_SERVICE_TYPE,
                    svcData.svcAlgo, TestServiceSpi.class.getName(), svcData.aliases, null);
            services.put(s.getType() + "." + s.getAlgorithm(), s);
            for (String alias : svcData.aliases) {
                services.put(s.getType() + "." + alias, s);
            }
        }

        @Override
        public Provider.Service getService(String type, String algorithm) {
            return services.get(type + "." + algorithm);
        }

        @Override
        public Set<Provider.Service> getServices() {
            return new HashSet<>(services.values());
        }
    }

    private static void installDynamicServices(String svcDataPath) throws Throwable {
        for (ServiceData svcDataObj : getSvcData(Paths.get(svcDataPath))) {
            DynamicServiceData svcData = (DynamicServiceData) svcDataObj;
            DynamicProvider dynamicProvider = DynamicProvider.install(svcData);
            dynamicProvider.putAlgo(svcData);
        }
    }

    public static void cleanupWorkspace() throws Throwable {
        if (workspace != null) {
            FileUtils.deleteFileTreeWithRetry(workspace);
        }
    }
}