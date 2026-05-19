/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
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
 * @summary Verify JavaSecurityProviderAccess API is accessible
 * @modules java.base/jdk.internal.access
 * @run main/othervm
 *      --add-exports=java.base/jdk.internal.access=ALL-UNNAMED
 *      JavaSecurityProviderAccessTest
 */

import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.Set;

import jdk.internal.access.JavaSecurityProviderAccess;
import jdk.internal.access.SharedSecrets;

public class JavaSecurityProviderAccessTest {

    public static void main(String[] args) {
        JavaSecurityProviderAccess a = SharedSecrets.getJavaSecurityProviderAccess();
        if (a == null) {
            throw new AssertionError(
                    "JavaSecurityProviderAccess not accessible");
        }
        Provider p = Security.getProvider("SUN");
        if (p == null) {
            throw new AssertionError("SUN provider not found");
        }

        Provider.Service svc = p.getService("MessageDigest", "SHA-256");
        if (svc == null) {
            throw new AssertionError(
                    "Expected MessageDigest.SHA-256 service");
        }

        List<String> aliases = a.getAliases(svc);
        Set<Provider.Service> notAllowed = a.getNotAllowedServices(p);
        boolean allowed = a.isServiceAllowed(svc);
    }
}