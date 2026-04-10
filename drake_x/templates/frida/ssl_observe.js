/**
 * Drake-X Frida Observation Template: SSL/TLS Certificate Observation
 *
 * PURPOSE: Observe certificate pinning and trust manager behavior.
 * This is an OBSERVATION template — it does NOT bypass pinning.
 */

Java.perform(function () {
    // Observe OkHttp CertificatePinner
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCerts) {
            console.log("[Drake-X] CertificatePinner.check() called");
            console.log("[Drake-X]   Hostname: " + hostname);
            console.log("[Drake-X]   Cert count: " + peerCerts.size());
            return this.check(hostname, peerCerts); // observe only
        };
        console.log("[Drake-X] Hooked CertificatePinner.check");
    } catch (e) {
        console.log("[Drake-X] CertificatePinner not found: " + e);
    }

    // Observe X509TrustManager
    try {
        var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        // Note: this is an interface; hook the implementing class if known
        console.log("[Drake-X] X509TrustManager class found — hook implementing class for details");
    } catch (e) {
        console.log("[Drake-X] X509TrustManager: " + e);
    }
});
