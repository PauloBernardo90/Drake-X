/**
 * Drake-X Frida Observation Template: PackageInstaller Observation
 *
 * PURPOSE: Observe sideloading / secondary APK installation attempts.
 */

Java.perform(function () {
    try {
        var PI = Java.use("android.content.pm.PackageInstaller");
        PI.createSession.implementation = function (params) {
            console.log("[Drake-X] PackageInstaller.createSession() called");
            console.log("[Drake-X]   Params: " + params);
            return this.createSession(params);
        };
        console.log("[Drake-X] PackageInstaller observation active");
    } catch (e) {
        console.log("[Drake-X] PackageInstaller hook failed: " + e);
    }
});
