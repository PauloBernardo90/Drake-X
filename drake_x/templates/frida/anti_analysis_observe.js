/**
 * Drake-X Frida Observation Template: Anti-Analysis Detection Observer
 *
 * PURPOSE: Observe root detection, emulator detection, debug detection,
 * and Frida detection checks WITHOUT modifying their behavior.
 */

Java.perform(function () {
    // Root detection — File.exists for su paths
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (path.indexOf("su") !== -1 || path.indexOf("magisk") !== -1 || path.indexOf("busybox") !== -1) {
                console.log("[Drake-X] [ROOT] File.exists() checked: " + path + " -> " + this.exists());
            }
            return this.exists();
        };
        console.log("[Drake-X] Hooked File.exists for root detection observation");
    } catch (e) { console.log("[Drake-X] File.exists hook failed: " + e); }

    // Debug detection
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () {
            var result = this.isDebuggerConnected();
            console.log("[Drake-X] [DEBUG] isDebuggerConnected() -> " + result);
            return result;
        };
        console.log("[Drake-X] Hooked Debug.isDebuggerConnected");
    } catch (e) { console.log("[Drake-X] Debug hook failed: " + e); }

    // Library loading (for native anti-analysis)
    try {
        var System = Java.use("java.lang.System");
        System.loadLibrary.overload("java.lang.String").implementation = function (lib) {
            console.log("[Drake-X] [NATIVE] System.loadLibrary('" + lib + "')");
            return this.loadLibrary(lib);
        };
        console.log("[Drake-X] Hooked System.loadLibrary");
    } catch (e) { console.log("[Drake-X] loadLibrary hook failed: " + e); }
});
