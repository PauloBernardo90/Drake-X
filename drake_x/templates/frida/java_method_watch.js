/**
 * Drake-X Frida Observation Template: Java Method Watch
 *
 * PURPOSE: Observe calls to a specific Java method at runtime.
 * This is an OBSERVATION template — it does NOT modify behavior.
 *
 * USAGE:
 *   frida -U -l java_method_watch.js -f <package_name>
 *
 * Replace PLACEHOLDER values below with your actual targets.
 */

Java.perform(function () {
    // === CONFIGURE THESE ===
    var targetClass = "PLACEHOLDER_CLASS";  // e.g. "com.example.app.MainActivity"
    var targetMethod = "PLACEHOLDER_METHOD"; // e.g. "checkRoot"

    try {
        var clazz = Java.use(targetClass);
        clazz[targetMethod].overload().implementation = function () {
            console.log("[Drake-X] " + targetClass + "." + targetMethod + "() called");
            console.log("[Drake-X]   Arguments: " + JSON.stringify(arguments));
            var result = this[targetMethod].apply(this, arguments);
            console.log("[Drake-X]   Return: " + result);
            return result; // DO NOT modify — observation only
        };
        console.log("[Drake-X] Hooked " + targetClass + "." + targetMethod);
    } catch (e) {
        console.log("[Drake-X] Failed to hook: " + e);
    }
});
