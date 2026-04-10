/**
 * Drake-X Frida Observation Template: JNI/Native Library Loading
 *
 * PURPOSE: Observe which native libraries are loaded and when.
 */

Java.perform(function () {
    var System = Java.use("java.lang.System");

    System.loadLibrary.overload("java.lang.String").implementation = function (lib) {
        console.log("[Drake-X] System.loadLibrary('" + lib + "')");
        console.log("[Drake-X]   Stack: " + Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()));
        return this.loadLibrary(lib);
    };

    System.load.overload("java.lang.String").implementation = function (path) {
        console.log("[Drake-X] System.load('" + path + "')");
        return this.load(path);
    };

    console.log("[Drake-X] JNI load observation active");
});
