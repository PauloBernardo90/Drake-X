/**
 * Drake-X Frida Observation Template: WebView URL Loading
 *
 * PURPOSE: Observe URLs loaded into WebView instances.
 */

Java.perform(function () {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("[Drake-X] WebView.loadUrl('" + url + "')");
        return this.loadUrl(url);
    };
    WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, headers) {
        console.log("[Drake-X] WebView.loadUrl('" + url + "', headers)");
        return this.loadUrl(url, headers);
    };
    console.log("[Drake-X] WebView observation active");
});
