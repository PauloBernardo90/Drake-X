// Drake-X Ghidra Headless Export Script
//
// Exports structured native-analysis data as JSON for consumption by
// the Drake-X APK analysis pipeline. Designed for ELF shared libraries
// (.so) commonly found in Android APKs.
//
// Usage (via analyzeHeadless):
//   analyzeHeadless <project_dir> <project_name> \
//     -import <binary> -overwrite \
//     -postScript DrakeXExportNativeJson.java <output.json>
//
// Output: a JSON file with functions, strings, imports, exports,
// xrefs, and metadata.
//
// @category Drake-X

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import java.io.FileWriter;
import java.util.*;

public class DrakeXExportNativeJson extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath = args.length > 0 ? args[0] : "/tmp/drake_ghidra_export.json";

        JsonObject root = new JsonObject();

        // Metadata
        JsonObject meta = new JsonObject();
        meta.addProperty("program_name", currentProgram.getName());
        meta.addProperty("language", currentProgram.getLanguageID().toString());
        meta.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        meta.addProperty("image_base", currentProgram.getImageBase().toString());
        meta.addProperty("executable_format", currentProgram.getExecutableFormat());
        root.add("metadata", meta);

        // Functions
        JsonArray functions = new JsonArray();
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        int funcCount = 0;
        while (funcIter.hasNext() && funcCount < 5000) {
            Function func = funcIter.next();
            JsonObject fo = new JsonObject();
            fo.addProperty("name", func.getName());
            fo.addProperty("address", func.getEntryPoint().toString());
            fo.addProperty("signature", func.getPrototypeString(false, false));
            fo.addProperty("is_external", func.isExternal());
            fo.addProperty("is_thunk", func.isThunk());
            fo.addProperty("body_size", func.getBody().getNumAddresses());

            // Callers
            JsonArray callers = new JsonArray();
            for (Function caller : func.getCallingFunctions(monitor)) {
                callers.add(caller.getName());
            }
            fo.add("callers", callers);

            // Callees
            JsonArray callees = new JsonArray();
            for (Function callee : func.getCalledFunctions(monitor)) {
                callees.add(callee.getName());
            }
            fo.add("callees", callees);

            functions.add(fo);
            funcCount++;
        }
        root.add("functions", functions);
        root.addProperty("function_count", funcCount);

        // Strings
        JsonArray strings = new JsonArray();
        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        int stringCount = 0;
        while (dataIter.hasNext() && stringCount < 2000) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                JsonObject so = new JsonObject();
                so.addProperty("address", data.getAddress().toString());
                so.addProperty("value", data.getDefaultValueRepresentation());
                strings.add(so);
                stringCount++;
            }
        }
        root.add("strings", strings);
        root.addProperty("string_count", stringCount);

        // Imports (external symbols)
        JsonArray imports = new JsonArray();
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator symIter = symTable.getExternalSymbols();
        int importCount = 0;
        while (symIter.hasNext() && importCount < 2000) {
            Symbol sym = symIter.next();
            JsonObject io = new JsonObject();
            io.addProperty("name", sym.getName());
            io.addProperty("namespace", sym.getParentNamespace().getName());
            imports.add(io);
            importCount++;
        }
        root.add("imports", imports);
        root.addProperty("import_count", importCount);

        // Exports
        JsonArray exports = new JsonArray();
        SymbolIterator allSyms = symTable.getAllSymbols(true);
        int exportCount = 0;
        while (allSyms.hasNext() && exportCount < 2000) {
            Symbol sym = allSyms.next();
            if (sym.isExternalEntryPoint() || sym.getName().startsWith("Java_")) {
                JsonObject eo = new JsonObject();
                eo.addProperty("name", sym.getName());
                eo.addProperty("address", sym.getAddress().toString());
                eo.addProperty("is_jni", sym.getName().startsWith("Java_"));
                exports.add(eo);
                exportCount++;
            }
        }
        root.add("exports", exports);
        root.addProperty("export_count", exportCount);

        // Write JSON
        FileWriter writer = new FileWriter(outputPath);
        writer.write(root.toString());
        writer.close();

        println("Drake-X: exported " + funcCount + " functions, " +
                stringCount + " strings, " + importCount + " imports, " +
                exportCount + " exports to " + outputPath);
    }
}
