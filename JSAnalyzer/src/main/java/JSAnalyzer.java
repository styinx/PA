package main.java;

import static java.lang.System.exit;

import com.google.gson.*;
import com.google.javascript.jscomp.*;
import com.google.javascript.rhino.Node;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public final class JSAnalyzer {

    private String m_filename;
    private Integer[] m_lines = {0, 0};

    private boolean readJSFile(String filename, ControlFlowGraph<Node> cfg) {

        if (!filename.endsWith(".js")) {
            return false;
        }

        try {
            List<String> lines = Files.readAllLines(Paths.get(filename));

            m_filename = filename;
            cfg = createCFG(lines);

            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }


        return false;
    }

    private ControlFlowGraph<Node> createCFG(List<String> lines) {
        ControlFlowGraph<Node> cfg = null;
        return cfg;
    }

    private void doAnalysis(ControlFlowGraph<Node> cfg) {
        JsonObject json = new JsonObject();
        JsonObject info = new JsonObject();
        JsonArray mustReach = new JsonArray();
        JsonArray mayReach = new JsonArray();

        // doSth

        info.add("sources_that_must_reach_sinks", mustReach);
        info.add("sources_that_may_reach_sinks", mayReach);

        json.add("getInformation@" + m_lines[0] + "-" + m_lines[1], info);

        try {
            Files.writeString(
                    Paths.get(m_filename.replace(".js", "_out.js")),
                    json.toString());

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Please provide a valid file.");
            exit(1);
        }

        JSAnalyzer analyzer = new JSAnalyzer();
        ControlFlowGraph<Node> cfg = null;

        if (!analyzer.readJSFile(args[1], cfg)) {
            System.out.println("No valid JS file given.");
            exit(1);
        }

        analyzer.doAnalysis(cfg);
    }
}
