package com.google.javascript.jscomp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.javascript.rhino.Node;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

class StaticTaintAnalysisPass implements CompilerPass, NodeTraversal.ScopedCallback {

    /**
     * When a scope is left the result is stored in a JsonObject for that specific scope.
     * When the analysis is finished all JsonObjects are combined and written to the output
     * file. This file is stored in the same directory as the input file. As long as the
     * input file is a .js file the output file will have the same name with a _out.json
     * postfix.
     */
    private static class STAResult {
        JsonObject json;

        STAResult() {
            json = new JsonObject();
        }

        /**
         * Write the contents of the JsonObject into the output file.
         * @param name  String that contains the name of the input file.
         */
        void writeRes(String name) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            // Gson writes arrays into multiple lines, so we remove the blanks and newlines.
            String formatted = gson.toJson(json)
                    .replaceAll("\\[\\n\\s+", "[")
                    .replaceAll("\",\\n\\s+", "\", ")
                    .replaceAll("\\n\\s+]", "]");

            try {
                Files.writeString(
                        Paths.get(name.replace(".js", "_out.json")),
                        formatted);

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private AbstractCompiler compiler;
    private STAResult result;

    public StaticTaintAnalysisPass(AbstractCompiler compiler) {
        this.compiler = compiler;
        this.result = new STAResult();
    }

    /**
     * Runs the analysis.
     * @param externs Top of external JS tree
     * @param root Top of JS tree
     */
    @Override
    public void process(Node externs, Node root) {
        NodeTraversal nt = new NodeTraversal(
                compiler,
                this,
                new SyntacticScopeCreator(compiler));

        nt.traverseRoots(externs, root);
        result.writeRes(nt.getSourceName());
    }

    @Override
    public final boolean shouldTraverse(NodeTraversal t, Node n, Node parent) {
        return !n.isScript() || !t.getInput().isExtern();
    }

    /**
     * Runs the STA for each function that is found in the input.
     * @param t The root node.
     */
    @Override
    public void enterScope(NodeTraversal t) {
        if (t.inGlobalScope()) {
            return;
        }

        if (!t.getScope().isFunctionBlockScope()) {
            return;
        }

        ControlFlowAnalysis cfa = new ControlFlowAnalysis(compiler, false, true);
        cfa.process(null, t.getScopeRoot().getParent());

        // Compute the static taint analysis.
        StaticTaintAnalysis sta = new StaticTaintAnalysis(cfa.getCfg());
        sta.doSTA(t.getScopeRoot().getParent());
        sta.saveResult(result.json);
    }

    @Override
    public void visit(NodeTraversal t, Node n, Node parent) {

    }

    @Override
    public void exitScope(NodeTraversal t) {

    }
}