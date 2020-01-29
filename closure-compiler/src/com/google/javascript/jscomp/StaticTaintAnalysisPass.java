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
     * Stores the result of a lattice when the scope is left.
     * Remembers if a variable is may be tainted or must be tainted.
     */
    private static class STAResult {
        JsonObject json;

        STAResult() {
            json = new JsonObject();
        }

        void writeRes() {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            System.out.println("\n" + gson.toJson(json) + "\n");
            System.out.println("\n" + json.toString() + "\n");
        try {
            Files.writeString(
                    Paths.get("file.js".replace(".js", "_out.js")),
                    gson.toJson(json));

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

    @Override
    public void process(Node externs, Node root) {
        (new NodeTraversal(
                compiler,
                this,
                new SyntacticScopeCreator(compiler))).traverseRoots(externs, root);

        result.writeRes();
    }

    @Override
    public final boolean shouldTraverse(NodeTraversal t, Node n, Node parent) {
        return !n.isScript() || !t.getInput().isExtern();
    }

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