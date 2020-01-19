package com.google.javascript.jscomp;

import com.google.javascript.jscomp.NodeTraversal.AbstractPostOrderCallback;
import com.google.javascript.rhino.Node;

class StaticTaintAnalysisPass implements CompilerPass {

    final AbstractCompiler compiler;
    final StaticTaintAnalysis analysis;

    public StaticTaintAnalysisPass(AbstractCompiler compiler) {
        this.compiler = compiler;
        this.analysis = new StaticTaintAnalysis(null, null);
    }

    @Override
    public void process(Node externs, Node root) {
        analysis.analyze();
        analysis.doSTA(root);
        NodeTraversal.traverse(compiler, root, new Traversal());
    }

    private class Traversal extends AbstractPostOrderCallback {

        @Override
        public void visit(NodeTraversal t, Node n, Node parent) {

        }
    }
}