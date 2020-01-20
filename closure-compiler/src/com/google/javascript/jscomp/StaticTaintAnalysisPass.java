package com.google.javascript.jscomp;

import com.google.javascript.rhino.Node;

class StaticTaintAnalysisPass implements CompilerPass, NodeTraversal.ScopedCallback {

    private AbstractCompiler compiler;
    private StaticTaintAnalysis STAanalysis;
    private ControlFlowGraph<Node> cfg;

    public StaticTaintAnalysisPass(AbstractCompiler compiler) {
        this.compiler = compiler;
    }

    @Override
    public void process(Node externs, Node root) {
        (new NodeTraversal(compiler, this, new SyntacticScopeCreator(compiler)))
                .traverseRoots(externs, root);
    }

    @Override
    public final boolean shouldTraverse(NodeTraversal t, Node n, Node parent) {
        return !n.isScript() || !t.getInput().isExtern();
    }

    @Override
    public void enterScope(NodeTraversal t) {
        if (t.inGlobalScope()) {
            return; // Don't even brother. All global variables are likely escaped.
        }

        if (!t.getScope().isFunctionBlockScope()) {
            return; // Only want to do the following if its a function block scope.
        }

        Node functionScopeRoot = t.getScopeRoot().getParent();

        if (LiveVariablesAnalysis.MAX_VARIABLES_TO_ANALYZE < t.getScope().getVarCount()) {
            return;
        }

        SyntacticScopeCreator scopeCreator = (SyntacticScopeCreator) t.getScopeCreator();

        // Compute the static taint analysis.
        ControlFlowAnalysis cfa = new ControlFlowAnalysis(compiler, false, true);

        // Process the body of the function.
        cfa.process(null, functionScopeRoot);
        cfg = cfa.getCfg();

        STAanalysis = new StaticTaintAnalysis(cfg, t.getScope(), compiler, scopeCreator);
        try {
            STAanalysis.analyze();
        } catch (Exception e) {

        }
        STAanalysis.printRes();
    }

    @Override
    public void visit(NodeTraversal t, Node n, Node parent) {

    }

    @Override
    public void exitScope(NodeTraversal t) {

    }
}