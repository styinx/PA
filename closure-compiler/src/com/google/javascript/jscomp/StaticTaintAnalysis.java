package com.google.javascript.jscomp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.javascript.jscomp.graph.LatticeElement;
import com.google.javascript.rhino.Node;

import java.util.*;


/**
 * Performs a static taint analysis for all variables.
 * <p>
 * A variable may leak information (is tainted) to a
 * sink if it is a source or contains contents from a source.
 */
class StaticTaintAnalysis
        extends DataFlowAnalysis<Node, StaticTaintAnalysis.STAScope> {

    /**
     * Definition of a variable that holds its tainted state and the relation to other variables.
     * If the variable does not have a parent it is considered a root.
     */
    public static final class VariableDefinition {
        enum Tainted {No, May, Must}

        private Node node;
        private HashSet<Var> dependent;
        private boolean source;
        private boolean sink;
        private Tainted tainted;

        private VariableDefinition(Node n) {
            this.node = n;
            this.dependent = new HashSet<Var>();
            this.source = false;
            this.sink = false;
            this.tainted = Tainted.No;
        }
    }

    /**
     * Defines a function scope that holds a collection of variables.
     */
    public static final class STAScope implements LatticeElement {
        private HashMap<Var, VariableDefinition> definitions;

        STAScope() {
            this.definitions = new HashMap<Var, VariableDefinition>();
        }

        public STAScope(STAScope other) {
            definitions = new HashMap<Var, VariableDefinition>(other.definitions);
        }

        public STAScope(Collection<Var> vars) {
            this();
            for (Var var : vars) {
                definitions.put(var, new VariableDefinition(var.scope.getRootNode()));
            }
        }
    }

    /**
     * Performs a join of two STALattices and combines their contents.
     * This means if they have the same scope (function name) the variables are joined.
     */
    private static class STAJoin extends JoinOp.BinaryJoinOp<STAScope> {
        @Override
        STAScope apply(STAScope first, STAScope second) {
            STAScope result = new STAScope();
            Map<Var, VariableDefinition> resultMap = result.definitions;

            for (Map.Entry<Var, VariableDefinition> varEntry : first.definitions.entrySet()) {
                Var var = varEntry.getKey();
                VariableDefinition aDef = varEntry.getValue();

                if (aDef == null) {
                    resultMap.put(var, null);
                    continue;
                }

                if (second.definitions.containsKey(var)) {
                    VariableDefinition bDef = second.definitions.get(var);

                    if (aDef.equals(bDef)) {
                        resultMap.put(var, aDef);
                    } else {
                        resultMap.put(var, null);
                    }
                } else {
                    resultMap.put(var, aDef);
                }
            }

            for (Map.Entry<Var, VariableDefinition> entry : second.definitions.entrySet()) {
                Var var = entry.getKey();
                if (!first.definitions.containsKey(var)) {
                    resultMap.put(var, entry.getValue());
                }
            }
            return result;
        }
    }

    private static String source = "retSource";
    private static String sink = "sink";
    private HashMap<String, Var> variables;
    private String scope;
    private STAScope result;

    /**
     * Constructs a data flow analysis.
     *
     * @param cfg The control flow graph object that this object performs
     *            on. Modification of the graph requires a separate call to
     *            {@link #analyze()}.
     * @see #analyze()
     */
    StaticTaintAnalysis(
            ControlFlowGraph<Node> cfg,
            AbstractCompiler compiler,
            Scope scope,
            SyntacticScopeCreator scopeCreator) {

        super(cfg, new STAJoin());
        this.variables = new HashMap<String, Var>();
        this.scope = "scope";
        this.result = new STAScope();
        HashSet<Var> escaped = new HashSet<Var>();
        ArrayList<Var> orderedVars = new ArrayList<Var>();

        computeEscaped(scope.getParent(), escaped, compiler, scopeCreator);
        NodeUtil.getAllVarsDeclaredInFunction(variables, orderedVars, compiler, scopeCreator, scope.getParent());
    }

    @Override
    boolean isForward() {
        return true;
    }

    @Override
    STAScope flowThrough(Node node, STAScope input) {
        STAScope out = new STAScope(input);
        try {
            doSTA(node, node, out, false);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        this.result = out;
        return out;
    }

    @Override
    STAScope createInitialEstimateLattice() {
        return new STAScope();
    }

    @Override
    STAScope createEntryLattice() {
        return new STAScope(variables.values());
    }

    /**
     * If the variable name was changed this function
     * returns the original function name.
     *
     * @param varName Name of the variable as String.
     * @return The original function name as String.
     */
    private static String getNormalizedVarName(String varName) {
        if (varName.indexOf('$') > 0) {
            varName = varName.substring(0, varName.indexOf('$', 0)) +
                    varName.substring(varName.lastIndexOf('@'));
        }
        return varName;
    }

    void saveResult(JsonObject json) {
        JsonObject info = new JsonObject();
        JsonArray mustReach = new JsonArray();
        JsonArray mayReach = new JsonArray();

        json.add(scope, info);
        info.add("sources_that_must_reach_sinks", mustReach);
        info.add("sources_that_may_reach_sinks", mayReach);

        for(String var : variables.keySet()) {
            json.add(var, new JsonObject());
        }

        for (Var var : result.definitions.keySet()) {
            VariableDefinition def = result.definitions.get(var);
            if(def.tainted == VariableDefinition.Tainted.May) {
                mayReach.add(var.name);
            } else if(def.tainted == VariableDefinition.Tainted.Must) {
                mayReach.add(var.name);
                mustReach.add(var.name);
            }
//            if (var.mayBeTainted() || var.mustBeTainted()) {
//                if (!var.isRoot()) {
//                    for (VariableDefinition parent : var.getParents()) {
//                        if (var.mayBeTainted()) {
//                            mayReach.add(StaticTaintAnalysis.getNormalizedVarName(parent.toString()));
//                        } else {
//                            mayReach.add(StaticTaintAnalysis.getNormalizedVarName(parent.toString()));
//                            mustReach.add(StaticTaintAnalysis.getNormalizedVarName(parent.toString()));
//                        }
//                    }
//                } else {
//                    if (var.mayBeTainted()) {
//                        mayReach.add(StaticTaintAnalysis.getNormalizedVarName(var.toString()));
//                    } else {
//                        mayReach.add(StaticTaintAnalysis.getNormalizedVarName(var.toString()));
//                        mustReach.add(StaticTaintAnalysis.getNormalizedVarName(var.toString()));
//                    }
//                }
//            }
//            System.out.println(" |\t May Tainted: " +
//                    var.mayBeTainted() + " |\t Must Tainted: " +
//                    var.mustBeTainted() + " |\t Root: " +
//                    var.isRoot() + " |\t Sink: " +
//                    var.isSink() + " |\t Source: " +
//                    var.isSource() + " |\t Name " +
//                    StaticTaintAnalysis.getNormalizedVarName(var.toString()) + " | Parents: " +
//                    var.getParents()
//            );
        }
    }

    private void doSTA(Node n, Node cfgNode, STAScope output, boolean conditional) {
        if(n == null) {
            return;
        }

        switch (n.getToken()) {
            case BLOCK:
            case ROOT:
                return;

            case FUNCTION:
                scope = n.getFirstChild().getString() + "@" + n.getLineno();
                return;

            case CALL:
                // Source is called
                if(n.hasXChildren(1)) {
                    if(n.getParent().isName()) {
                        Node ads = n.getParent();
                        System.out.println(" # " + ads.getLineno() + " | " + ads.getString());
                        output.definitions.get(variables.get(n.getParent().getString())).source = true;
                    }
                } else if(n.hasXChildren(2)) {
                    if(n.getSecondChild().isName()) {
                        Node ads = n.getSecondChild();
                        System.out.println(" # " + ads.getLineno() + " | " + ads.getString());
                        VariableDefinition var = output.definitions.get(variables.get(n.getParent().getString()));
                        var.sink = true;

                        // If the variable was a source before it leaks.
                        if(var.source) {
                            var.tainted = VariableDefinition.Tainted.Must;
                        }
                    }
                }
                return;

            case WHILE:
            case DO:
            case IF:
            case FOR:
                doSTA(NodeUtil.getConditionExpression(n), cfgNode, output, conditional);
                return;

            case FOR_IN:
            case FOR_OF:
            case FOR_AWAIT_OF:
                // for(x in y) {...}
                Node lhs = n.getFirstChild();
                Node rhs = lhs.getNext();
                if (NodeUtil.isNameDeclaration(lhs)) {
                    lhs = lhs.getLastChild(); // for(var x in y) {...}
                }
                if (lhs.isName()) {
                    // TODO(lharker): This doesn't seem right - given for (x in y), the value set to x isn't y
                    //addToDefIfLocal(lhs.getString(), cfgNode, rhs, output);
                } else if (lhs.isDestructuringLhs()) {
                    lhs = lhs.getFirstChild();
                }
                if (lhs.isDestructuringPattern()) {
                    doSTA(lhs, cfgNode, output, true);
                }
                return;

            case AND:
            case OR:
                doSTA(n.getFirstChild(), cfgNode, output, conditional);
                doSTA(n.getLastChild(), cfgNode, output, true);
                return;

            case HOOK:
                doSTA(n.getFirstChild(), cfgNode, output, conditional);
                doSTA(n.getSecondChild(), cfgNode, output, true);
                doSTA(n.getLastChild(), cfgNode, output, true);
                return;

            case LET:
            case CONST:
            case VAR:
                for (Node c = n.getFirstChild(); c != null; c = c.getNext()) {
                    if (c.hasChildren()) {
                        if (c.isName()) {
                            doSTA(c.getFirstChild(), cfgNode, output, conditional);
                            output.definitions.put(variables.get(c.getString()), new VariableDefinition(c));
//                            addToDefIfLocal(c.getString(), conditional ? null : cfgNode,
//                                    c.getFirstChild(), output);
                        } else {
//                            checkState(c.isDestructuringLhs(), c);
                            doSTA(c.getSecondChild(), cfgNode, output, conditional);
                            doSTA(c.getFirstChild(), cfgNode, output, conditional);
                        }
                    }
                }
                return;

            case DEFAULT_VALUE:
                if (n.getFirstChild().isDestructuringPattern()) {
                    doSTA(n.getSecondChild(), cfgNode, output, true);
                    doSTA(n.getFirstChild(), cfgNode, output, conditional);
                } else if (n.getFirstChild().isName()) {
                    doSTA(n.getSecondChild(), cfgNode, output, true);
//                    addToDefIfLocal(
//                            n.getFirstChild().getString(), conditional ? null : cfgNode, null, output);
                } else {
                    doSTA(n.getFirstChild(), cfgNode, output, conditional);
                    doSTA(n.getSecondChild(), cfgNode, output, true);
                }
                break;

            case NAME:
                VariableDefinition var = output.definitions.get(variables.get(n.getParent().getString()));
                var.sink = true;
                if (NodeUtil.isLhsByDestructuring(n)) {
//                    addToDefIfLocal(n.getString(), conditional ? null : cfgNode, null, output);
                } else if ("arguments".equals(n.getString())) {
//                    escapeParameters(output);
                }
                return;

            default:
                if (NodeUtil.isAssignmentOp(n)) {
                    if (n.getFirstChild().isName()) {
                        Node name = n.getFirstChild();
                        doSTA(name.getNext(), cfgNode, output, conditional);
//                        addToDefIfLocal(name.getString(), conditional ? null : cfgNode, n.getLastChild(), output);
                        return;
                    } else if (NodeUtil.isGet(n.getFirstChild())) {
                        // Treat all assignments to arguments as redefining the
                        // parameters itself.
                        Node obj = n.getFirstFirstChild();
                        if (obj.isName() && "arguments".equals(obj.getString())) {
//                            // TODO(user): More accuracy can be introduced
//                            // i.e. We know exactly what arguments[x] is if x is a constant
//                            // number.
//                            escapeParameters(output);
                        }
                    } else if (n.getFirstChild().isDestructuringPattern()) {
                        doSTA(n.getSecondChild(), cfgNode, output, conditional);
                        doSTA(n.getFirstChild(), cfgNode, output, conditional);
                        return;
                    }
                }

                // DEC and INC actually defines the variable.
                if (n.isDec() || n.isInc()) {
                    Node target = n.getFirstChild();
                    if (target.isName()) {
//                        addToDefIfLocal(target.getString(), conditional ? null : cfgNode, null, output);
                        return;
                    }
                }

                for (Node c = n.getFirstChild(); c != null; c = c.getNext()) {
                    doSTA(c, cfgNode, output, conditional);
                }
        }
    }
}