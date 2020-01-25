package com.google.javascript.jscomp;

import com.google.gson.JsonArray;
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

    class Pair<T, R> {
        T first;
        R second;

        Pair(T t, R r) {
            this.first = t;
            this.second = r;
        }
    }

    /**
     * Definition of a variable that holds its tainted state and the relation to other variables.
     * If the variable does not have a parent it is considered a root.
     */
    public static final class VariableDefinition {
        enum Tainted {No, May, Must}

        private Node node;
        private Var var;
        private HashSet<VariableDefinition> dependent;
        private Boolean source;
        private Boolean sink;
        private Tainted tainted;

        private VariableDefinition(Node n) {
            this.node = n;
            this.var = null;
            this.dependent = new HashSet<VariableDefinition>();
            this.source = false;
            this.sink = false;
            this.tainted = Tainted.No;
        }

        private String getName() {
            if (node != null) {
                if (node.isName()) {
                    return node.getString() + "@" + node.getLineno();
                }
                return node.toString() + "@" + node.getLineno();
            }
            return "~";
        }
    }

    /**
     * Defines a function scope that holds a collection of variables.
     */
    public static final class STAScope implements LatticeElement {
        enum Reachable {Undefined, Never, Maybe, Must}

        ;

        private String name;
        private VariableDefinition varContext;
        private Reachable conditionContext;
        private HashSet<VariableDefinition> definitions;

        STAScope() {
            this.name = "scope@-1";
            this.varContext = null;
            this.conditionContext = Reachable.Undefined;
            this.definitions = new HashSet<VariableDefinition>();
        }

        public STAScope(STAScope other) {
            if (!other.name.equals("scope@-1")) {
                name = other.name;
            } else {
                name = "scope@-1";
            }
            varContext = other.varContext;
            conditionContext = other.conditionContext;
            definitions = new HashSet<VariableDefinition>(other.definitions);
        }

        public STAScope(Collection<VariableDefinition> vars) {
            this();
            definitions.addAll(vars);
        }

        VariableDefinition.Tainted taintState() {
            switch (conditionContext) {
                case Never:
                    return VariableDefinition.Tainted.No;
                case Maybe:
                    return VariableDefinition.Tainted.May;
                case Undefined:
                case Must:
                    return VariableDefinition.Tainted.Must;
            }
            return VariableDefinition.Tainted.No;
        }

        VariableDefinition findVar(Node n) {
            if (n != null && n.isName()) {
                for (VariableDefinition var : definitions) {
                    if (var.node.getString().equals(n.getString())) {
                        return var;
                    }
                }
                VariableDefinition var = new VariableDefinition(n);
                definitions.add(var);
                return var;
            }
            return null;
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
            result.definitions.addAll(first.definitions);
            result.definitions.addAll(second.definitions);
            return result;
        }
    }

    private static String source = "retSource";
    private static String sink = "sink";
    private HashMap<String, Var> variables;
    private String scopeName;
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
        this.scopeName = "scope@-1";
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
    STAScope flowThrough(Node n, STAScope in) {
        log("Flow", n);
        doSTA(n);
        return result;
    }

    @Override
    STAScope createInitialEstimateLattice() {
        return result;
    }

    @Override
    STAScope createEntryLattice() {
        return result;
    }

    void saveResult(JsonObject json) {
        JsonObject info = new JsonObject();
        JsonArray mustReach = new JsonArray();
        JsonArray mayReach = new JsonArray();

        json.add(scopeName, info);
        info.add("sources_that_must_reach_sinks", mustReach);
        info.add("sources_that_may_reach_sinks", mayReach);

        for (VariableDefinition var : result.definitions) {
            if (var.tainted == VariableDefinition.Tainted.May) {
                mayReach.add(var.getName());
            } else if (var.tainted == VariableDefinition.Tainted.Must) {
                mayReach.add(var.getName());
                mustReach.add(var.getName());
            }

            JsonObject prop = new JsonObject();
            json.add(var.getName(), prop);
            prop.addProperty("source", var.source);
            prop.addProperty("sink", var.sink);
            prop.addProperty("taint", var.tainted.toString());

            JsonArray dep = new JsonArray();
            prop.add("dependent", dep);
            for (VariableDefinition v : var.dependent) {
                dep.add(v.getName());
            }
        }
    }

    private void log(String what, Node n) {
        if (n != null) {
            System.out.print(what + " \t#" + n.getLineno() + " \t" + n.getToken().name());

            if (n.isName()) {
                System.out.println(" \t" + n.getString());
            } else {
                System.out.println();
            }
        } else {
            System.out.println(what);
        }
    }

    private boolean isConditional(Node n) {
        return n.isIf() || n.isVanillaFor() || n.isForIn() || n.isWhile() || n.isSwitch();
    }

    private void doSTACall(Node n) {
        log("Call", n);
        // Source
        if (n.hasOneChild() && n.getFirstChild().isName()) {
            if (n.getFirstChild().getString().equals(StaticTaintAnalysis.source)) {
                // Check assignment
                if (result.varContext != null) {
                    // Set as source
                    result.varContext.source = true;
                }
            }
        }
        // Sink
        else if (n.hasTwoChildren() && n.getFirstChild().isName()) {
            if (n.getFirstChild().getString().equals(StaticTaintAnalysis.sink)) {
                if (n.getSecondChild().isName()) {
                    VariableDefinition var = result.findVar(n.getSecondChild());

                    if (var.tainted != VariableDefinition.Tainted.Must) {
                        //  Set as sink
                        var.sink = true;
                        // If it was a source before we mark it as tainted
                        if (var.source) {
                            // If we do not know if we reach the conditional body.
                            var.tainted = result.taintState();
                        }

                        // If a dependent variable is a source we mark the parent as tainted.
                        for (VariableDefinition dep : var.dependent) {
                            if (dep.source) {
                                // If we do not know if we reach the conditional body.
                                dep.tainted = result.taintState();
                            }
                        }
                    }
                }
            }
        }
    }

    private void doSTAVar(Node n) {
        log("Var", n.getFirstChild());
        if (n.hasChildren() && n.getFirstChild().isName()) {
            VariableDefinition var = new VariableDefinition(n.getFirstChild());
            result.definitions.add(var);

            result.varContext = var;
            doSTAChildren(n.getFirstChild());
            result.varContext = null;
        }
    }

    private void doSTAAssign(Node n) {
        log("Assign", n.getFirstChild());
        if (n.hasChildren() && n.getFirstChild().isName()) {
            result.varContext = result.findVar(n.getFirstChild());

            doSTAChildren(n);
            result.varContext = null;
        }
    }

    private void doSTAName(Node n) {
        log("Name", n);
        if (result.varContext != null) {
            log("#=============== Parent " + result.varContext.getName(), null);
            VariableDefinition var = result.findVar(n);
            log("#=============== depends on " + var.getName(), null);

            if (result.varContext != var) {
                if (!var.dependent.isEmpty()) {
                    result.varContext.dependent.addAll(var.dependent);
                } else {
                    result.varContext.dependent.add(var);
                }
            }
        }
    }

    /**
     *
     * @param n Node
     * @param conditionalValue A pair that stores on one hand if the condition
     *                         can be evaluated to a constant and on the other
     *                         hand if the condition contains a named variable.
     */
    private void checkCondition(Node n, Pair<Boolean, Boolean> conditionalValue) {
        if (NodeUtil.isConstantName(n)) {
            // TODO We need to check if the value maybe evaluates to false.
            //  Then we need to set the value to false beause the body is
            //  never reachable.
            conditionalValue.first = true;
        } else {
            conditionalValue.first = false;
            if (n.isName()) {
                conditionalValue.second = true;
            }
        }
        for (Node c : n.children()) {
            checkCondition(c, conditionalValue);
        }
    }

    private void doSTAConditional(Node n) {
        log("Cond", n);

        Pair<Boolean, Boolean> conditionalValue = new Pair<Boolean, Boolean>(false, false);

        // If the conditional is either a loop or it is an if with 1 block.
        if (!(n.isSwitch() || (n.isIf() && n.hasXChildrenOrMore(3)))) {
            log("=========# Is loop or single if", null);
            // Get the node where the expression is stored.
            Node condition = NodeUtil.getConditionExpression(n);
            if (condition != null) {

                checkCondition(condition, conditionalValue);
                if (conditionalValue.first) {
                    log("=========# must reach", null);
                    // If the expression evaluates to true we always reach the body.
                    result.conditionContext = STAScope.Reachable.Must;
                } else {
                    if (conditionalValue.second) {
                        log("=========# can maybe reach", null);
                        // We are not sure if we can reach it.
                        result.conditionContext = STAScope.Reachable.Maybe;
                    } else {
                        log("=========# can never reach", null);
                        // If it evaluates to false we never can reach it.
                        result.conditionContext = STAScope.Reachable.Never;
                    }
                }
            } else {
                log("=========# must reach", null);
                // The condition is empty, we can always reach the body.
                result.conditionContext = STAScope.Reachable.Must;
            }

            // If the block is maybe or definitely reachable.
            if (result.conditionContext != STAScope.Reachable.Never) {
                Node block = NodeUtil.getLoopCodeBlock(n);
                if (block != null) {
                    doSTAChildren(block);
                }
            }
        } else {
            log("=========# Is switch or if with > 3", null);
            log("=========# must reach", null);
            // If we are inside a switch or an if with more than 1 block
            // and a name is inside one of those blocks it must be reachable.
            result.conditionContext = STAScope.Reachable.Must;

            for (Node c : n.children()) {
                // Do not check the condition but only block.
                if (!c.equals(n.getFirstChild())) {
                    doSTAChildren(c);
                }
            }
        }

        result.conditionContext = STAScope.Reachable.Undefined;
    }

    private void doSTAChildren(Node n) {
        for (Node c : n.children()) {
            doSTA(c);
        }
    }

    private void doSTA(Node n) {
        log("", n);
        if (n == null) {
            return;
        }

        if (n.isFunction()) {
            log("Func", n);
            // First child is the function name.
            scopeName = n.getFirstChild().getString() + "@" + n.getLineno();
        } else if (n.isCall()) {
            doSTACall(n);
        } else if (n.isVar() || n.isConst() || n.isLet()) {
            doSTAVar(n);
        } else if (n.isAssign()) {
            doSTAAssign(n);
        } else if (isConditional(n)) {
            doSTAConditional(n);
        } else if (n.isName()) {
            doSTAName(n);
        } else if (n.isBlock()) {
            return;
        } else if(n.isObjectLit() || n.isArrayLit()) {
            result.varContext = result.findVar(n.getParent());
            doSTAChildren(n);
            result.varContext = null;
        } else {
            doSTAChildren(n);
        }
    }
}