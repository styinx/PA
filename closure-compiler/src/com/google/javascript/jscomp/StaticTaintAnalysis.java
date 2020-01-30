package com.google.javascript.jscomp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.javascript.jscomp.graph.LatticeElement;
import com.google.javascript.rhino.Node;

import java.util.ArrayList;
import java.util.LinkedHashSet;


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
    public static final class VariableDefinition implements Comparable<VariableDefinition> {
        // Defines if the variable leaks.
        enum Tainted {No, May, Must}
        // Defines if the variable is declared inside a conditional.
        enum Reachable {Always, Maybe, Never}

        private Node node;
        private LinkedHashSet<VariableDefinition> dependent;
        private Boolean source;
        private Tainted tainted;
        private Reachable reachable;

        private VariableDefinition(Node n) {
            this.node = n;
            this.dependent = new LinkedHashSet<VariableDefinition>();
            this.source = false;
            this.tainted = Tainted.No;
            this.reachable = Reachable.Always;
        }

        /**
         * Name of the variable.
         * @return the name of the variable with line number.
         */
        private String getName() {
            // Should never happen that the node is null.
            if (node != null) {
                if (node.isName()) {
                    return node.getString() + "@" + node.getLineno();
                }
                return node.toString() + "@" + node.getLineno();
            }
            return "";
        }

        /**
         * We add a variable as dependency.
         * For example in {@code var x = y;} the variable x is depedent on y.
         * If y is already dependent on another variable, x is assigned all the
         * dependencies of y.
         * @param other The dependent variable.
         */
        private void addDependency(VariableDefinition other) {
            if (other.dependent.isEmpty()) {
                dependent.add(other);
            } else {
                dependent.addAll(other.dependent);
            }
        }

        /**
         * This function should be used when a sink is reached.
         * Based on the given reachability we can decide if the variable
         * may or must be tainted.
         * @param reachability The statements reachability.
         */
        private void setTaintedState(Reachable reachability) {
            if(reachability == Reachable.Always) {
                tainted = Tainted.Must;
            } else if (reachability == Reachable.Maybe) {
                tainted = Tainted.May;
            }
        }

        /**
         * Used for ordering the variables in a Collection based on the line number.
         * @param o The variable to compare to.
         * @return if the other variable is bigger (>0) or equal or samller (<= 0).
         */
        @Override
        public int compareTo(VariableDefinition o) {
            if (node != null && o.node != null) {
                return node.getLineno() - o.node.getLineno();
            }
            return 0;
        }
    }

    /**
     * Stores the name of a function and definitions of variables inside this function.
     * It also remembers the current variables context (see paper, {@code var x = y;}
     * y is in the context of x) and the conditional context.
     */
    public static final class STAScope implements LatticeElement {
        private String name;
        private VariableDefinition varContext;
        private VariableDefinition.Reachable conditionContext;
        private LinkedHashSet<VariableDefinition> definitions;

        STAScope() {
            this.name = "scope@-1";
            this.varContext = null;
            this.conditionContext = VariableDefinition.Reachable.Always;
            this.definitions = new LinkedHashSet<VariableDefinition>();
        }

        /**
         * Helps readability. If the current conditional context is not reachable we could go over it.
         * @return true if the current condition is not reachable.
         */
        boolean isUnReachable() {
            return conditionContext == VariableDefinition.Reachable.Never;
        }

        /**
         * Returns a variable definition that matches the name of the given node.
         * @param n The node of the variable that is searched for.
         * @return a variable definition if the variable exists, otherwise a new definition.
         */
        VariableDefinition findVar(Node n) {
            if (n != null && n.isName()) {
                for (VariableDefinition var : definitions) {
                    if (var.node.getString().equals(n.getString())) {
                        return var;
                    }
                }
                // Should not happen that a variable name is not defined.
                VariableDefinition var = new VariableDefinition(n);
                definitions.add(var);
                return var;
            }
            return null;
        }
    }

    /**
     * Performs a join of two STALattices and combines their contents.
     * This means if they have the same scope the variables are joined.
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
    private STAScope result;

    /**
     * Constructs a data flow analysis.
     * @param cfg The control flow graph object that this object performs
     *            on.
     */
    StaticTaintAnalysis(ControlFlowGraph<Node> cfg) {
        super(cfg, new STAJoin());
        this.result = new STAScope();
    }

    @Override
    boolean isForward() {
        return true;
    }

    @Override
    STAScope flowThrough(Node n, STAScope in) {
        return in;
    }

    @Override
    STAScope createInitialEstimateLattice() {
        return result;
    }

    @Override
    STAScope createEntryLattice() {
        return result;
    }

    /**
     * This function is called from the compiler pass and stores the variables
     * with a tainted state inside a json object.
     * @param json The JsonObject where the result should be stored.
     */
    void saveResult(JsonObject json) {
        JsonObject info = new JsonObject();
        JsonArray may = new JsonArray();
        JsonArray must = new JsonArray();

        for (VariableDefinition var : result.definitions) {
            if (var.tainted == VariableDefinition.Tainted.May) {
                may.add(var.getName());
            } else if (var.tainted == VariableDefinition.Tainted.Must) {
                may.add(var.getName());
                must.add(var.getName());
            }
        }

        json.add(result.name, info);
        info.add("sources_that_must_reach_sinks", must);
        info.add("sources_that_may_reach_sinks", may);
    }

    /**
     * Recursively evaluates the subtree of a condition and returns the reachability.
     * @param first Left hand side of the condition.
     * @param second Right hand side of the condition.
     * @return if the conditions block is Always, Mabe, or never reachable.
     */
    private static VariableDefinition.Reachable getConditionalReachability(
            VariableDefinition.Reachable first,
            VariableDefinition.Reachable second) {

        // Both conditions have the same reachability.
        if (first.equals(second)) {
            return first;
        }
        // Both conditions have different reachability classes.
        // Always return the lower class.
        else {
            if (first == VariableDefinition.Reachable.Always) {
                return second;
            } else if (first == VariableDefinition.Reachable.Never) {
                return first;
            } else if (first == VariableDefinition.Reachable.Maybe && second == VariableDefinition.Reachable.Always) {
                return first;
            } else if (first == VariableDefinition.Reachable.Maybe && second == VariableDefinition.Reachable.Never) {
                return second;
            } else {
                // There is no other case but we improve readability.
                return VariableDefinition.Reachable.Always;
            }
        }
    }

    /**
     * The inspected node is variable. A new variable definition is added for each
     * introduced variable. The current functions variable context is also set.
     * @param n The Node to inspect.
     */
    private void doSTAVar(Node n) {
        // In the case that we have multiple variables in one statement.
        for (Node c : n.children()) {
            if (c.isName()) {
                VariableDefinition var = new VariableDefinition(c);
                result.definitions.add(var);

                result.varContext = var;
                doSTAChildren(c);
                result.varContext = null;
            }
        }
    }

    /**
     * If an assignment outside of a variable declaration happens it is required
     * to update the assigned variables dependencies.
     * @param n The node to inspect.
     */
    private void doSTAAssign(Node n) {
        if (n.hasChildren()) {
            // If we have a variable to variable assignment.
            if (n.getFirstChild().isName()) {
                result.varContext = result.findVar(n.getFirstChild());
                doSTAChildren(n);
                result.varContext = null;
            }
            // We call o['a'] = x.
            else if (n.getFirstChild().isGetElem()) {
                VariableDefinition caller = result.findVar(n.getFirstChild().getFirstChild());
                VariableDefinition value = result.findVar(n.getSecondChild());

                caller.addDependency(value);
            }
        }
    }

    /**
     * If a variable appears inside an assignment (result.varContext is not be empty)
     * the variables dependencies on the left side must be updated.
     * This is a special case of {@see doSTAAssign} and {@see doSTAVar} since
     * it includes OBJECT_LIT or ARRAY_LIT tokens.
     * @param n The node to inspect.
     */
    private void doSTAName(Node n) {
        if (result.varContext != null) {
            VariableDefinition var = result.findVar(n);

            if (result.varContext != var) {
                result.varContext.addDependency(var);
            }
        }
    }

    /**
     * A function is called. We check the type of the function an whether it is
     * of importance to use.
     * @param n The node to inspect.
     */
    private void doSTACall(Node n) {
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

                    // If it was a source before we mark it as tainted.
                    if (var.source) {
                        // Set the tainted state based on the reachability.
                        var.setTaintedState(var.reachable);
                    }

                    // If a dependent variable is a source we mark the parent as tainted.
                    for (VariableDefinition dep : var.dependent) {
                        if (dep.source) {
                            // We can only decide if the dependent source is also reachable.
                            if (dep.reachable == var.reachable) {
                                // Set the tainted state based on the reachability of the dependent variable.
                                dep.setTaintedState(var.reachable);
                            }
                        }
                    }
                }
            }
        }
        // Another function call.
        else {
            // We call o.f(x).
            if (n.getFirstChild().isGetProp() && n.getSecondChild().isName()) {
                VariableDefinition caller = result.findVar(n.getFirstChild().getFirstChild());
                VariableDefinition argument = result.findVar(n.getSecondChild());

                caller.addDependency(argument);
            }
        }
    }

    /**
     * Helper function that returns the reachability of a condition.
     * @param n The node to inspect.
     * @return the reachability of the condition body.
     */
    private VariableDefinition.Reachable checkCondition(Node n) {
        VariableDefinition.Reachable reachable = VariableDefinition.Reachable.Always;

        if (n != null) {
            // The current node of the condition is constant.
            if (NodeUtil.isConstantName(n)) {
                // We assume that the constant evaluates always to true.
                reachable = VariableDefinition.Reachable.Always;
            }
            // We can not evaluate the value of the variable.
            else if (n.isName()) {
                // We are not sure what the value of the variable is.
                reachable = VariableDefinition.Reachable.Maybe;

            }

            for (Node c : n.children()) {
                // Check inner conditions. The value takes the lower reachable type.
                VariableDefinition.Reachable next = checkCondition(c);
                reachable = StaticTaintAnalysis.getConditionalReachability(reachable, next);
            }
        }
        return reachable;
    }

    /**
     * The token represents an if condition or a loop. We check the reachability of the
     * condition. If it is maybe or always reachable we check for the nested statements.
     * The scopes conditional context is also altered.
     * We also mark the already defined variables with the same reachability class.
     * At the exit of the scope we reset the conditional context and the variables
     * reachability class to the reachability of the outer scope.
     * @param n The node to inspect.
     */
    private void doSTAConditional(Node n) {
        // Remember the context of the outer scope.
        VariableDefinition.Reachable parentContext = result.conditionContext;

        // Get the node where the expression is stored.
        Node condition = NodeUtil.getConditionExpression(n);
        result.conditionContext = checkCondition(condition);

        // When we enter the condition we mark all already defined
        // variables with the conditional context.
        for (VariableDefinition var : result.definitions) {
            var.reachable = result.conditionContext;
        }

        // If the block is maybe or always reachable we proceed.
        if (!result.isUnReachable()) {
            if (n.isIf()) {
                for (Node c : n.children()) {
                    // Do not check the condition but only blocks.
                    if (!c.equals(n.getFirstChild())) {
                        doSTAChildren(c);
                    }
                }
            } else {
                Node block = NodeUtil.getLoopCodeBlock(n);
                if (block != null) {
                    doSTAChildren(block.getFirstChild());
                }
            }
        }
        // Reset the conditional contexts.
        result.conditionContext = parentContext;
        for (VariableDefinition var : result.definitions) {
            var.reachable = result.conditionContext;
        }
    }

    /**
     * If a case of a switch contains a variable name we always assume it is
     * maybe reachable since we can not evaluate the condition.
     * We also set and reset the conditional context and the reachability classes
     * of the variables that are currently defined.
     * @param n The node to inspect.
     */
    private void doSTASwitch(Node n) {
        // Remember the context of the outer scope.
        VariableDefinition.Reachable parentContext = result.conditionContext;
        result.conditionContext = VariableDefinition.Reachable.Maybe;

        // When we enter the condition we mark all already defined
        // variables with the conditional context.
        for (VariableDefinition var : result.definitions) {
            var.reachable = result.conditionContext;
        }

        for (Node c : n.children()) {
            if (c != n.getFirstChild()) {
                if (c.isCase()) {
                    doSTAChildren(c.getSecondChild());
                } else if (c.isDefaultCase()) {
                    doSTAChildren(c.getFirstChild());
                }
            }
        }
        // Reset the conditional contexts.
        result.conditionContext = parentContext;
        for (VariableDefinition var : result.definitions) {
            var.reachable = result.conditionContext;
        }
    }

    /**
     * Do an STA of a nodes children.
     * @param n The node which children we want to analyze.
     */
    private void doSTAChildren(Node n) {
        for (Node c : n.children()) {
            doSTA(c);
        }
    }

    /**
     * The entry point of a STA.
     * @param n The node we inspect.
     */
    public void doSTA(Node n) {
        if (n == null) {
            return;
        }

        switch (n.getToken()) {
            case FUNCTION:
                // First child is the function name.
                result.name = n.getFirstChild().getString() + "@" + n.getLineno();
                doSTA(n.getLastChild());
                break;

            case CALL:
                doSTACall(n);
                break;

            case VAR:
            case CONST:
            case LET:
                doSTAVar(n);
                break;

            case NAME:
                doSTAName(n);
                break;

            case ASSIGN:
                doSTAAssign(n);
                break;

            case IF:
            case FOR:
            case FOR_IN:
            case WHILE:
                doSTAConditional(n);
                break;

            case SWITCH:
                doSTASwitch(n);
                break;

            default:
                doSTAChildren(n);
        }
    }
}