package com.google.javascript.jscomp;

import com.google.javascript.jscomp.graph.LatticeElement;
import com.google.javascript.rhino.Node;

import static com.google.javascript.rhino.Token.*;

import java.util.*;


/**
 * Performs a static taint analysis for all variables.
 * <p>
 * A variable may leak information (is tainted) to a
 * sink if it is a source or contains contents from a source.
 */
public class StaticTaintAnalysis
        extends DataFlowAnalysis<Node, StaticTaintAnalysis.STALattice> {

    /**
     *
     */
    public enum STAState {
        UNTAINTED,
        MUST_TAINTED,
        MAY_TAINTED
    }

    /**
     *
     */
    private static class STAObj {
        private String name;
        private Integer line;

        STAObj(String name, Integer line) {
            this.name = name;
            this.line = line;
        }

        public String getName() {
            return name;
        }

        public String toString() {
            return this.name + "@" + this.line;
        }

        public int hashCode() {
            return Objects.hashCode(toString());
        }
    }

    private static class STAVar extends STAObj {
        private STAState state;
        private HashSet<STAVar> parents;
        private boolean source;

        STAVar(String name, Integer line, STAState state) {
            super(name, line);
            this.state = state;
            parents = new HashSet<STAVar>();
            source = false;
        }

        STAState getState() {
            return state;
        }

        void setState(STAState state) {
            this.state = state;
        }

        void setParent(STAVar parent) {
            this.parents.add(parent);
            source = source || parent.isSource();
        }

        HashSet<STAVar> getRootParents() {
            HashSet<STAVar> root = new HashSet<STAVar>();

            if(!parents.isEmpty()) {
                for (STAVar parent : parents) {
                    root.addAll(parent.getRootParents());
                }
            }

            root.add(this);
            return root;
        }

        public boolean isSource() {
            return source;
        }

        public void setSource(boolean source) {
            this.source = source;
        }
    }

    /**
     *
     */
    static final class STALattice implements LatticeElement {
        // Defines the active scope we currently use.
        STAObj activeFunction;
        // Defines a map of all functions and the corresponding line number
        HashSet<STAObj> functions;
        // Defines a map of all variables within a function and their taint state.
        HashMap<STAObj, HashSet<STAVar>> variables;

        STALattice() {
            activeFunction = new STAObj("GLOBAL", -1);
            functions = new HashSet<STAObj>();
            variables = new HashMap<STAObj, HashSet<STAVar>>();
        }

        public STALattice(STALattice other) {
            activeFunction = other.activeFunction;
            functions = other.functions;
            variables = other.variables;
        }

        void addFunction(STAObj func) {
            functions.add(func);
            variables.put(func, new HashSet<STAVar>());
            activeFunction = func;
        }

        void addVariable(STAVar var) {
            variables.get(activeFunction).add(var);
        }

        STAVar findVar(String varName) {
            for (STAVar var : variables.get(activeFunction)) {
                if (varName.equals(var.getName())) {
                    return var;
                }
            }
            return null;
        }

        void printRes() {
            for (STAObj func : functions) {
                System.out.println(func.toString());

                HashSet<STAVar> mustTainted = new HashSet<STAVar>();
                HashSet<STAVar> mayTainted = new HashSet<STAVar>();
                System.out.println("Vars: ");
                for (STAVar var : variables.get(func)) {
                    if (var.isSource()) {
                        if (var.getState() == STAState.MUST_TAINTED) {
                            mustTainted.add(var);
                        } else if (var.getState() == STAState.MAY_TAINTED) {
                            mayTainted.add(var);
                        }
                    }

                    String parents = "";
                    for(STAVar parent : var.getRootParents()) {
                        parents = parents.concat(parent.getName() + ", ");
                    }

                    System.out.println("  " + var.getName() + "(" + parents + var.isSource() + ")");
                }

                System.out.print("Must: ");
                for (STAVar must : mustTainted) {
                    System.out.print(must.toString() + ", ");
                }

                System.out.print("\nMay: ");
                for (STAVar must : mustTainted) {
                    System.out.print(must.toString() + ", ");
                }
                for (STAVar may : mayTainted) {
                    System.out.print(may.toString() + ", ");
                }
                System.out.println("\n---");
            }
        }
    }

    /**
     *
     */
    private static class STAJoin
            extends JoinOp.BinaryJoinOp<StaticTaintAnalysis.STALattice> {

        @Override
        STALattice apply(STALattice first, STALattice second) {
            return new STALattice();
        }
    }

    private static String source = "retSource";
    private static String sink = "sink";
    private STALattice lattice;

    /**
     * Constructs a data flow analysis.
     *
     * <p>Typical usage
     * <pre>
     * DataFlowAnalysis dfa = ...
     * dfa.analyze();
     * </pre>
     * <p>
     *
     * @param cfg The control flow graph object that this object performs
     *            on. Modification of the graph requires a separate call to
     *            {@link #analyze()}.
     * @see #analyze()
     */
    StaticTaintAnalysis(
            ControlFlowGraph<Node> cfg,
            Scope jsScope,
            AbstractCompiler compiler,
            SyntacticScopeCreator scopeCreator) {
        super(cfg, new STAJoin());
        lattice = new STALattice();
    }

    @Override
    boolean isForward() {
        return true;
    }

    @Override
    STALattice flowThrough(Node node, STALattice input) {
        STALattice out = new STALattice(input);
        doSTA(node, out, null);
        return out;
    }

    @Override
    STALattice createInitialEstimateLattice() {
        return lattice;
    }

    @Override
    STALattice createEntryLattice() {
        return lattice;
    }

    /**
     * If the variable name was changed this function
     * returns the original function name.
     * @param varName Name of the variable as String.
     * @return The original function name as String.
     */
    private static String getNormalizedVarName(String varName) {
        if (varName.indexOf('$') >= 0) {
            varName = varName.substring(0, varName.indexOf('$'));
        }
        return varName;
    }

    void printRes() {
        lattice.printRes();
    }

    private void printNode(Node n, String pre) {
        System.out.println(pre + n.getToken().name());

        for (Node c : n.children()) {
            printNode(c, pre + "  ");
        }
    }

    private void doSTAFunction(Node n, STALattice result) {
        // Add the function as a new top level scope.
        result.addFunction(new STAObj(n.getFirstChild().getString(), n.getLineno()));

        // If we have a non empty function body continue.
        if (n.hasXChildren(3)) {
            doSTA(n.getChildAtIndex(2), result, null);
        }
    }

    private void doSTAVariable(Node n, STALattice result) {
        Node varToken = n.getFirstChild();
        // Add the variable to the current function scope.
        STAVar var = new STAVar(
                StaticTaintAnalysis.getNormalizedVarName(varToken.getString()),
                n.getLineno(),
                STAState.UNTAINTED);

        result.addVariable(var);

        // The variable has an assignment.
        if (varToken.hasChildren()) {
            Node right = varToken.getFirstChild();
            switch (right.getToken()) {
                case NAME:
                    // Another variable is assigned.
                    STAVar other = result.findVar(StaticTaintAnalysis.getNormalizedVarName(right.getString()));
                    if (other != null) {
                        var.setParent(other);
                    }
                    break;
                case CALL:
                    // A function return value is assigned.
                    doSTACall(right, result, var);
                    break;
                case OBJECTLIT:
                    doSTAObject(right, result, var);
                    break;
                default:
                    doSTA(n.getFirstChild(), result, var);
            }
        }
    }

    private void doSTACall(Node n, STALattice result, STAVar var) {
        // Here we call a source.
        if (n.getFirstChild().getString().equals(StaticTaintAnalysis.source) && n.getSecondChild() == null) {
            if (var != null) {
                var.setSource(true);
            }
        }

        // Here we call a sink.
        // If the function we call is a sink the called variable is definitely tainted.
        else if (n.getFirstChild().getString().equals(StaticTaintAnalysis.sink) && n.getSecondChild() != null) {
            STAVar calledVar = result.findVar(n.getSecondChild().getString());
            if (calledVar != null) {
                calledVar.setState(STAState.MUST_TAINTED);
            }
        }
    }

    private void doSTAObject(Node n, STALattice result, STAVar var) {
        for (Node c : n.children()) {
            if (c.getToken() == STRING_KEY) {
                if (c.hasChildren()) {
                    Node right = c.getFirstChild();
                    switch (right.getToken()) {
                        case NAME:
                            STAVar other = result.findVar(n.getFirstChild().getString());
                            if (other != null) {
                                var.setParent(other);
                            }
                            break;
                        case OBJECTLIT:
                            doSTAObject(right, result, var);
                            break;
                        default:
                            doSTA(right, result, var);
                    }
                }
            }
        }
    }

    private void doSTA(Node n, STALattice result, STAVar var) {
//        while (n != null) {
//            printNode(n, "");
//
//            n = n.getNext();
//        }

        switch (n.getToken()) {
            case FUNCTION:
                doSTAFunction(n, result);
                break;
            case VAR:
                doSTAVariable(n, result);
                break;
            case IF:
                break;
            case CALL:
                doSTACall(n, result, var);
                break;
            case EXPR_RESULT:
                // Check the function that is called.
                doSTACall(n.getFirstChild(), result, var);
//            case ASSIGN:
//            case RETURN:
//            case BITOR:
//            case BITXOR:
//            case BITAND:
//            case EQ:
//            case NE:
//            case LT:
//            case LE:
//            case GT:
//            case GE:
//            case LSH:
//            case RSH:
//            case URSH:
//            case ADD:
//            case SUB:
//            case MUL:
//            case DIV:
//            case MOD:
//            case EXPONENT:
//            case NOT:
//            case BITNOT:
//            case POS:
//            case NEG:
//            case NEW:
//            case DELPROP:
//            case TYPEOF:
//            case GETPROP:
//            case GETELEM:
//            case NAME:
//            case NUMBER:
//            case STRING:
//            case NULL:
//            case THIS:
//            case FALSE:
//            case TRUE:
//            case SHEQ:
//            case SHNE:
//            case REGEXP:
//            case THROW:
//            case IN:
//            case INSTANCEOF:
//            case ARRAYLIT:
//            case OBJECTLIT:
//            case TRY:
//            case PARAM_LIST:
//            case COMMA:
//            case ASSIGN_BITOR:
//            case ASSIGN_BITXOR:
//            case ASSIGN_BITAND:
//            case ASSIGN_LSH:
//            case ASSIGN_RSH:
//            case ASSIGN_URSH:
//            case ASSIGN_ADD:
//            case ASSIGN_SUB:
//            case ASSIGN_MUL:
//            case ASSIGN_DIV:
//            case ASSIGN_MOD:
//            case ASSIGN_EXPONENT:
//            case HOOK:
//            case OR:
//            case AND:
//            case INC:
//            case DEC:
//            case SWITCH:
//            case CASE:
//            case DEFAULT_CASE:
//            case WHILE:
//            case DO:
//            case FOR:
//            case FOR_IN:
//            case BREAK:
//            case CONTINUE:
//            case WITH:
//            case CATCH:
//            case VOID:
//            case EMPTY:
//            case ROOT:
//            case BLOCK:
//            case LABEL:
//            case EXPR_RESULT:
//            case SCRIPT:
//            case GETTER_DEF:
//            case SETTER_DEF:
//            case CONST:
//            case DEBUGGER:
//            case LABEL_NAME:
//            case STRING_KEY:
//            case CAST:
//            case ARRAY_PATTERN:
//            case OBJECT_PATTERN:
//            case DESTRUCTURING_LHS:
//            case CLASS:
//            case CLASS_MEMBERS:
//            case MEMBER_FUNCTION_DEF:
//            case SUPER:
//            case LET:
//            case FOR_OF:
//            case FOR_AWAIT_OF:
//            case YIELD:
//            case AWAIT:
//            case IMPORT:
//            case IMPORT_SPECS:
//            case IMPORT_SPEC:
//            case IMPORT_STAR:
//            case EXPORT:
//            case EXPORT_SPECS:
//            case EXPORT_SPEC:
//            case MODULE_BODY:
//            case DYNAMIC_IMPORT:
//            case ITER_REST:
//            case OBJECT_REST:
//            case ITER_SPREAD:
//            case OBJECT_SPREAD:
//            case COMPUTED_PROP:
//            case TAGGED_TEMPLATELIT:
//            case TEMPLATELIT:
//            case TEMPLATELIT_SUB:
//            case TEMPLATELIT_STRING:
//            case DEFAULT_VALUE:
//            case NEW_TARGET:
//            case IMPORT_META:
//            case STRING_TYPE:
//            case BOOLEAN_TYPE:
//            case NUMBER_TYPE:
//            case FUNCTION_TYPE:
//            case PARAMETERIZED_TYPE:
//            case UNION_TYPE:
//            case ANY_TYPE:
//            case NULLABLE_TYPE:
//            case VOID_TYPE:
//            case REST_PARAMETER_TYPE:
//            case NAMED_TYPE:
//            case OPTIONAL_PARAMETER:
//            case RECORD_TYPE:
//            case UNDEFINED_TYPE:
//            case ARRAY_TYPE:
//            case GENERIC_TYPE:
//            case GENERIC_TYPE_LIST:
//            case ANNOTATION:
//            case PIPE:
//            case STAR:
//            case EOC:
//            case QMARK:
//            case BANG:
//            case EQUALS:
//            case LB:
//            case LC:
//            case COLON:
//            case INTERFACE:
//            case INTERFACE_EXTENDS:
//            case INTERFACE_MEMBERS:
//            case ENUM:
//            case ENUM_MEMBERS:
//            case IMPLEMENTS:
//            case TYPE_ALIAS:
//            case DECLARE:
//            case MEMBER_VARIABLE_DEF:
//            case INDEX_SIGNATURE:
//            case CALL_SIGNATURE:
//            case NAMESPACE:
//            case NAMESPACE_ELEMENTS:
//            case PLACEHOLDER1:
//            case PLACEHOLDER2:
//            case PLACEHOLDER3:
            default:
                break;
        }
    }

    void write() {
//        JsonObject json = new JsonObject();
//        JsonObject info = new JsonObject();
//        JsonArray mustReach = new JsonArray();
//        JsonArray mayReach = new JsonArray();
//
//        // doSth
//
//        info.add("sources_that_must_reach_sinks", mustReach);
//        info.add("sources_that_may_reach_sinks", mayReach);
//
//        json.add("getInformation@" + m_lines[0] + "-" + m_lines[1], info);
//
//        try {
//            Files.writeString(
//                    Paths.get(m_filename.replace(".js", "_out.js")),
//                    json.toString());
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
    }
}