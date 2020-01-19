package com.google.javascript.jscomp;

import com.google.javascript.jscomp.graph.LatticeElement;
import com.google.javascript.rhino.Node;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;

import static com.google.javascript.rhino.Token.*;

/**
 * Performs a static taint analysis for all variables.
 *
 * A variable may leak information (is tainted) to a
 * sink if it is a source or contains contents from a source.
 */
public class StaticTaintAnalysis
    extends DataFlowAnalysis<Node, StaticTaintAnalysis.STALattice> {

    /**
     * Stores two elements with same or different types.
     * @param <A>
     * @param <B>
     */
    public static class Pair<A, B> {
        private A first;
        private B second;

        public Pair(A first, B second) {
            super();
            this.first = first;
            this.second = second;
        }

        public A first() {
            return first;
        }

        public B second() {
            return second;
        }
    }

    /**
     *
     */
    static final class STALattice implements LatticeElement {

        public STALattice() {
        }
    }

    /**
     *
     */
    public enum STAState {
        UNDEFINED,
        TAINTED,
        UNTAINTED,
    }

    /**
     *
     */
    public enum STAType {
        UNDEFINED,
        SOURCE,
        SINK,
    }

    Pair<Boolean, Integer> source;
    Pair<Boolean, Integer> sink;
    HashMap<String, STAState> state;

    /**
     * Constructs a data flow analysis.
     *
     * <p>Typical usage
     * <pre>
     * DataFlowAnalysis dfa = ...
     * dfa.analyze();
     * </pre>
     * <p>
     * {@link #analyze()} annotates the result to the control flow graph by
     * means of {@link DiGraphNode#setAnnotation} without any
     * modification of the graph itself. Additional calls to {@link #analyze()}
     * recomputes the analysis which can be useful if the control flow graph
     * has been modified.
     *
     * @param targetCfg The control flow graph object that this object performs
     *                  on. Modification of the graph requires a separate call to
     *                  {@link #analyze()}.
     * @param joinOp
     * @see #analyze()
     */
    StaticTaintAnalysis(ControlFlowGraph<Node> targetCfg, JoinOp<STALattice> joinOp) {
        super(targetCfg, joinOp);
        state = new HashMap<String, STAState>();
    }

    @Override
    boolean isForward() {
        return false;
    }

    @Override
    STALattice flowThrough(Node node, STALattice input) {
        return null;
    }

    @Override
    STALattice createInitialEstimateLattice() {
        return null;
    }

    @Override
    STALattice createEntryLattice() {
        return null;
    }

    public void doSTA(Node n) {
        if (!n.isVar()) {
            return;
        }

//            if(!state.containsKey(n.getOriginalName())) {
//                state.put(STAState.UNDEFINED);
//            }

        switch (n.getToken()) {

            case RETURN:
            case BITOR:
            case BITXOR:
            case BITAND:
            case EQ:
            case NE:
            case LT:
            case LE:
            case GT:
            case GE:
            case LSH:
            case RSH:
            case URSH:
            case ADD:
            case SUB:
            case MUL:
            case DIV:
            case MOD:
            case EXPONENT:
            case NOT:
            case BITNOT:
            case POS:
            case NEG:
            case NEW:
            case DELPROP:
            case TYPEOF:
            case GETPROP:
            case GETELEM:
            case CALL:
            case NAME:
            case NUMBER:
            case STRING:
            case NULL:
            case THIS:
            case FALSE:
            case TRUE:
            case SHEQ:
            case SHNE:
            case REGEXP:
            case THROW:
            case IN:
            case INSTANCEOF:
            case ARRAYLIT:
            case OBJECTLIT:
            case TRY:
            case PARAM_LIST:
            case COMMA:
            case ASSIGN:
            case ASSIGN_BITOR:
            case ASSIGN_BITXOR:
            case ASSIGN_BITAND:
            case ASSIGN_LSH:
            case ASSIGN_RSH:
            case ASSIGN_URSH:
            case ASSIGN_ADD:
            case ASSIGN_SUB:
            case ASSIGN_MUL:
            case ASSIGN_DIV:
            case ASSIGN_MOD:
            case ASSIGN_EXPONENT:
            case HOOK:
            case OR:
            case AND:
            case INC:
            case DEC:
                break;
            case FUNCTION:
                Node function = n.getLastChild();
                String functionName = function.getFirstChild().getString();
                boolean hasParameters = function.getSecondChild().hasChildren();
                break;
            case IF:
            case SWITCH:
            case CASE:
            case DEFAULT_CASE:
            case WHILE:
            case DO:
            case FOR:
            case FOR_IN:
            case BREAK:
            case CONTINUE:
            case VAR:
            case WITH:
            case CATCH:
            case VOID:
            case EMPTY:
            case ROOT:
            case BLOCK:
            case LABEL:
            case EXPR_RESULT:
            case SCRIPT:
            case GETTER_DEF:
            case SETTER_DEF:
            case CONST:
            case DEBUGGER:
            case LABEL_NAME:
            case STRING_KEY:
            case CAST:
            case ARRAY_PATTERN:
            case OBJECT_PATTERN:
            case DESTRUCTURING_LHS:
            case CLASS:
            case CLASS_MEMBERS:
            case MEMBER_FUNCTION_DEF:
            case SUPER:
            case LET:
            case FOR_OF:
            case FOR_AWAIT_OF:
            case YIELD:
            case AWAIT:
            case IMPORT:
            case IMPORT_SPECS:
            case IMPORT_SPEC:
            case IMPORT_STAR:
            case EXPORT:
            case EXPORT_SPECS:
            case EXPORT_SPEC:
            case MODULE_BODY:
            case DYNAMIC_IMPORT:
            case ITER_REST:
            case OBJECT_REST:
            case ITER_SPREAD:
            case OBJECT_SPREAD:
            case COMPUTED_PROP:
            case TAGGED_TEMPLATELIT:
            case TEMPLATELIT:
            case TEMPLATELIT_SUB:
            case TEMPLATELIT_STRING:
            case DEFAULT_VALUE:
            case NEW_TARGET:
            case IMPORT_META:
            case STRING_TYPE:
            case BOOLEAN_TYPE:
            case NUMBER_TYPE:
            case FUNCTION_TYPE:
            case PARAMETERIZED_TYPE:
            case UNION_TYPE:
            case ANY_TYPE:
            case NULLABLE_TYPE:
            case VOID_TYPE:
            case REST_PARAMETER_TYPE:
            case NAMED_TYPE:
            case OPTIONAL_PARAMETER:
            case RECORD_TYPE:
            case UNDEFINED_TYPE:
            case ARRAY_TYPE:
            case GENERIC_TYPE:
            case GENERIC_TYPE_LIST:
            case ANNOTATION:
            case PIPE:
            case STAR:
            case EOC:
            case QMARK:
            case BANG:
            case EQUALS:
            case LB:
            case LC:
            case COLON:
            case INTERFACE:
            case INTERFACE_EXTENDS:
            case INTERFACE_MEMBERS:
            case ENUM:
            case ENUM_MEMBERS:
            case IMPLEMENTS:
            case TYPE_ALIAS:
            case DECLARE:
            case MEMBER_VARIABLE_DEF:
            case INDEX_SIGNATURE:
            case CALL_SIGNATURE:
            case NAMESPACE:
            case NAMESPACE_ELEMENTS:
            case PLACEHOLDER1:
            case PLACEHOLDER2:
            case PLACEHOLDER3:
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