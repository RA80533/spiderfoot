"""
This type stub file was generated by pyright.
"""

from _ast import AST, Add, And, BitAnd, BitOr, BitXor, Div, Eq, FloorDiv, Gt, GtE, If, In, Invert, Is, IsNot, LShift, Lt, LtE, Mod, Mult, Name, Not, NotEq, NotIn, Or, PyCF_ONLY_AST, RShift, Sub, UAdd, USub

"""
    ast
    ~~~

    This is a stripped down version of Armin Ronacher's ast module.

    :copyright: Copyright 2008 by Armin Ronacher.
    :license: Python License.
"""
BOOLOP_SYMBOLS = ...
BINOP_SYMBOLS = ...
CMPOP_SYMBOLS = ...
UNARYOP_SYMBOLS = ...
ALL_SYMBOLS = ...
def parse(expr, filename=..., mode=...): # -> AST:
    """Parse an expression into an AST node."""
    ...

def iter_fields(node): # -> Generator[tuple[Unknown, Any], None, None]:
    """Iterate over all fields of a node, only yielding existing fields."""
    ...

class NodeVisitor:
    """
    Walks the abstract syntax tree and call visitor functions for every node
    found.  The visitor functions may return values which will be forwarded
    by the `visit` method.

    Per default the visitor functions for the nodes are ``'visit_'`` +
    class name of the node.  So a `TryFinally` node visit function would
    be `visit_TryFinally`.  This behavior can be changed by overriding
    the `get_visitor` function.  If no visitor function exists for a node
    (return value `None`) the `generic_visit` visitor is used instead.

    Don't use the `NodeVisitor` if you want to apply changes to nodes during
    traversing.  For this a special visitor exists (`NodeTransformer`) that
    allows modifications.
    """
    def get_visitor(self, node): # -> Any | None:
        """
        Return the visitor function for this node or `None` if no visitor
        exists for this node.  In that case the generic visit function is
        used instead.
        """
        ...
    
    def visit(self, node): # -> Any | None:
        """Visit a node."""
        ...
    
    def generic_visit(self, node): # -> None:
        """Called if no explicit visitor function exists for a node."""
        ...
    


class NodeTransformer(NodeVisitor):
    """
    Walks the abstract syntax tree and allows modifications of nodes.

    The `NodeTransformer` will walk the AST and use the return value of the
    visitor functions to replace or remove the old node.  If the return
    value of the visitor function is `None` the node will be removed
    from the previous location otherwise it's replaced with the return
    value.  The return value may be the original node in which case no
    replacement takes place.

    Here an example transformer that rewrites all `foo` to `data['foo']`::

        class RewriteName(NodeTransformer):

            def visit_Name(self, node):
                return copy_location(Subscript(
                    value=Name(id='data', ctx=Load()),
                    slice=Index(value=Str(s=node.id)),
                    ctx=node.ctx
                ), node)

    Keep in mind that if the node you're operating on has child nodes
    you must either transform the child nodes yourself or call the generic
    visit function for the node first.

    Nodes that were part of a collection of statements (that applies to
    all statement nodes) may also return a list of nodes rather than just
    a single node.

    Usually you use the transformer like this::

        node = YourTransformer().visit(node)
    """
    def generic_visit(self, node):
        ...
    


class SourceGenerator(NodeVisitor):
    """
    This visitor is able to transform a well formed syntax tree into python
    sourcecode.  For more details have a look at the docstring of the
    `node_to_source` function.
    """
    def __init__(self, indent_with) -> None:
        ...
    
    def write(self, x): # -> None:
        ...
    
    def newline(self, n=...): # -> None:
        ...
    
    def body(self, statements): # -> None:
        ...
    
    def body_or_else(self, node): # -> None:
        ...
    
    def signature(self, node): # -> None:
        ...
    
    def decorators(self, node): # -> None:
        ...
    
    def visit_Assign(self, node): # -> None:
        ...
    
    def visit_AugAssign(self, node): # -> None:
        ...
    
    def visit_ImportFrom(self, node): # -> None:
        ...
    
    def visit_Import(self, node): # -> None:
        ...
    
    def visit_Expr(self, node): # -> None:
        ...
    
    def visit_FunctionDef(self, node): # -> None:
        ...
    
    def visit_ClassDef(self, node): # -> None:
        ...
    
    def visit_If(self, node): # -> None:
        ...
    
    def visit_For(self, node): # -> None:
        ...
    
    def visit_While(self, node): # -> None:
        ...
    
    def visit_With(self, node): # -> None:
        ...
    
    def visit_Pass(self, node): # -> None:
        ...
    
    def visit_Print(self, node): # -> None:
        ...
    
    def visit_Delete(self, node): # -> None:
        ...
    
    def visit_TryExcept(self, node): # -> None:
        ...
    
    def visit_TryFinally(self, node): # -> None:
        ...
    
    def visit_Global(self, node): # -> None:
        ...
    
    def visit_Nonlocal(self, node): # -> None:
        ...
    
    def visit_Return(self, node): # -> None:
        ...
    
    def visit_Break(self, node): # -> None:
        ...
    
    def visit_Continue(self, node): # -> None:
        ...
    
    def visit_Raise(self, node): # -> None:
        ...
    
    def visit_Attribute(self, node): # -> None:
        ...
    
    def visit_Call(self, node): # -> None:
        ...
    
    def visit_Name(self, node): # -> None:
        ...
    
    def visit_NameConstant(self, node): # -> None:
        ...
    
    def visit_arg(self, node): # -> None:
        ...
    
    def visit_Str(self, node): # -> None:
        ...
    
    def visit_Bytes(self, node): # -> None:
        ...
    
    def visit_Num(self, node): # -> None:
        ...
    
    def visit_Constant(self, node): # -> None:
        ...
    
    def visit_Tuple(self, node): # -> None:
        ...
    
    def sequence_visit(left, right): # -> (self: Unknown, node: Unknown) -> None:
        ...
    
    visit_List = ...
    visit_Set = ...
    def visit_Dict(self, node): # -> None:
        ...
    
    def visit_BinOp(self, node): # -> None:
        ...
    
    def visit_BoolOp(self, node): # -> None:
        ...
    
    def visit_Compare(self, node): # -> None:
        ...
    
    def visit_UnaryOp(self, node): # -> None:
        ...
    
    def visit_Subscript(self, node): # -> None:
        ...
    
    def visit_Slice(self, node): # -> None:
        ...
    
    def visit_ExtSlice(self, node): # -> None:
        ...
    
    def visit_Yield(self, node): # -> None:
        ...
    
    def visit_Lambda(self, node): # -> None:
        ...
    
    def visit_Ellipsis(self, node): # -> None:
        ...
    
    def generator_visit(left, right): # -> (self: Unknown, node: Unknown) -> None:
        ...
    
    visit_ListComp = ...
    visit_GeneratorExp = ...
    visit_SetComp = ...
    def visit_DictComp(self, node): # -> None:
        ...
    
    def visit_IfExp(self, node): # -> None:
        ...
    
    def visit_Starred(self, node): # -> None:
        ...
    
    def visit_Repr(self, node): # -> None:
        ...
    
    def visit_alias(self, node): # -> None:
        ...
    
    def visit_comprehension(self, node): # -> None:
        ...
    
    def visit_excepthandler(self, node): # -> None:
        ...
    


