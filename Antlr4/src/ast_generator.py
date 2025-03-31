import os
import re
import sys
import antlr4
import logging
import subprocess
import networkx as nx
from colorama import Fore, init

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.insert(0, parent_dir)

# print("Current directory:", current_dir)
# print("Parent directory added to Python path:", parent_dir)

from collections import defaultdict
from generated.SolidityLexer import SolidityLexer
from generated.SolidityParser import SolidityParser
from generated.SolidityListener import SolidityListener

class FunctionListener(SolidityListener):
    def __init__(self):
        self.contracts = defaultdict(lambda: {"isOwnable": False, "isAccessControl": False})
        self.current_contract = None
        self.current_function = None
        self.functions = {}
        self.call_graph = defaultdict(set)
        self.callers_graph = defaultdict(set)
        self.state_variables = set()
        self.modifiers = {}
        self.expression_dependencies = {}
        self.data_dependencies = {}
        self.control_stack = []
        self.control_dependencies = {}
   
    def enterContractDefinition(self, ctx: SolidityParser.ContractDefinitionContext):
        """
        If a contract is 'contract X is Ownable/AccessControl', we mark it.
        """
        self.current_contract = ctx.identifier().getText()
        # Check base contracts
        for spec in ctx.inheritanceSpecifier():
            base_name = spec.userDefinedTypeName().getText()
            
            if base_name == "Ownable":
                self.contracts[self.current_contract]["isOwnable"] = True
            if base_name == "AccessControl":
                self.contracts[self.current_contract]["isAccessControl"] = True

    def exitContractDefinition(self, ctx: SolidityParser.ContractDefinitionContext):
        self.current_contract = None
    
    def enterStateVariableDeclaration(self, ctx: SolidityParser.StateVariableDeclarationContext):
        # Add the variable to the set of state variable names
        for child in ctx.getChildren():
            if isinstance(child, SolidityParser.IdentifierContext):
                variable_name = child.getText()
                self.state_variables.add(variable_name)

    def enterFunctionDefinition(self, ctx:SolidityParser.FunctionDefinitionContext):
       # Attempt to figure out if it's a constructor, fallback, or receive
        fn_name = None
        fn_descriptor = ctx.functionDescriptor()

        # We'll track "function_kind" so we know if it's "constructor", "fallback", "receive", or normal
        function_kind = "function"
        is_constructor = False

        if fn_descriptor is not None:
            # Could be fallback, receive, or a named function
            if fn_descriptor.ConstructorKeyword() is not None:
            # It's a constructor
                fn_name = "constructor"
                function_kind = "constructor"
            elif fn_descriptor.FallbackKeyword() is not None:
                fn_name = "fallback"
                function_kind = "fallback"
            elif fn_descriptor.ReceiveKeyword() is not None:
                fn_name = "receive"
                function_kind = "receive"
            else:
                # normal or constructor by name
                # e.g. function <identifier>(...)
                for child in fn_descriptor.getChildren():
                    if isinstance(child, SolidityParser.IdentifierContext):
                        fn_name = child.getText()
                # If there's a constructorDefinition, it's a constructor
                if fn_descriptor and fn_descriptor.ConstructorKeyword():
                    is_constructor = True
                    fn_name = "constructor"
                    function_kind = "constructor"
        else:
            # If there's no functionDescriptor, it might be old-style constructor or fallback
            if fn_descriptor and fn_descriptor.ConstructorKeyword():
                is_constructor = True
                fn_name = "constructor"
                function_kind = "constructor"
            else:
                # Possibly fallback if no name found
                fn_name = "fallback"
                function_kind = "fallback"

        if not fn_name:
            fn_name = "anonymous_function"

        # We are entering a function
        self.current_function = fn_name

        # Initialize the function data
        self.functions[self.current_function] = {
            'calls': set(), 
            'state_variables': set(),
            'source': ctx.getText(),
            'modifiers': set(),
            
            # NEW FIELDS for role extraction:
            'function_kind': function_kind,     # function, constructor, fallback, receive
            'is_vulnerable': False,             # we'll set this to True if it's public/external or special
            'role_checks': set(),               # inline checks like require(...) referencing roles
        }

        # Ensure in call graphs
        if self.current_function not in self.call_graph:
            self.call_graph[self.current_function] = set()
        if self.current_function not in self.callers_graph:
            self.callers_graph[self.current_function] = set()

        # Check the function's modifiers for "public"/"external" or "onlyX/role" references
        function_visibility = "default"
        is_read_only = False
        modifier_list = ctx.modifierList()
        if modifier_list:
            for child in modifier_list.getChildren():
                if isinstance(child, SolidityParser.ModifierInvocationContext):
                    # e.g. onlyOwner, onlyRole(MINTER_ROLE)
                    modifier_name = child.getText()
                    self.functions[self.current_function]['modifiers'].add(modifier_name)
                else:
                    # Could be visibility keywords like public, external, payable
                    text = child.getText().lower()
                    if text in ["public", "external", "internal", "private"]:
                        function_visibility = text
                    if text in ["view", "pure"]:
                        is_read_only = True

        # Decide if it's vulnerable:
        #  - If it's constructor/fallback/receive => mark is_vulnerable = True
        #  - If it's "function" with public/external => likely vulnerable
        block = ctx.block()
        if function_kind in ("constructor", "fallback", "receive"):
            self.functions[self.current_function]['is_vulnerable'] = True
        elif function_kind == "function":
            if function_visibility in ("public", "external") and not is_read_only:
            # We treat it as potentially privileged => is_vulnerable
                self.functions[self.current_function]['is_vulnerable'] = True

        # Finally, parse the function body for dependencies if it exists
        if block:
            self.parseFunctionBody(block)


    def parseFunctionBody(self, body: SolidityParser.BlockContext):
        # Traverse the body AST to identify function calls and state variable accesses
        for expr in body.statement():  # assuming 'expression' is the method to get all expressions within the body
            current_dependencies = self.extractDataDependencies(expr, self.data_dependencies)

            # Store these dependencies (assuming you have a method or structure to store them)
            self.storeDependencies(expr, current_dependencies)

            # Update data_dependencies with variables modified or defined in the current expression
            self.updateDependencies(expr, self.data_dependencies)

        for stmt in body.statement():
            self.checkControlDependencies(stmt)

            if self.isControlStatement(stmt):
                # Push to control stack and process its body
                self.control_stack.append(stmt)
                self.processControlStatementBody(stmt)
                self.control_stack.pop()

    def checkControlDependencies(self, stmt):
        """
        If there's a control statement at the top of the stack,
        then the current statement has a control dependency on it.
        """
        if self.control_stack:
            control_stmt = self.control_stack[-1]  # get the control statement at the top
            if stmt not in self.control_dependencies:
                self.control_dependencies[stmt] = []
            self.control_dependencies[stmt].append(control_stmt)

    def isControlStatement(self, stmt):
        """
        Check if the statement is a control statement (like if, for, while, etc.)
        """
        return isinstance(stmt, (SolidityParser.IfStatementContext, SolidityParser.WhileStatementContext,
                                 SolidityParser.ForStatementContext))


    def processControlStatementBody(self, control_stmt):
        """
        Process the body of the control statement to capture dependencies within it.
        This can be a recursive process if there are nested control statements.
        """
        if isinstance(control_stmt, SolidityParser.IfStatementContext):
            # Handle 'if' and optional 'else'
            self.parseFunctionBodyForControlDependencies(control_stmt.ifBody)
            if control_stmt.elseBody:
                self.parseFunctionBodyForControlDependencies(control_stmt.elseBody)


    def extractDataDependencies(self, expr, data_dependencies):
        """
        Check if the expression has variables that were previously defined or modified.
        """
        dependencies = set()
        variables_in_expr = self.extractVariables(expr)  # Extract all variables in the current expression

        for var in variables_in_expr:
            if var in data_dependencies:
                dependencies.add(data_dependencies[var])  # Add the expression or statement this variable depends on

        return dependencies


    def updateDependencies(self, expr, data_dependencies):
        """
        Update the data_dependencies dictionary with variables that are modified or defined in the current expression.
        """
        modified_variables = self.extractModifiedVariables(expr)  # Extract variables that are modified in the current expression

        for var in modified_variables:
            data_dependencies[var] = expr  # Update the variable's dependency to the current expression

    def extractVariables(self, expr):
        return [variable.getText() for variable in expr.getTokens(SolidityParser.Identifier)]

    def extractModifiedVariables(self, expr):
        modified_vars = []

        # Check for assignments in the expression
        simple_stmt = expr.simpleStatement()
        if simple_stmt:
            variable = simple_stmt.expressionStatement()  # Assuming assignment() is a method within SimpleStatementContext
            if variable:
                modified_vars.append(variable.getText())
        # assignments = expr.assignment()
        # for assignment in assignments:
        #     # Get the left-hand side of the assignment which is typically the variable being modified
        #     variable = assignment.identifier()
        #     if variable:
        #         modified_vars.append(variable.getText())

        return modified_vars

    def storeDependencies(self, expr, dependencies):
        if expr not in self.expression_dependencies:
            self.expression_dependencies[expr] = set()

        self.expression_dependencies[expr].update(dependencies)

    def exitFunctionDefinition(self, ctx:SolidityParser.FunctionDefinitionContext):
        function_name = None

        function_descriptor = ctx.functionDescriptor()
        if function_descriptor:
            for child in function_descriptor.getChildren():
                if isinstance(child, SolidityParser.IdentifierContext):
                    function_name = child.getText()
                    break
        if function_name and function_name == self.current_function:
            # We are exiting the current function
            self.current_function = None

    def enterFunctionCall(self, ctx:SolidityParser.FunctionCallContext):
        if self.current_function:
            fn_data = self.functions[self.current_function]
            call_text = ctx.getText()
            # e.g. require(hasRole(MINTER_ROLE, msg.sender)), hasRole(MINTER_ROLE,msg.sender)
            # 1) Add to calls
            called_function = re.sub(r'\(.*\)$', '', call_text)
            fn_data['calls'].add(called_function)
            self.call_graph[self.current_function].add(called_function)
            self.callers_graph[called_function].add(self.current_function)

            # 2) If this function is "vulnerable", look for role checks
            if fn_data['is_vulnerable']:
                # Heuristic: if call_text has "hasRole" or "msg.sender", or if it's a require(...) containing them
                if called_function == "require":
                    # e.g. require(msg.sender == owner) or require(hasRole(X, msg.sender))
                    if "msg.sender" in call_text or "hasRole" in call_text:
                        fn_data['role_checks'].add(call_text)
                else:
                    # direct hasRole(...) or something referencing msg.sender
                    if "hasRole" in call_text or "msg.sender" in call_text:
                        fn_data['role_checks'].add(call_text)

    def enterIdentifier(self, ctx:SolidityParser.Identifier):
        if self.current_function:
            identifier = ctx.getText()
            if identifier and identifier in self.state_variables:
                self.functions[self.current_function]['state_variables'].add(identifier)
    def get_function_src(self, func):
        return self.get_functions().get(func, {}).get('source', '')

    def get_function_callers(self, func):
        return self.callers_graph.get(func, set())

    def get_function_callees(self, func):
        return self.call_graph.get(func, set())

    def get_functions(self):
        return self.functions

    def get_call_graph(self):
        return self.call_graph

    def get_callers_graph(self):
        return self.callers_graph

    def get_state_variables(self):
        return self.state_variables

    def get_related_state_variables(self, func):
        related_functions = defaultdict(set)

        for state_var in self.functions.get(func, {}).get('state_variables', set()):
            for fu, values in self.functions.items():
                if fu == func:
                    continue
                if state_var in values['state_variables']:
                    related_functions[state_var].add(fu)
        return related_functions
    
    def enterModifierDefinition(self, ctx: SolidityParser.ModifierDefinitionContext):
        # Extract the modifier name
        modifier_name = ctx.identifier().getText() if ctx.identifier() else None

        # Extract the modifier body (if it has one)
        modifier_body = ctx.block().getText() if ctx.block() else None
    
        if modifier_name:
            self.modifiers[modifier_name] = modifier_body
            print(f"Modifier Found: {modifier_name}")
            if modifier_body:
                print(f"Modifier Body: {modifier_body}")

    def get_modifier_body(self, modifier_name):
            #Retrieve the body of a modifier by its name.
            return self.modifiers.get(modifier_name, None)
    
    def display_modifiers(self):
        """
        Print all tracked modifiers.
        """
        print("\n--- Tracked Modifiers ---")
        for name, body in self.modifiers.items():
            print(f"Modifier: {name}")
            print(f"Body: {body if body else 'None'}\n")
    
    def get_summary(self):
        return {
            "contracts": dict(self.contracts),
            "functions": self.functions,
            "call_graph": self.call_graph,
            "callers_graph": self.callers_graph,
            "modifiers": self.modifiers,
            "state_variables": self.state_variables,
        }

"""""
def parse_solidity_file(file_path):
    
    Parse the Solidity file and produce the syntax tree with modifiers.
    
    # Read Solidity source code
    with open(file_path, 'r') as file:
        code = file.read()

    # Create an input stream for the lexer
    input_stream = antlr4.InputStream(code)
    lexer = SolidityLexer(input_stream)
    lexer.removeErrorListeners()
    token_stream = antlr4.CommonTokenStream(lexer)

    # Parse the token stream to generate the syntax tree
    parser = SolidityParser(token_stream)
    parser.removeErrorListeners()
    tree = parser.sourceUnit()

    # Walk the tree with the custom listener
    listener = ModifierListener()
    walker = antlr4.ParseTreeWalker()
    walker.walk(listener, tree)

    return listener
"""

def antlr_listener(f):
    with open(f, 'r') as file:
        code = file.read()

    input_stream = antlr4.InputStream(code)
    lexer = SolidityLexer(input_stream)
    lexer.removeErrorListeners()
    token_stream = antlr4.CommonTokenStream(lexer)
    parser = SolidityParser(token_stream)
    parser.removeErrorListeners()
    tree = parser.sourceUnit()

    listener = FunctionListener()
    walker = antlr4.ParseTreeWalker()
    walker.walk(listener, tree)

    return listener, tree, parser


# def print_ast(tree, parser):
#     print("\n--- Full AST Structure ---")
#     print(tree.toStringTree(recog=parser))

def print_pretty_ast(tree, parser, indent=0):
    
    #Recursively prints the AST in a neat, indented format.

    # Args:
    #     tree: The root node of the parse tree.
    #     parser: The parser used to generate the rule names.
    #     indent: The current indentation level.
    
    if tree.getChildCount() == 0:
        # Leaf node (token)
        print("  " * indent + f"- {tree.getText()}")
    else:
        # Internal node (rule)
        rule_name = parser.ruleNames[tree.getRuleIndex()] if hasattr(tree, "getRuleIndex") else "Unknown"
        print("  " * indent + f"+ {rule_name}")
        for i in range(tree.getChildCount()):
            print_pretty_ast(tree.getChild(i), parser, indent + 1)

def display_summary(summary):
    print("\n--- Parsing Summary ---")

    # 1) Contract-level info
    print("Contracts:")
    for c_name, c_info in summary["contracts"].items():
        print(f"  - {c_name}: Ownable={c_info['isOwnable']}, AccessControl={c_info['isAccessControl']}")

    # 2) Functions
    print("\nFunctions:")
    for func_name, details in summary["functions"].items():
        print(f"  - {func_name}:")
        print(f"      kind: {details.get('function_kind', 'function')}")
        print(f"      is_vulnerable: {details.get('is_vulnerable', False)}")
        print(f"      modifiers: {details.get('modifiers', set())}")
        print(f"      calls: {details['calls']}")
        print(f"      state_variables: {details['state_variables']}")
        
        # Show role checks if any
        role_checks = details.get('role_checks', set())
        if role_checks:
            print(f"      role_checks:")
            for rc in role_checks:
                print(f"        - {rc}")

    # 3) Call graph
    print("\nCall Graph:")
    for caller, callees in summary["call_graph"].items():
        callee_list = ", ".join(callees) if callees else "None"
        print(f"  - {caller} calls {callee_list}")

    # 4) Modifiers (only if you store them in self.modifiers)
    print("\nModifiers:")
    if summary["modifiers"]:
        print(", ".join(summary["modifiers"]))
    else:
        print("None")

    # 5) State vars
    print("\nState Variables:")
    if summary["state_variables"]:
        print(", ".join(summary["state_variables"]))
    else:
        print("None")

def parse_with_ast(file_path):
    """
    Runs the ANTLR-based FunctionListener on the given file
    and returns a summary dict that includes 'is_vulnerable' and 'role_checks'.
    """
    listener, tree, parser = antlr_listener(file_path)
    summary = listener.get_summary()  # The dictionary with 'contracts', 'functions', etc.
    return summary

def get_antlr_parsing(f):
    # Read the Solidity source code from a file
    with open(f, 'r') as file:
        code = file.read()

    # Create a stream of tokens from the source code
    input_stream = antlr4.InputStream(code)
    lexer = SolidityLexer(input_stream)
    token_stream = antlr4.CommonTokenStream(lexer)

    # Use the token stream to create an AST
    parser = SolidityParser(token_stream)
    tree = parser.sourceUnit()

    # Print the AST to the console
    # print(tree.toStringTree(recog=parser))

    for child in tree.getChildren():
        if type(child) is SolidityParser.ContractDefinitionContext:
            print(child)
            for c in child.getChildren():
                if type(c) is SolidityParser.ContractPartContext:
                    print(c)


if __name__ == '__main__':
   if len(sys.argv) > 1:
        solidity_file_path = sys.argv[1]  # Take the first command line argument after the script name
        listener, tree, parser = antlr_listener(solidity_file_path)
        
        # Optionally print AST
        print_pretty_ast(tree, parser)
        
        # Then display summary
        summary = listener.get_summary()
        display_summary(summary)

        # If you want to see any stored modifier bodies:
        listener.display_modifiers()
   else:
        print("Usage: python Main.py <path_to_solidity_file.sol>")
