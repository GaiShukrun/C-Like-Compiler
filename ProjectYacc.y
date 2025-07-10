%{
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>
#include <ctype.h>
#define TABLE_SIZE 100 
#define MAX_BUFFER_SIZE 10000000

jmp_buf exception_buf;
#define TRY if (setjmp(exception_buf) == 0)
#define CATCH else
#define THROW longjmp(exception_buf, 1)


int yylex(void);
int yyerror();
char *yytext;
int mainFunctionCount = 0;
int currentFunctionIsStatic = 0;
char error_msg[1000];

typedef struct node {
    char *token;
    struct node *left;
    struct node *right;
} node;

typedef struct {
    char *name;
    char *type;
} Parameter;

typedef struct {
    char *access;  // "public" or "private"
    char *name;
    char *returnType;
    int argCount;
    Parameter *args;  // Dynamic array of parameters
    int isStatic;  // 1 if static, 0 if not
} Function;

typedef struct Symbol {
    char *name;
    char *type;
    union {
    Function *func;  // For functions
    } data;
    struct Symbol *next;
} Symbol;

typedef struct {
    Symbol *table[TABLE_SIZE];
} SymbolTable;
typedef enum {
    FUNCTION_SCOPE,
    BLOCK_SCOPE
} ScopeType;

typedef struct Scope {
    SymbolTable table;
    char* functionName;
        ScopeType type;
    struct Scope* parent;
    struct Scope* NestedScope;
    struct Scope* UpperScope;
    
} Scope;

typedef struct TAC {
    char *op;
    char *arg1;
    char *arg2;
    char *result;
    struct TAC *next;
} TAC;

TAC *tac_first = NULL;
TAC *tac_last = NULL;
int temp_var_count = 0;
int label_count = 1;
int total_size = 0;
 
 
typedef struct {
    char *name;
    char *type;
} LocalVar;

typedef struct {
    char *name;
    char *type;
} Localfunc; 

Localfunc local_funcs[100];
LocalVar local_vars[100];  
int local_var_count = 0;
int local_func_count = 0 ;
int func_var_count = 0;
char instruction_buffer[MAX_BUFFER_SIZE];
int buffer_index = 0;
void generate_3ac_condition(node *condition, char *label_true, char *label_false) ;

char* generate_3ac_expr_for_condition(node *expr) ;
void add_to_buffer(const char* instruction) ;
void clear_buffer() ;
TAC* create_tac(char *op, char *arg1, char *arg2, char *result);
void add_tac(TAC *code);
char* new_temp();
char* new_label();
char* getLiteralType(const char* token) ;
void handleIdListWithInit1(node *idList, char *type);
void handleStringDecl(node *stringDecl);
void handleStringDeclList(node *stringDeclList);
char* generate_3ac_expr(node *expr);
void generate_3ac_if_block(node *tree);
void generate_3ac_for(node *tree);
void generate_3ac_do_while(node *tree);
void generate_3ac_while(node *tree);
void generate_3ac_if_else_single(node *tree);
void generate_3ac_if_else_block(node *tree);
void generate_3ac_if_single(node *tree);
void generate_3ac_if_else(node *tree);
char* generate_3ac_cond(node *expr);
void generate_3ac_declaration(node *tree) ;
void generate_3ac_block(node *tree);
void generate_3ac_function(node *tree);

void generate_3ac(node *tree);

void generate_3ac_and_condition(node *condition, char *label_true, char *label_false) ;
void generate_3ac_or_condition(node *condition, char *label_true, char *label_false);
int count_local_variables(node *tree) ;
int get_type_size(char *type);
int isLiteral(const char* token);
int count_parameters(node *tree);



Scope* currentScope = NULL;


SymbolTable symbolTable;
void insertFunctionGlobal(char *name, char *access, char *returnType, Parameter *args, int argCount, int isStatic);
void insertFunction1(char *name, char *access, char *returnType, Parameter *args, int argCount, int isStatic);
unsigned int hash(char *name);
void initSymbolTable();
void insert(char *name, char *type);
void insertIdList(node *idList, char *type);
Symbol *lookup(char *name);
int areTypesCompatible(char *type1, char *type2);
void semanticCheck(char *leftSide, char *rightSide,int line);
void printSymbolTable();
char* inferType(char *value) ;
char* checkExpressionType(node *expr);
void freeSymbolTable();
void freeSymbol(Symbol *symbol) ;
void printAllScopeTables() ;
void printNestedScopes(Scope* scope, int level, int subLevel);

node *syntax_tree;

Symbol *lookupGlobal(char *name);
Symbol *lookupInTable(SymbolTable *table, char *name);
Symbol *lookupCurrentScope(char *name);
void popScope();
void pushScope(char* functionName) ;
void postorderTraversal(node *tree) ;
void processNode(node *tree);
void handleDeclaration(node *tree);
void handleStringDeclaration(node *tree);
void handleAssignment(node *tree);
Symbol *lookupForcalls(char *name);
void handleFunctionDefinition(node *tree) ;
void handleNestedFunctionDefinition(node *tree); 
void handleBlockScope(node *tree) ;
void handleParameters(node *params);
void handleFunctionCall(node *tree) ;
void freeSymbol(Symbol *symbol);
void insertFunction(char *name, char *access, char *returnType, Parameter *args, int argCount, int isStatic);
void fillParameterArray(node *params, Parameter *args, int *index);
void countParameters(node *params, int *count) ;
Parameter* getParameters(node *params, int *count);
void fillIdList(char *type, node *idList, Parameter *args, int *index);
void countIdsInList(node *idList, int *count);
char* getFunctionReturnType(node *functionCall);
void checkFunctionArguments(Function *func, node *argList);
void countArguments(node *argList, int *count);
void checkFunctionReturnType(node *blockNode, char *expectedReturnType, char *funcName, int *hasReturn);
void checkArgumentsRecursive(Function *func, node *argNode, int *argIndex, int *paramGroupIndex, int *paramIndexInGroup);
void processFunctionBody(node *tree);
void handleIfStatement(node *tree);
void handleWhileLoop(node *tree);
void handleDoWhileLoop(node *tree);
void handleForLoop(node *tree);
char* handleHexLiteral(char *value);
int isPointerType(char *type);
char* getBaseType(char *pointerType);
void handleIdListWithInit(node *idList, char *type);

node *mknode(char *token, node *left, node *right);
void printtree(node *tree, int depth);
void preorder(node *tree);
extern int yylineno;
#define YYSTYPE struct node*

%}
%token NUM PLUS MINUS ID IF ELSE EQ LE GE '(' ')' '{' '}' DIV MUL ASS NEQ OR AND '!' '&' 
%token WHILE FOR VAR ARGS PUBLIC PRIVATE STATIC RETURN NULL_T VOID DO
%token BOOL CHAR INT DOUBLE FLOAT STRING INT_PTR CHAR_PTR DOUBLE_PTR FLOAT_PTR
%token BOOL_LITERAL CHAR_LITERAL INT_LITERAL HEX_LITERAL DOUBLE_LITERAL FLOAT_LITERAL STRING_LITERAL 
%left OR
%left AND
%nonassoc '<' '>' EQ LE GE NEQ
%left PLUS MINUS
%left DIV MUL
%right '!'
%nonassoc UMINUS
%nonassoc IFX
%nonassoc ELSE
%%
program: global_list { 
//printtree(mknode("Program", $1, NULL), 0);
syntax_tree = mknode("Program", $1, NULL);
}
       ;

global_list: global_list global_item { $$ = mknode("DONT", $1, $2); }
           | global_item { $$ = $1; }
           ;

global_item: function { $$ = mknode("DONT",mknode("(Function",$1,NULL),mknode(")",NULL,NULL));  }
 //          | stmt { $$ = mknode("DONT",mknode("(",$1,NULL),mknode(")",NULL,NULL));  }
 //          | declaration { $$ = $1; }
           ;

function: function_definition { $$ = $1; } 
        ;
function_call: ID '(' argument_list ')' { $$ = mknode("Function-Call", mknode("Function-Name",$1,NULL),
mknode("DONT",mknode("(Parameter_List",$3,NULL),mknode(")",NULL,NULL))); }
             ;
             
  

function_definition: access_modifier return_type ID '(' args parameter_list ')' optional_static block_stmt
                  {$$ = mknode("Function-Definition",
                                   mknode("DONT",
    mknode("Function-Modifier-return_type",$1,$2),mknode("Function-Name",$3,NULL)),  
    mknode("DONT",$8
    ,mknode("DONT",mknode("(Args>>",$6,NULL),mknode(")",$9,mknode("BLOCK)",NULL,NULL)))));}
                   ;
                   
nested_function_definition: access_modifier return_type ID '(' args parameter_list ')' optional_static block_stmt
                  {$$ = mknode("Nested-Function-Definition",mknode("DONT",mknode("Nested-Function-Modifier-return_type",$1,$2),mknode("Nested-Function-Name",$3,NULL)),mknode("DONT",$8,mknode("DONT",
mknode("(Args>>",$6,NULL),mknode(")",$9,mknode("BLOCK)",NULL,NULL)))));}
                   ;                
                   
args: ARGS{$$=$1;} 
    | 
     ;
     
optional_static: ':' STATIC { $$ = mknode("STATIC", NULL, NULL); }
               | /* empty */ { $$ = mknode("NON-STATIC", NULL, NULL); }
               ;
               
access_modifier: PUBLIC { $$ = mknode("Public",NULL,NULL); }
               | PRIVATE { $$ = mknode("Private",NULL,NULL); }
               ;

return_type: type { $$ = $1; }
           | VOID { $$ = mknode("void",$1,NULL); }
          
           ;

parameter_list: parameter_group{ $$ = $1;}
              |  parameter_group ';' parameter_list { $$ = mknode("DONT", $1, $3); }
              | /* empty */ { $$ = mknode("DONT", NULL, NULL); }
              ;

parameter_group: type ':' id_list { $$ = mknode("DONT", $1, $3); }
               ;

id_list: ID { $$ = $1; }
       | id_list ',' ID { $$ = mknode("DONT", $1, $3); }

       ;
       
stmt: ass { $$ = $1; }
    | ST { $$ = mknode("DONT",mknode("(",$1,NULL),mknode(")",NULL,NULL)); }
    | exp ';' { $$ = $1; }
    | RETURN exp ';' { $$ = mknode("RETURN", $2, NULL); }
    | RETURN ';' { $$ = mknode("RETURN", NULL, NULL); }
    ;
//single stmt for specific conditions like if(..)stmt , while(..)stmt etc.
single_stmt: ass { $$ = $1; }
           | exp ';' { $$ = $1;}
           | declaration { $$ = $1;}
           ;
           
//declaration: VAR type ':' id_list ';' { $$ = mknode("Declaration", mknode("(",$2, $4),mknode(")",NULL,NULL)); } |
 //            STRING string_decl_list ';' { $$ = mknode("String Declaration", $2, NULL); }
  //                ;

declaration: VAR type ':' id_list_with_init  ';' 
             { 
               $$ = mknode("Declaration", mknode("(",$2, $4),mknode(")",NULL,NULL));          
            }
           
           | STRING string_decl_list ';' 
             { 
               $$ = mknode("String Declaration", $2, NULL);               
             }
           | nested_function_definition { $$= mknode("Nested-Function",$1,NULL);}
           ;
id_list_with_init: id_with_init { $$ = $1; }
                 | id_list_with_init ',' id_with_init { $$ = mknode("DONT", $1, $3); }
                 ;

id_with_init: ID { $$ = $1; }
            | ID ASS exp { $$ = mknode("ID_INIT", $1, mknode("<-", $3, NULL)); }
            ;
string_decl_list: string_decl { $$ = $1; }
                | string_decl_list ',' string_decl { $$ = mknode("DONT", $1, $3); }
                ;

string_decl: ID '[' exp ']' 
           { 
             $$ = mknode("String", $1, $3); 
        
           }
           | ID '[' exp ']' ASS exp  
           { 
             $$ = mknode("String Assignment", $1, mknode("[",$3,mknode("]",$6,NULL)));
           }
           ;

        
type: BOOL {$$ =mknode("BOOL",NULL,NULL);}| CHAR {$$ =mknode("CHAR",NULL,NULL);}| INT {$$ =mknode("INT",NULL,NULL);} 
    | DOUBLE {$$ =mknode("DOUBLE",NULL,NULL);}|FLOAT {$$ =mknode("FLOAT",NULL,NULL);}
    | INT_PTR {$$ =mknode("INT Pointer",NULL,NULL);}  | CHAR_PTR {$$ =mknode("CHAR Pointer",NULL,NULL);}| DOUBLE_PTR {$$ =mknode("DOUBLE Pointer",NULL,NULL);}| FLOAT_PTR {$$ =mknode("FLOAT Pointer",NULL,NULL); }
    ;
    
ST: IF '(' exp ')' block_stmt { 
	      $$ = mknode("IF", $3, mknode("THEN", $5, mknode("BLOCK)",NULL,NULL)));
}

  | IF '(' exp ')' single_stmt { 
	  $$ = mknode("IF", $3, mknode("THEN", $5, NULL)); 
  }
  
  | IF '(' exp ')' block_stmt ELSE block_stmt{
	  $$=mknode("IF ELSE STMT",mknode("IF",$3,mknode("THEN",$5,mknode("BLOCK)",NULL,NULL))),mknode("ELSE",     $7,mknode("BLOCK)",NULL,NULL)) );
       }
  | IF '(' exp ')' single_stmt ELSE single_stmt { 
       $$ = mknode("IF-ELSE", $3, mknode("THEN", $5, mknode("ELSE", $7, NULL))); 
       }
  | IF '(' exp')' block_stmt ELSE single_stmt { 
       $$ = mknode("IF ELSE STMT",mknode("IF",$3,mknode("THEN",$5,mknode("BLOCK)",NULL,NULL))),mknode("ELSE",$7,NULL));
       }
  | IF '(' exp ')' single_stmt ELSE block_stmt { 
       $$ = mknode("IF-ELSE",mknode("IF", $3, mknode("THEN", $5, NULL)),mknode("ELSE", $7, mknode("BLOCK)",NULL,NULL)));
       }
  
  | WHILE '(' exp ')' block_stmt { 
      $$ = mknode("WHILE", $3, mknode("THEN", $5, mknode("BLOCK)",NULL,NULL))); 
       }
  | DO block_stmt  WHILE '(' exp ')' ';'
    { 
       $$ = mknode("DO-WHILE",mknode("BODY", $2,mknode("BLOCK)",NULL,NULL)),mknode("CONDITION", $5, NULL));
    }
   
  | FOR '(' ass_no_semi ';' exp ';' ass_no_semi ')' block_stmt 
    { 
    	$$ = mknode("FOR",$3,mknode("COND", $5, mknode("UPDATE", $7, mknode("THEN", $9, mknode("BLOCK)",NULL,NULL)))));
    }
  | FOR '(' ass_no_semi ';' exp ';' ass_no_semi ')' stmt
    { $$ = mknode("FOR", $3, mknode("COND", $5,mknode("UPDATE", $7, mknode("THEN", $9, NULL))));

    };
 
block_stmt: '{' declarations statements '}'  { $$ = mknode("(BLOCK", $2, $3); }
//block_stmt: '{' global_list '}' { $$ = mknode("(BLOCK", $2, NULL); }
          ;
          
declarations: declaration declarations { $$ = mknode("DONT", $1, $2); }
            | /* empty */ { $$ = mknode("DONT", NULL, NULL); }
            ;

statements: stmt statements { $$ = mknode("DONT", $1, $2); }
	  | '{'declarations statements '}' statements { $$ =mknode("{BLOCK",mknode("",$2,$3),mknode("}",$5,NULL));}
          | /* empty */ { $$ = mknode("DONT", NULL, NULL); }
          ; 
ass: ID ASS exp ';' 
     { 
       $$ = mknode("ASSIGN", $1, mknode("<-",$3,NULL)); 
     }
      | MUL ID ASS exp ';'
    {
      $$ = mknode("ASSIGN_DEREF", $2, mknode("<-",$4,NULL));
    }
    | ID '[' exp ']' ASS exp ';'
     {
       $$ = mknode("ASSIGN", mknode("ARRAY_INDEX", $1, $3), mknode("<-",$6,NULL));
     }
  
   ;
ass_no_semi: ID ASS exp { 
        $$ = mknode("ASSIGN", $1, mknode("<-",$3,NULL)); 
        }
           | 
            | MUL ID ASS exp 
    {
      $$ = mknode("ASSIGN_DEREF", $2, mknode("<-",$4,NULL));
    }
    | ID '[' exp ']' ASS exp
     {
       $$ = mknode("ASSIGN", mknode("ARRAY_INDEX", $1, $3), mknode("<-",$6,NULL));
     }
           ;


exp: exp PLUS exp { $$ = mknode("+", $1, $3); }
   | exp MINUS exp { $$ = mknode("-", $1, $3); }
   | exp MUL exp { $$ = mknode("*", $1, $3); }
   | exp DIV exp { $$ = mknode("/", $1, $3); }
   | '(' exp ')' { $$ = mknode("(",$2,$3); } // You asked to print ( and ) for indentation  purposes ,
//so when actually  ( and ) come by in a token , i will print the actual name of ( and ) so we can differentiate between indentation and regular use of ( and ).
   |exp '<' exp { $$ = mknode("<", $1, $3); }
   | exp '>' exp { $$ = mknode(">", $1, $3); }
   | exp EQ exp { $$ = mknode("==", $1, $3); }
   | exp LE exp { $$ = mknode("<=", $1, $3); }
   | exp GE exp { $$ = mknode(">=", $1, $3); }
   | exp NEQ exp { $$ = mknode("!=",$1,$3);}
   | '!'exp { $$ = mknode("!",$2,NULL);}
   | exp AND exp {$$ = mknode("&&",$1,$3);}
   | exp OR exp {$$ = mknode("||",$1,$3);}
   | MINUS exp %prec UMINUS { $$ = mknode("UMINUS", $2, NULL); }
   | INT_LITERAL { $$ = $1; }
   | HEX_LITERAL { $$ = $1; }
   | DOUBLE_LITERAL { $$ = $1; }
   | FLOAT_LITERAL { $$ = $1; }
   | BOOL_LITERAL { $$ = $1; }
   | CHAR_LITERAL { $$ = $1; }
   | STRING_LITERAL { $$ = $1; }
   | ID '[' exp ']' { $$ = mknode("ARRAY_INDEX", $1, $3); }
   | '&' ID '[' exp ']' { $$ = mknode("ADDR_ARRAY_ELEM", $2, $4); }
   | '&' ID { $$ = mknode("& ADDRESS", $2, NULL); }
   | ID { $$ = $1; }
   | MUL '(' exp ')' { $$ = mknode("Derefernce", $3, NULL); }
   | MUL ID {$$ = mknode("Derefernce",$2,NULL);}
   | NULL_T { $$ = mknode("NULL", NULL, NULL); }
   | function_call { $$ = $1; }
   | '|'ID'|' {
      // $$ = $2;
{ $$ = mknode("String-Length", $2, NULL); }
   }
   ;

argument_list: argument_list ',' exp { $$ = mknode("DONT", $1, $3); }
             | exp { $$ = $1; }
             | /* empty */ { $$ = mknode("DONT", NULL, NULL); }
             ;
%%
#include "lex.yy.c"
int main() {
    pushScope("global");  // Initialize global scope
    TRY {
        int result = yyparse();
        mainFunctionCount = 0;
        if (result == 0) { 

            postorderTraversal(syntax_tree);
          // printtree(syntax_tree, 0);
      generate_3ac(syntax_tree);  // Generate 3AC
            
        }
    } CATCH {
        fprintf(stderr, "%s\n", error_msg);
        
    }
    while (currentScope != NULL) {
        popScope();  // Clean up all scopes
    }
    return 0;
}
void printtree(node *tree, int depth) {
    if (tree == NULL) return;
    if(strcmp(tree->token,"DONT") == 0 ){	  
    }else{
       for (int i = 0; i < depth; ++i){ 
            printf(" ");
        }
        printf("%s\n", tree->token);
    }
    if (tree->left != NULL) {
        printtree(tree->left, depth + 1);
    }
    // Print right child if exists
    if (tree->right != NULL) {
        printtree(tree->right, depth + 1);
    }
}
void preorder(node *tree) {
    if (tree != NULL) {
        printf("%s\n", tree->token);
        preorder(tree->left);
        preorder(tree->right);
    }
}
int yyerror(char *msg) {
    snprintf(error_msg, sizeof(error_msg), "Parse error at line %d: %s near '%s'\n", yylineno, msg, yytext);
   // fprintf(stderr, "Parse error at line %d: %s near '%s'\n", yylineno, msg, yytext);
    THROW;
}
node *mknode(char *token, node *left, node *right) {
    node *newnode = (node*)malloc(sizeof(node));
    char *newstr = (char*)malloc(strlen(token) + 1);
    strcpy(newstr, token);
    newnode->left = left;
    newnode->right = right;
    newnode->token = newstr;
    return newnode;
}
unsigned int hash(char *name) {
    unsigned int hashval = 0;
    for (int i = 0; name[i] != '\0'; i++) {
        hashval = 31 * hashval + name[i];
    }
    return hashval % TABLE_SIZE;
}

void initSymbolTable() {
    for (int i = 0; i < TABLE_SIZE; i++) {
        symbolTable.table[i] = NULL;
    }
}

void insert(char *name, char *type) {
    if (strcmp(name, "DONT") == 0) return; 
   // printf("AAAAAA '%s'\n",currentScope->functionName);
    
        unsigned int index = hash(name);
        Symbol *newSymbol = (Symbol *)malloc(sizeof(Symbol));
        newSymbol->name = strdup(name);
        if (strstr(type, "Pointer") != NULL) {
            newSymbol->type = strdup(type);
        } else {
            newSymbol->type = strdup(type);
        }
        newSymbol->next = currentScope->table.table[index];
        currentScope->table.table[index] = newSymbol;
     // printf("Debug: Inserted variable '%s' of type '%s' into scope '%s'\n", name, type, currentScope->functionName);
   
}
void insertIdList(node *idList, char *type) {
   // printf("insertIdList\n");
    if (idList == NULL) return;
    if (strcmp(idList->token, "DONT") != 0) {
        if (strcmp(idList->token, "String") == 0) {
            // This is a string declaration
            insert(idList->left->token, "STRING");
        } else {
            
            insert(idList->token, type);
        }
    } else {
        insertIdList(idList->left, type);
        insertIdList(idList->right, type);
    }
}
//*
Symbol *lookup(char *name) {
    Scope* currentScopePtr = currentScope;
 
    while (currentScopePtr != NULL) {
        // First, check the current scope's symbol table
        Symbol* symbol = lookupInTable(&currentScopePtr->table, name);
        if (symbol) return symbol;
        
        // If this is a function scope, check its parameters
        if (currentScopePtr->type == FUNCTION_SCOPE) {
            Symbol *sym = lookupGlobal(currentScopePtr->functionName);
            if (sym && strcmp(sym->type, "FUNCTION") == 0) {
                Function *func = sym->data.func;
                for (int i = 0; i < func->argCount; i++) {
                    if (strcmp(func->args[i].name, name) == 0) {
                        // Create a temporary symbol for the parameter
                        Symbol *paramSym = malloc(sizeof(Symbol));
                        paramSym->name = strdup(func->args[i].name);
                        paramSym->type = strdup(func->args[i].type);
                        return paramSym;
                    }
                }
            }
        }
        
        // Move to parent scope
        currentScopePtr = currentScopePtr->parent;
    }
    
    // If not found in the direct ancestry, check nested scopes
    currentScopePtr = currentScope;
    while (currentScopePtr != NULL) {
        Scope* nestedScope = currentScopePtr->NestedScope;
        while (nestedScope != NULL) {
            Symbol* symbol = lookupInTable(&nestedScope->table, name);
            if (symbol) return symbol;
            nestedScope = nestedScope->UpperScope;
        }
        currentScopePtr = currentScopePtr->parent;
    }
    
    // Variable not found in any accessible scope
    return NULL;
}
Symbol *lookupCurrentScope(char *name) {
    return lookupInTable(&currentScope->table, name);
}

Symbol *lookupInTable(SymbolTable *table, char *name) {
    unsigned int index = hash(name);
    Symbol *current = table->table[index];
    while (current != NULL) {
        if (strcmp(current->name, name) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

int areTypesCompatible(char *type1, char *type2) {
    // First, handle the case where the types are exactly the same
    if (strcmp(type1, type2) == 0) return 1;
    
    // Handle NULL assignment to pointers
    if (strcmp(type1, "NULL") == 0 && isPointerType(type2)) return 1;
    if (strcmp(type2, "NULL") == 0 && isPointerType(type1)) return 1;
    
    // Handle pointer types
    if (isPointerType(type1) && isPointerType(type2)) {
        // Remove "Pointer" from both types and compare the base types
        char *baseType1 = strtok(strdup(type1), " ");
        char *baseType2 = strtok(strdup(type2), " ");
        int result = strcmp(baseType1, baseType2) == 0;
        free(baseType1);
        free(baseType2);
        return result;
    }
    
    // Handle other special cases (like HEX and INT compatibility)
    if (strcmp(type1, "HEX") == 0 && strcmp(type2, "INT") == 0) return 1;
    if (strcmp(type1, "INT") == 0 && strcmp(type2, "HEX") == 0) return 1;
    
    // If none of the above conditions are met, the types are not compatible
    return 0;
}


void semanticCheck(char *leftSide, char *rightSide, int line) {
    Symbol *leftSymbol = lookup(leftSide);

    if (leftSymbol == NULL) {
         snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d:  Identifier '%s' is not declared\n", yylineno,leftSide);
        //fprintf(stderr, "Semantic Error: Variable '%s' is not declared\n", leftSide);
        THROW;
    }
    
    char *rightType;
    if (strcmp(rightSide, "UNKNOWN") == 0) {
        snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Unable to determine type of right-hand side expression\n", yylineno);
        //fprintf(stderr, "Semantic Error at line %d: Unable to determine type of right-hand side expression\n", line);
        THROW;
    } else {
        rightType = rightSide;
    }
    
    //printf("Debug: Left side '%s' has type '%s'\n", leftSide, leftSymbol->type);
    //printf("Debug: Right side has type '%s'\n", rightType);
    //!
    if (!areTypesCompatible(leftSymbol->type, rightType)) {
     snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Type mismatch in assignment.. '%s' (%s) <- '%s'\n",
                yylineno, leftSide, leftSymbol->type, rightType);
      //  fprintf(stderr, "Semantic Error at line %d: Type mismatch in assignment. '%s' (%s) <- '%s'\n",
        //        line, leftSide, leftSymbol->type, rightType);
        THROW;
    }
}

char* inferType(char *value) {
    if (strcmp(value, "NULL") == 0 || strcmp(value, "NULL_T") == 0) {
        return "NULL";
    }
   
    // Check if it's a string literal
    if (value[0] == '"' && value[strlen(value)-1] == '"') {
        return "STRING";
    }
    
    // Check if it's a boolean literal
    if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0) {
   
        return "BOOL";
    }
    
    // Check if it's a char literal
    if (value[0] == '\'' && value[2] == '\'' && strlen(value) == 3) {
        return "CHAR";
    }
    
    // Check if it's a hexadecimal literal
    if (strlen(value) > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        char *endptr;
        strtol(value, &endptr, 16);
        if (*endptr == '\0') {
            return "INT"; // Hex literals are typically treated as integers
        }
    }
    
    // Check if it's a float literal
    if ((strchr(value, 'f') != NULL || strchr(value, 'F') != NULL )&& strchr(value, '.') != NULL ) {
        char *endptr;
        strtof(value, &endptr);
        if (*endptr == 'f' || *endptr == 'F') {
           
            return "FLOAT";
        }
    }
    char *hexType = handleHexLiteral(value);
    if (strcmp(hexType, "HEX") == 0) {
        return hexType;
    }
    
    // Check if it's a double literal
    if (strchr(value, '.') != NULL || strchr(value, 'e') != NULL || strchr(value, 'E') != NULL) {
        char *endptr;
        strtod(value, &endptr);
        if (*endptr == '\0') {
            return "DOUBLE";
        }
    }
    
    // Check if it's an integer literal
    char *endptr;
    strtol(value, &endptr, 10);
    if (*endptr == '\0') {
        return "INT";
    }
    
    
    // If it's not a literal, it might be an identifier or an expression
    Symbol *sym = lookup(value);
    if (sym != NULL) {
        return sym->type;
    }
    
    // If we can't infer the type, return "UNKNOWN"
    return "UNKNOWN";
}

char* checkExpressionType(node *expr) {

    if (expr == NULL) return "UNKNOWN";
    if (strcmp(expr->token, "NULL") == 0 || strcmp(expr->token, "NULL_T") == 0) {
        return "NULL";
    }
  
   //printf("checkExpressionType\n");

    if (strcmp(expr->token, "Function-Call") == 0) return getFunctionReturnType(expr);
if( strcmp(expr->token, "(") == 0){
      return checkExpressionType(expr->left);

}
    if (expr->left == NULL && expr->right == NULL) {
   
        Symbol *sym = lookup(expr->token);
        if (sym != NULL) {
          //  printf("Debug: Found symbol '%s' of type '%s'\n", sym->name, sym->type);
            return sym->type;
       }else  {
            // Check if it's a literal
            
            char* literalType = inferType(expr->token);
            //printf("literal  '%s' of type '%s' \n",expr->token,literalType);
            if (strcmp(literalType, "UNKNOWN") != 0) {
               // printf("Debug: Inferred literal type '%s' for token '%s'\n", literalType, expr->token);
                return literalType;
            }else{
           // checkFunctionReturnType(node *blockNode, , currentScope->functionName, 1)
             
            // If it's not a literal and not in symbol table, it's an undeclared variable
        
            
            }
        }
    
  }
  
    Symbol *sym;
    char *ptrType, *leftType, *rightType;

    switch(expr->token[0]) {
        case 'S':
            if (strcmp(expr->token, "String-Length") == 0) {
                if (!expr->left) {
                    fprintf(stderr, "Error at line %d: String-Length node has no child\n", yylineno);
                    return "UNKNOWN";
                }
                sym = lookup(expr->left->token);
                if (!sym) {
                 snprintf(error_msg, sizeof(error_msg),  "Semantic Error at line %d: Undeclared variable '%s' used in string length operation\n", yylineno, expr->left->token);
      
                    
                    THROW;
                }
                if (strcmp(sym->type, "STRING") != 0) {
                snprintf(error_msg, sizeof(error_msg),  "Semantic Error at line %d: | | operator can only be used with strings, got %s for variable '%s'\n", yylineno, sym->type, expr->left->token);
                   
                    THROW;
                }
                return "INT";
            }
            if (strcmp(expr->token, "String-Length-of") == 0) return "INT";
            break;
        case 'A':
            if (strcmp(expr->token, "ARRAY_INDEX") == 0 || strcmp(expr->token, "ADDR_ARRAY_ELEM") == 0) {
                sym = lookup(expr->left->token);
                if (!sym) {
                 snprintf(error_msg, sizeof(error_msg),  "Semantic Error at line %d: Undeclared array '%s'\n", yylineno, expr->left->token);
                //    fprintf(stderr, "Semantic Error at line %d: Undeclared array '%s'\n", yylineno, expr->left->token);
                    THROW;
                }
                if (strcmp(sym->type, "STRING") == 0) {
                    return (strcmp(expr->token, "ARRAY_INDEX") == 0) ? "CHAR" : "CHAR Pointer";
                }
                ptrType = malloc(strlen(sym->type) + 8);
                sprintf(ptrType, "%s%s", sym->type, (strcmp(expr->token, "ARRAY_INDEX") == 0) ? "" : " Pointer");
                return ptrType;
            }
            break;
        case '&':
            if (strcmp(expr->token, "& ADDRESS") == 0) {
                if (!expr->left) {
                    snprintf(error_msg, sizeof(error_msg),  "Semantic Error at line %d: Address-of operator used without an operand\n",yylineno);
                  //  fprintf(stderr, "Semantic Error at line %d: Address-of operator used without an operand\n", yylineno);
                    THROW;
                }
                if (strcmp(expr->left->token, "ARRAY_INDEX") == 0) {
                    Symbol *arraySym = lookup(expr->left->left->token);
                    if (arraySym && strcmp(arraySym->type, "STRING") == 0) {
                        return "CHAR Pointer";
                    }
                }
                sym = lookup(expr->left->token);
                if (!sym) {
                  snprintf(error_msg, sizeof(error_msg),  "Semantic Error at line %d: Cannot take address of undeclared variable '%s'\n", yylineno, expr->left->token);
                    //fprintf(stderr, "Semantic Error at line %d: Cannot take address of undeclared variable '%s'\n", yylineno, expr->left->token);
                    THROW;
                }

                // Check for allowed types
                if (strcmp(sym->type, "INT") == 0 ||
                    strcmp(sym->type, "CHAR") == 0 ||
                    strcmp(sym->type, "FLOAT") == 0 ||
                    strcmp(sym->type, "DOUBLE") == 0) {
                    ptrType = malloc(strlen(sym->type) + 8);
                    sprintf(ptrType, "%s Pointer", sym->type);
                    return ptrType;
                }
	snprintf(error_msg, sizeof(error_msg),  "Semantic Error at line %d: Address-of operator can only be applied to INT, CHAR, FLOAT, DOUBLE, or string array elements. Got %s\n", yylineno, sym->type);
                // If we reach here, the type is not allowed
               // fprintf(stderr, "Semantic Error at line %d: Address-of operator can only be applied to INT, CHAR, FLOAT, DOUBLE, or string array elements. Got %s\n", yylineno, sym->type);
                THROW;
            }
            break;
        case 'D':
              if (strcmp(expr->token, "DONT") == 0) {
                if (strcmp(expr->left->token, "Left Parenthesis") == 0 && 
                    strcmp(expr->right->token, "Right Parenthesis") == 0) {
                    return checkExpressionType(expr->left->left);
                }
               
             }
            if (strcmp(expr->token, "Derefernce") == 0 || strcmp(expr->token, "DEREF") == 0) {
                leftType = (expr->token[0] == 'D') ? checkExpressionType(expr->left) : expr->left->token;
                sym = (expr->token[0] == 'D') ? NULL : lookup(leftType);
                if (sym && !isPointerType(sym->type)) {
                snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Cannot dereference non-pointer type '%s' for variable '%s'\n",
                            yylineno, sym->type, expr->left->token);
                  //  fprintf(stderr, "Semantic Error at line %d: Cannot dereference non-pointer type '%s' for variable '%s'\n",
                         //   yylineno, sym->type, expr->left->token);
                    THROW;
                }
                if (!sym && !isPointerType(leftType)) {
                snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Cannot dereference non-pointer type '%s'\n",yylineno, leftType);
             //       fprintf(stderr, "Semantic Error at line %d: Cannot dereference non-pointer type '%s'\n",yylineno, leftType);
                    THROW;
                }
                return getBaseType(sym ? sym->type : leftType);
            }
            break;
    }

    if (expr->left && !expr->right) {
        if (strcmp(expr->token, "!") == 0) {
            leftType = checkExpressionType(expr->left);
            if (strcmp(leftType, "BOOL") != 0) {
              snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Logical NOT (!) can only be applied to boolean expressions, got %s\n", yylineno, leftType);
           //     fprintf(stderr, "Semantic Error at line %d: Logical NOT (!) can only be applied to boolean expressions, got %s\n", yylineno, leftType);
                THROW;
            }
            return "BOOL";
        }
        if (strcmp(expr->token, "UMINUS") == 0) return checkExpressionType(expr->left);
    }
	
    leftType = checkExpressionType(expr->left);
    rightType = checkExpressionType(expr->right);
     
    if (strcmp(expr->token, "+") == 0 || strcmp(expr->token, "-") == 0 || strcmp(expr->token, "UMINUS")==0) {
        if ((isPointerType(leftType) && strcmp(rightType, "INT") == 0) ||
            (strcmp(leftType, "INT") == 0 && isPointerType(rightType))) {
            return isPointerType(leftType) ? leftType : rightType;
        }
        int doubleCount = 0;
        int hasFloat = 0;
        int allInt = 1;

        if (strcmp(leftType, "DOUBLE") == 0) doubleCount++;
        else if (strcmp(leftType, "FLOAT") == 0) hasFloat = 1;
        else if (strcmp(leftType, "INT") != 0) allInt = 0;

        if (strcmp(rightType, "DOUBLE") == 0) doubleCount++;
        else if (strcmp(rightType, "FLOAT") == 0) hasFloat = 1;
        else if (strcmp(rightType, "INT") != 0) allInt = 0;

        if (doubleCount > 1) return "FLOAT";
        if (doubleCount == 1) return "DOUBLE";
        if (hasFloat) return "FLOAT";
        if (allInt) return "INT";
         //printf("left: '%s' right: '%s'\n ",leftType,rightType);
         if( strcmp(leftType,rightType) != 0 ){
         	snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: cannot make %s  operator with %s and %s\n", yylineno,expr->token,leftType,rightType);

        THROW;
		}else {
				return "CHAR";
			}
    }
    else if (strcmp(expr->token, "*") == 0 || strcmp(expr->token, "/") == 0) {
        int doubleCount = 0;
        int hasFloat = 0;
        int allInt = 1;

        if (strcmp(leftType, "DOUBLE") == 0) doubleCount++;
        else if (strcmp(leftType, "FLOAT") == 0) hasFloat = 1;
        else if (strcmp(leftType, "INT") != 0) allInt = 0;

        if (strcmp(rightType, "DOUBLE") == 0) doubleCount++;
        else if (strcmp(rightType, "FLOAT") == 0) hasFloat = 1;
        else if (strcmp(rightType, "INT") != 0) allInt = 0;

        if (doubleCount > 0) return "DOUBLE";
        if (hasFloat) return "FLOAT";
        if (allInt) return "INT";
	      	snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: cannot make %s  operator with %s and %s\n", yylineno,expr->token,leftType,rightType);
      //  fprintf(stderr, "Semantic Error at line %d: Invalid operands for arithmetic operation\n", yylineno);
        THROW;
    }

    else if (strcmp(expr->token, "<") == 0 || strcmp(expr->token, ">") == 0 ||
             strcmp(expr->token, "<=") == 0 || strcmp(expr->token, ">=") == 0 ||
             strcmp(expr->token, "==") == 0 || strcmp(expr->token, "!=") == 0 ||
             strcmp(expr->token, "&&") == 0 || strcmp(expr->token, "||") == 0) {

        if (strcmp(expr->token, "&&") == 0 || strcmp(expr->token, "||") == 0) {
            if (strcmp(leftType, "BOOL") != 0) {
            	 snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Left operand of %s must be boolean, got %s\n",
                        yylineno, expr->token, leftType);
              //  fprintf(stderr, "Semantic Error at line %d: Left operand of %s must be boolean, got %s\n",
                    //    yylineno, expr->token, leftType);
                THROW;
            }
            if (strcmp(rightType, "BOOL") != 0) {
           snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Right operand of %s must be boolean, got %s\n",
                        yylineno, expr->token, rightType);  
                //fprintf(stderr, "Semantic Error at line %d: Right operand of %s must be boolean, got %s\n",
                  //      yylineno, expr->token, rightType);
                THROW;
            }
            return "BOOL";
        }

        if (strcmp(expr->token, "==") == 0 || strcmp(expr->token, "!=") == 0) {
            if (strcmp(leftType, "NULL") == 0 || strcmp(rightType, "NULL") == 0) {
                if (strcmp(leftType, "NULL") == 0 && (isPointerType(rightType) || strcmp(rightType, "NULL") == 0)) {
                    return "BOOL";
                }
                if (strcmp(rightType, "NULL") == 0 && (isPointerType(leftType) || strcmp(leftType, "NULL") == 0)) {
                    return "BOOL";
                }
                snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Invalid comparison with NULL. Got %s and %s\n",
                        yylineno, leftType, rightType);  
                //fprintf(stderr, "Semantic Error at line %d: Invalid comparison with NULL. Got %s and %s\n",
                   //     yylineno, leftType, rightType);
                THROW;
            }
            if ((strcmp(leftType, "CHAR") == 0 && strcmp(rightType, "CHAR") == 0) ||
                (strcmp(leftType, "INT") == 0 && strcmp(rightType, "INT") == 0) ||
                (strcmp(leftType, "FLOAT") == 0 && strcmp(rightType, "FLOAT") == 0) ||
                (strcmp(leftType, "BOOL") == 0 && strcmp(rightType, "BOOL") == 0) ||
                (strcmp(leftType, "DOUBLE") == 0 && strcmp(rightType, "DOUBLE") == 0) ||
                (isPointerType(leftType) && isPointerType(rightType) && strcmp(leftType, rightType) == 0)) {
                return "BOOL";
            } else {
              snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Invalid operands for %s operator. Got %s and %s\n",
                        yylineno, expr->token, leftType, rightType);  
               //fprintf(stderr, "Semantic Error at line %d: Invalid operands for %s operator. Got %s and %s\n",
                 //       yylineno, expr->token, leftType, rightType);
                THROW;
            }
        }

        if ((strcmp(expr->token, "<") == 0 || strcmp(expr->token, ">") == 0 ||
             strcmp(expr->token, "<=") == 0 || strcmp(expr->token, ">=") == 0) &&
            (isPointerType(leftType) || isPointerType(rightType))) {
             snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Invalid comparison operator '%s' for pointers\n", yylineno, expr->token);  
         //   fprintf(stderr, "Semantic Error at line %d: Invalid comparison operator '%s' for pointers\n", yylineno, expr->token);
            THROW;
        }

        return "BOOL";
    }
     

    return "UNKNOWN";
}

void postorderTraversal(node *tree) {
    if (tree == NULL) return;

    postorderTraversal(tree->left);
    postorderTraversal(tree->right);
    // printf("Processing node: %s\n", tree->token); 
  
    processNode(tree);
   
}

void processNode(node *tree) {

    if (tree == NULL) return;
    
     if (strcmp(tree->token, "Function-Definition") == 0) {
      // printf("processNode\n");
        handleFunctionDefinition(tree);
    } 
      
       
}

void handleDeclaration(node *tree) {

    if (strcmp(tree->token, "Declaration") == 0) {

        // Regular variable declaration
        if (tree->left && strcmp(tree->left->token, "(") == 0) {

            node *typeNode = tree->left->left;
            node *idListNode = tree->left->right;
            if (typeNode && idListNode) {

                //insertIdList(idListNode, typeNode->token);         
                handleIdListWithInit(idListNode, typeNode->token);
            }
        }
    } else if (strcmp(tree->token, "String Declaration") == 0) {

        // String declaration
        handleStringDeclaration(tree->left);
    }
}
void handleIdListWithInit(node *idList, char *type) {
    if (idList == NULL) return;
    if (strcmp(idList->token, "DONT") != 0) {
        if (strcmp(idList->token, "ID_INIT") == 0) {
            // This is an initialized variable
            insert(idList->left->token, type);
            node *initExpr = idList->right->left;
            char *initType = checkExpressionType(initExpr);
            if (!areTypesCompatible(type, initType)) {
          snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Type mismatch in initialization. '%s' (%s) <- (%s)\n",
                        yylineno, idList->left->token, type, initType);  
             //   fprintf(stderr, "Semantic Error at line %d: Type mismatch in initialization. '%s' (%s) <- (%s)\n",
               //         yylineno, idList->left->token, type, initType);
                THROW;
            }
        } else {
          //  printf("token: '%s' , type: '%s' \n",idList->token,type);
            insert(idList->token, type);
        }
    } else {
        handleIdListWithInit(idList->left, type);
        handleIdListWithInit(idList->right, type);
    }
}
void handleStringDeclaration(node *tree) {
    if (tree == NULL) return;
    
    if (strcmp(tree->token, "String") == 0) {
        // Single string declaration
        if (tree->left) {
            insert(tree->left->token, "STRING");
        }
    } else if (strcmp(tree->token, "String Assignment") == 0) {
        // String declaration with assignment
        if (tree->left) {
            insert(tree->left->token, "STRING");
        }
    } else if (strcmp(tree->token, "DONT") == 0) {
        // Multiple string declarations
        handleStringDeclaration(tree->left);
        handleStringDeclaration(tree->right);
    }
}

void handleAssignment(node *tree) {
//printf("handleAssignment\n");
    char *leftSide;
    node *rightSide;
    node *indexNode = NULL;
   
    if (strcmp(tree->left->token, "ARRAY_INDEX") == 0) {
        leftSide = tree->left->left->token;  // The array name
        indexNode = tree->left->right;       // The index expression
        rightSide = tree->right->left;
    } else {
        leftSide = tree->left->token;
        rightSide = tree->right->left;
    }
  // printf("looking for : '%s'\n",leftSide);
    Symbol *leftSymbol = lookup(leftSide);
   //  printf("found : '%s'\n",leftSymbol->type);
      if(leftSymbol == NULL){
       snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Undeclared variable '%s'\n", yylineno, leftSide);  
     // fprintf(stderr, "Semantic Error at line %d: Undeclared variable '%s'\n", yylineno, leftSide);
        THROW;
        }
      //  printf("found : '%s'\n",leftSymbol->type);
    if (strcmp(tree->token, "ASSIGN_DEREF") == 0) {
        // Existing code for ASSIGN_DEREF
        if (!isPointerType(leftSymbol->type)) {
               snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Cannot dereference non-pointer type '%s' for variable '%s'\n", 
                    yylineno, leftSymbol->type, leftSide);  
      //      fprintf(stderr, "Semantic Error at line %d: Cannot dereference non-pointer type '%s' for variable '%s'\n", 
        //            yylineno, leftSymbol->type, leftSide);
            THROW;
        }
        char *leftType = getBaseType(leftSymbol->type);
        char *rightType = checkExpressionType(rightSide);
        if (!areTypesCompatible(leftType, rightType)) {
         snprintf(error_msg, sizeof(error_msg), "Semantic Error at line %d: Type mismatch in dereferenced assignment. '*%s' (%s) <- '%s' (%s)\n",
                    yylineno, leftSide, leftType, rightSide->token, rightType); 
           // fprintf(stderr, "Semantic Error at line %d: Type mismatch in dereferenced assignment. '*%s' (%s) <- '%s' (%s)\n",
             //       yylineno, leftSide, leftType, rightSide->token, rightType);
            THROW;
        }
    } else {
        char *rightType;
        if (strcmp(rightSide->token, "Function-Call") == 0) {
             handleFunctionCall(rightSide);
            rightType = getFunctionReturnType(rightSide);
           
            
        } else if (strcmp(rightSide->token, "NULL") == 0) {
            rightType = "NULL";
        } else if (strcmp(rightSide->token, "& ADDRESS") == 0) {
            rightType = checkExpressionType(rightSide);
        } else if (strcmp(rightSide->token, "Derefernce") == 0) {
            rightType = checkExpressionType(rightSide);
        } 
        else {
            rightType = checkExpressionType(rightSide);

            if (strcmp(rightType, "UNKNOWN") == 0) {
              snprintf(error_msg, sizeof(error_msg),  "Semantic Error at line %d: Unknown variable or expression on right side of assignment\n", yylineno); 
		
		THROW;
	    }
        }

        if (strcmp(leftSymbol->type, "STRING") == 0) {
            if (indexNode != NULL) {
                // String array element assignment
                if (strcmp(rightType, "CHAR") != 0) {
               snprintf(error_msg, sizeof(error_msg),  "Semantic Error at line %d: String array elements can only be assigned single characters\n", yylineno); 
                 //   fprintf(stderr, "Semantic Error at line %d: String array elements can only be assigned single characters\n", yylineno);
                    THROW;
                }
            } else {

                if (strcmp(rightType, "STRING") != 0 ) {
     snprintf(error_msg, sizeof(error_msg),  "Semantic Error at line %d: Strings can only be assigned string literals\n", yylineno); 
                  //  fprintf(stderr, "Semantic Error at line %d: Strings can only be assigned string literals\n", yylineno);
                    THROW;
                }
            }
        } else {
             //   printf("LeftSide '%s' LeftSymbol '%s' \n",leftSide,leftSymbol->type);
            if (!areTypesCompatible(leftSymbol->type, rightType)) {
                 snprintf(error_msg, sizeof(error_msg),  "Semantic Error at line %d: Type mismatch in assignment. '%s' (%s) <- '%s' (%s)\n",
                        yylineno, leftSide, leftSymbol->type, rightSide->token, rightType); 
           //     fprintf(stderr, "Semantic Error at line %d: Type mismatch in assignment. '%s' (%s) <- '%s' (%s)\n",
             //           yylineno, leftSide, leftSymbol->type, rightSide->token, rightType);
                THROW;
            }
        }
    }
}
char* getBaseType(char *pointerType) {
    char *baseType = strtok(strdup(pointerType), " ");
    return baseType;
}
char* getFunctionReturnType(node *functionCall) {
   // printf("getFunctionReturnType\n");
    node *funcNameNode = functionCall->left;
    if (funcNameNode && strcmp(funcNameNode->token, "Function-Name") == 0) {
        char *funcName = funcNameNode->left->token;
      //  printf("Looking for '%s' in current and parent scopes\n", funcName);
        
        Scope *scope = currentScope;
        while (scope != NULL) {
            // Check current scope
            Symbol *sym = lookupInTable(&scope->table, funcName);
            if (sym && strcmp(sym->type, "FUNCTION") == 0) {
            // printf("found  '%s' in '%s' parent scope\n", funcName,scope->functionName);
                return sym->data.func->returnType;
            }
            
            // Check nested scopes
            Scope *nestedScope = scope->NestedScope;
            while (nestedScope != NULL) {
                sym = lookupInTable(&nestedScope->table, funcName);
                if (sym && strcmp(sym->type, "FUNCTION") == 0) {
                //  printf("found  '%s' in '%s' parent scope\n", funcName,nestedScope->functionName);
                    return sym->data.func->returnType;
                }
                nestedScope = nestedScope->UpperScope;
            }
            
            // Move to parent scope
            scope = scope->parent;
        }
        
        snprintf(error_msg, sizeof(error_msg), 
                 "Semantic Error: Function '%s' is not declared in the current scope '%s' or any parent or sibling scopes '%s' \n", 
                 funcName, currentScope->functionName,currentScope->parent->functionName);
        THROW;
    }
    
    fprintf(stderr, "Semantic Error: Unable to determine return type of function call '%s'\n", funcNameNode->token);
    return "UNKNOWN";
}

void handleFunctionDefinition(node *tree) {
    node *signatureNode = tree->left;
    node *bodyNode = tree->right;
  
    if (signatureNode && strcmp(signatureNode->token, "DONT") == 0) {
        node *modifierAndType = signatureNode->left;
        node *funcName = signatureNode->right;
        
        if (modifierAndType && funcName && 
            strcmp(modifierAndType->token, "Function-Modifier-return_type") == 0 &&
            strcmp(funcName->token, "Function-Name") == 0) {
            
            char *access = modifierAndType->left ? modifierAndType->left->token : "UNKNOWN";
            char *returnType = modifierAndType->right ? modifierAndType->right->token : "UNKNOWN";
            char *funcNameStr = funcName->left ? funcName->left->token : "UNKNOWN";
            
            int isStatic = 0;
            if (bodyNode && strcmp(bodyNode->token, "DONT") == 0) {
                node *optionalStatic = bodyNode->left;
                if (optionalStatic && strcmp(optionalStatic->token, "STATIC") == 0) {
                    isStatic = 1;
                }
            }
            currentFunctionIsStatic = isStatic;
          
            
            // Handle parameters
            Parameter *args = NULL;
            int argCount = 0;
            if (bodyNode && bodyNode->right && strcmp(bodyNode->right->token, "DONT") == 0) {
                node *argsNode = bodyNode->right->left;
                if (argsNode && strcmp(argsNode->token, "(Args>>") == 0) {
                    args = getParameters(argsNode->left, &argCount);
                }
                for (int i = 0; i < argCount; i++) {
                //if(strcmp(funcNameStr,"A3") ==0){ printf("CCCCC\n");}
                    insert(args[i].name, args[i].type);
                }
            }
            
            // Check if it's the main function
            if (strcmp(funcNameStr, "main") == 0) {
                if (strcmp(access, "Public") != 0 || !isStatic || 
                    strcmp(returnType, "void") != 0 || argCount != 0) {
              snprintf(error_msg, sizeof(error_msg), "Error: main function must be public static void main() with no arguments\n"); 
                    THROW;
                }
                if (mainFunctionCount > 0) {
            snprintf(error_msg, sizeof(error_msg),"Error: Multiple main functions defined\n"); 
                  //  fprintf(stderr, "Error: Multiple main functions defined\n");
                    THROW;
                }
                mainFunctionCount++;
                
            }
             Symbol *existing = lookupGlobal(funcNameStr);
            if (existing != NULL) {
             snprintf(error_msg, sizeof(error_msg),"Semantic Error at line %d: Function '%s' is already defined\n", yylineno, funcNameStr); 
              //  fprintf(stderr, "Semantic Error at line %d: Function '%s' is already defined\n", yylineno, funcNameStr);
                THROW;
            }
         //   printf("PUSHING FUNCTION '%s' to Scope '%s'\n" , funcNameStr,currentScope->functionName);
            Scope* oldScope = currentScope;
           pushScope(funcNameStr);
            currentScope->type = FUNCTION_SCOPE;

            // Insert function into global symbol table
           insertFunctionGlobal(funcNameStr, access, returnType, args, argCount, isStatic);
		 for (int i = 0; i < argCount; i++) {
        insert(args[i].name, args[i].type);
    }
            node *blockNode = NULL;
            if (bodyNode && bodyNode->right && bodyNode->right->right) {
                blockNode = bodyNode->right->right->left; // Navigate to the actual block
            }

            if (blockNode) {
                // Process the function body
                processFunctionBody(blockNode);

                // Check return type
             //   int hasReturn = 0;
            //    checkFunctionReturnType(blockNode, returnType, funcNameStr, &hasReturn);
                
              //  if (!hasReturn && strcmp(returnType, "void") != 0) {
    //   snprintf(error_msg, sizeof(error_msg),"Semantic Error: Non-void function '%s' has no return statement\n", funcNameStr); 
                   // fprintf(stderr, "Semantic Error: Non-void function '%s' has no return statement\n", funcNameStr);
              //      THROW;
               // }
            }
            
            // Free the temporary args array
            if (args) {
                for (int i = 0; i < argCount; i++) {
                    free(args[i].name);
                    free(args[i].type);
                }
                free(args);
            }
           
            currentFunctionIsStatic = 0;
            currentScope = oldScope;
        }
    }
}
void handleBlockScope(node *tree) {
    if (!tree || strcmp(tree->token, "{BLOCK") != 0) {
        return;
    }

    // Create a new nested scope for this block
    Scope* blockScope = (Scope*)malloc(sizeof(Scope));
    if (!blockScope) {
        snprintf(error_msg, sizeof(error_msg), "Error: Memory allocation failed for block scope\n");
        THROW;
    }

    initSymbolTable(&blockScope->table);
    blockScope->functionName = strdup("block");
    blockScope->type = BLOCK_SCOPE;
    blockScope->parent = currentScope;
    blockScope->NestedScope = NULL;
    blockScope->UpperScope = NULL;

    // Add to the linked list of nested scopes
    if (currentScope->NestedScope == NULL) {
        currentScope->NestedScope = blockScope;
    } else {
        Scope* lastNested = currentScope->NestedScope;
        while (lastNested->UpperScope != NULL) {
            lastNested = lastNested->UpperScope;
        }
        lastNested->UpperScope = blockScope;
        blockScope->NestedScope = lastNested;
    }

    // Save the current scope and set the new block scope as current
    Scope* oldScope = currentScope;
    currentScope = blockScope;

    // Process declarations
    if (tree->left && tree->left->left) {
        processFunctionBody(tree->left->left);
    }

    // Process statements inside the block
    if (tree->left && tree->left->right) {
        processFunctionBody(tree->left->right);
    }


   

    // Restore the previous scope
    currentScope = oldScope;
 
    // Free the block scope
    freeSymbolTable(&blockScope->table);
    free(blockScope->functionName);
    free(blockScope);
}
void handleNestedFunctionDefinition(node *tree) {
   //printf("handleNestedFunctionDefinition\n");
   
    node *signatureNode = tree->left;
    node *bodyNode = tree->right;
    
    if (signatureNode && strcmp(signatureNode->token, "DONT") == 0) {
        node *modifierAndType = signatureNode->left;
        node *funcName = signatureNode->right;
        
        if (modifierAndType && funcName && 

            strcmp(modifierAndType->token, "Nested-Function-Modifier-return_type") == 0 &&
            strcmp(funcName->token, "Nested-Function-Name") == 0) {
            
            char *access = modifierAndType->left ? modifierAndType->left->token : "UNKNOWN";
            char *returnType = modifierAndType->right ? modifierAndType->right->token : "UNKNOWN";
            char *funcNameStr = funcName->left ? funcName->left->token : "UNKNOWN";
            
            int isStatic = 0;
            if (bodyNode && strcmp(bodyNode->token, "DONT") == 0) {
                node *optionalStatic = bodyNode->left;
                if (optionalStatic && strcmp(optionalStatic->token, "STATIC") == 0) {
                    isStatic = 1;
                     
                }
            }
           currentFunctionIsStatic = isStatic;	
	// printf("Nested : '%s' in scope : '%s'\n",funcNameStr,currentScope->functionName);
	   Scope* nestedScope = (Scope*)malloc(sizeof(Scope));
            if (!nestedScope) {
              snprintf(error_msg, sizeof(error_msg),"Error: Memory allocation failed for nested scope\n"); 
               // fprintf(stderr, "Error: Memory allocation failed for nested scope\n");
                THROW;
            }
            initSymbolTable(&nestedScope->table);
            nestedScope->functionName = strdup(funcNameStr);
            nestedScope->type = FUNCTION_SCOPE; 
            nestedScope->parent = currentScope;
            nestedScope->NestedScope = NULL;
             nestedScope->UpperScope = NULL;

            // Add to the linked list of nested scopes
           if (currentScope->NestedScope == NULL) {
		currentScope->NestedScope = nestedScope;
	    } else {
		Scope* lastNested = currentScope->NestedScope;
		while (lastNested->UpperScope != NULL) {
		    lastNested = lastNested->UpperScope;
		}
		lastNested->UpperScope = nestedScope;
		nestedScope->NestedScope = lastNested;
	    }

            Scope* oldScope = currentScope;  // Save the current scope
            currentScope = nestedScope; 
            Symbol *existing = lookup(funcNameStr);
            if (existing != NULL) {
             snprintf(error_msg, sizeof(error_msg),"Semantic Error at line %d: Function '%s' is already defined\n", yylineno, funcNameStr); 
              //  fprintf(stderr, "Semantic Error at line %d: Function '%s' is already defined\n", yylineno, funcNameStr);
                THROW;
            }
            // Handle parameters
            Parameter *args = NULL;
            int argCount = 0;
            if (bodyNode && bodyNode->right && strcmp(bodyNode->right->token, "DONT") == 0) {
          
                node *argsNode = bodyNode->right->left;
                if (argsNode && strcmp(argsNode->token, "(Args>>") == 0) {
                    args = getParameters(argsNode->left, &argCount);
                     
                }
                for (int i = 0; i < argCount; i++) {
                
                insert(args[i].name, args[i].type);
              // printf("Debug: Added function argument %s of type %s to symbol table\n", args[i].name,   
              //  args[i].type);
             }
            }
            
            
            // Check if it's the main function
            if (strcmp(funcNameStr, "main") == 0) {
                if (strcmp(access, "Public") != 0 || !isStatic || 
                    strcmp(returnType, "void") != 0 || argCount != 0) {
            snprintf(error_msg, sizeof(error_msg),"Error: main function must be public static void main() with no arguments\n"); 
                 //   fprintf(stderr, "Error: main function must be public static void main() with no arguments\n");
                    THROW;
                }
                if (mainFunctionCount > 0) {
                   snprintf(error_msg, sizeof(error_msg),"Error: Multiple main functions defined\n"); 
         //           fprintf(stderr, "Error: Multiple main functions defined\n");
                    THROW;
                }
                 currentFunctionIsStatic = 1;
                mainFunctionCount++;
                 
            } 
             insertFunction1(funcNameStr, access, returnType, args, argCount, isStatic);
            node *blockNode = NULL;
            if (bodyNode && bodyNode->right && bodyNode->right->right) {
                blockNode = bodyNode->right->right->left; // Navigate to the actual block
            }
            if (blockNode) {
 
		// Process the function body
		processFunctionBody(blockNode);
		
		// Check return type
		//int hasReturn = 0;
		//checkFunctionReturnType(blockNode, returnType, funcNameStr, &hasReturn);
		
		//if (!hasReturn && strcmp(returnType, "void") != 0) {
		//   snprintf(error_msg, sizeof(error_msg),"Semantic Error: Non-void function '%s' has no return statement\n", funcNameStr); 
		 //   fprintf(stderr, "Semantic Error: Non-void function '%s' has no return statement\n", funcNameStr);
		//    THROW;
		//}
            }
            // Free the temporary args array
            if (args) {
                for (int i = 0; i < argCount; i++) {
                    free(args[i].name);
                    free(args[i].type);
                }
                free(args);
            }
           
            currentFunctionIsStatic = 0;
            currentScope = oldScope;
        }
    }
}
void processFunctionBody(node *tree) {
    if (tree == NULL) return;
     if (strcmp(tree->token, "DONT") == 0|| 
        strcmp(tree->token, "(") == 0 || 
        strcmp(tree->token, ")") == 0  ) {
        processFunctionBody(tree->left);
        processFunctionBody(tree->right);
        return;
    }
    // If we've reached the end of the block, stop recursion
    if (strcmp(tree->token, "BLOCK)") == 0) {
        return;
    }else if ( strcmp(tree->token,"Nested-Function" ) == 0 ){
      //  printf("process-Nested-FunctionBody   cuurent scope:'%s'\n",currentScope->functionName);
              handleNestedFunctionDefinition(tree->left);
              return; 
    }else if (strcmp(tree->token, "RETURN") == 0) {
    //printf("current scope '%s' \n" , currentScope->functionName);
   	Symbol *funcSymbol = lookup(currentScope->functionName);
        if (funcSymbol != NULL && strcmp(funcSymbol->type, "FUNCTION") == 0) {
            char *returnType = funcSymbol->data.func->returnType;
            // Check the return type
            int hasReturn = 1;
            checkFunctionReturnType(tree, returnType, currentScope->functionName, &hasReturn);
        } else {
            fprintf(stderr, "Error: Function symbol not found for '%s'\n", currentScope->functionName);
        }
        return;
       
 
    }else if (strcmp(tree->token, "{BLOCK") == 0){
    handleBlockScope(tree);
   // printf("AAAAAAAAAAAA '%s' \n " ,tree->right->token);
     if (tree->right && strcmp(tree->right->token, "}") == 0) {
            processFunctionBody(tree->right->left);
        }
        return;
    }
    else if (strcmp(tree->token, "Declaration") == 0 || 
               strcmp(tree->token, "String Declaration") == 0) {
        handleDeclaration(tree);
        return;
    }else if (strcmp(tree->token, "ASSIGN") == 0) {

        handleAssignment(tree);
	return;
    } else if (strcmp(tree->token, "Function-Call") == 0) {
        handleFunctionCall(tree);
         return;
    }else if (strcmp(tree->token, "IF") == 0 || strcmp(tree->token, "IF ELSE STMT") == 0) {
        handleIfStatement(tree);
        return;
    } else if (strcmp(tree->token, "WHILE") == 0) {
        handleWhileLoop(tree);
        return;
    } else if (strcmp(tree->token, "DO-WHILE") == 0) {
        handleDoWhileLoop(tree);
        return;
    } else if (strcmp(tree->token, "FOR") == 0) {
        handleForLoop(tree);
        return;
    }else if (strcmp(tree->token,"(BLOCK") != 0 ){
   
      checkExpressionType(tree);
    
    }

    // Recursively process left and right children
    processFunctionBody(tree->left);
    processFunctionBody(tree->right);
   
    
}
Scope* createNestedScope(char* scopeName, ScopeType type) {
    Scope* newScope = (Scope*)malloc(sizeof(Scope));
    if (!newScope) {
    	snprintf(error_msg, sizeof(error_msg),"Error: Memory allocation failed for new scope\n"); 
       // fprintf(stderr, "Error: Memory allocation failed for new scope\n");
        THROW;
    }
    initSymbolTable(&newScope->table);
    newScope->functionName = strdup(scopeName);
    newScope->type = type;
    newScope->parent = currentScope;
    newScope->NestedScope = NULL;
    newScope->UpperScope = NULL;

    // Add to the linked list of nested scopes
    if (currentScope->NestedScope == NULL) {
        currentScope->NestedScope = newScope;
    } else {
        Scope* lastNested = currentScope->NestedScope;
        while (lastNested->UpperScope != NULL) {
            lastNested = lastNested->UpperScope;
        }
        lastNested->UpperScope = newScope;
        newScope->NestedScope = lastNested;
    }

    return newScope;
}
void handleIfStatement(node *tree) {
    if (strcmp(tree->token, "IF") == 0) {
        node *condition = tree->left;
        node *thenPart = tree->right;

        char *conditionType = checkExpressionType(condition);
        if (strcmp(conditionType, "BOOL") != 0) {
        snprintf(error_msg, sizeof(error_msg),"Semantic Error: If condition must be a boolean, got %s\n", conditionType); 
       //     fprintf(stderr, "Semantic Error: If condition must be a boolean, got %s\n", conditionType);
            THROW;
        }

        // Create a new scope for the if block
        Scope* ifScope = createNestedScope("if-block", BLOCK_SCOPE);
        Scope* oldScope = currentScope;
        currentScope = ifScope;

        // Process the body of the if statement
        if (strcmp(thenPart->token, "THEN") == 0) {
            processFunctionBody(thenPart->left);
        }

        // Restore the original scope
        currentScope = oldScope;
    } else if (strcmp(tree->token, "IF ELSE STMT") == 0 || strcmp(tree->token, "IF-ELSE") == 0) {
        node *ifPart = tree->left;
        node *elsePart = tree->right;

        // Handle the if part
        handleIfStatement(ifPart);

        // Handle the else part
        Scope* elseScope = createNestedScope("else-block", BLOCK_SCOPE);
        Scope* oldScope = currentScope;
        currentScope = elseScope;

        processFunctionBody(elsePart->left);

        currentScope = oldScope;
    }
}
void handleWhileLoop(node *tree) {
    if (strcmp(tree->token, "WHILE") == 0) {
        node *condition = tree->left;
        node *body = tree->right;

        char *conditionType = checkExpressionType(condition);
        if (strcmp(conditionType, "BOOL") != 0) {
            snprintf(error_msg, sizeof(error_msg),"Semantic Error: While condition must be a boolean, got %s\n", conditionType); 
          //  fprintf(stderr, "Semantic Error: While condition must be a boolean, got %s\n", conditionType);
            THROW;
        }

        Scope* whileScope = createNestedScope("while-block", BLOCK_SCOPE);
        Scope* oldScope = currentScope;
        currentScope = whileScope;

        if (strcmp(body->token, "THEN") == 0) {
            processFunctionBody(body->left);
        }

        currentScope = oldScope;
    }
}

void handleDoWhileLoop(node *tree) {
    if (strcmp(tree->token, "DO-WHILE") == 0) {
        node *body = tree->left;
        node *condition = tree->right;

        Scope* doWhileScope = createNestedScope("do-while-block", BLOCK_SCOPE);
        Scope* oldScope = currentScope;
        currentScope = doWhileScope;

        processFunctionBody(body->left);

        currentScope = oldScope;

        char *conditionType = checkExpressionType(condition->left);
        if (strcmp(conditionType, "BOOL") != 0) {
          snprintf(error_msg, sizeof(error_msg),"Semantic Error: Do-While condition must be a boolean, got %s\n", conditionType); 
        //    fprintf(stderr, "Semantic Error: Do-While condition must be a boolean, got %s\n", conditionType);
            THROW;
        }
    }
}

void handleForLoop(node *tree) {
    if (strcmp(tree->token, "FOR") == 0) {
        node *init = tree->left;
        node *cond = tree->right->left;
        node *update = tree->right->right->left;
        node *body = tree->right->right->right->left;

        Scope* forScope = createNestedScope("for-block", BLOCK_SCOPE);
        Scope* oldScope = currentScope;
        currentScope = forScope;

        // Process initialization
        if (init != NULL) {
            processFunctionBody(init);
        }

        // Check condition
        if (cond != NULL) {
            char *conditionType = checkExpressionType(cond);
            if (strcmp(conditionType, "BOOL") != 0) {
                snprintf(error_msg, sizeof(error_msg),"Semantic Error: For loop condition must be a boolean, got %s\n", conditionType); 
               // fprintf(stderr, "Semantic Error: For loop condition must be a boolean, got %s\n", conditionType);
                THROW;
            }
        }

        // Process update
        if (update != NULL) {
            processFunctionBody(update);
        }

        // Process body
        processFunctionBody(body);

        currentScope = oldScope;
    }
}
char* handleHexLiteral(char *value) {
    // Check if it's a valid hexadecimal literal
    if (strlen(value) > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        char *endptr;
        strtol(value, &endptr, 16);
        if (*endptr == '\0') {
            return "HEX";
        }
    }
    return "UNKNOWN";
}
void checkFunctionReturnType(node *blockNode, char *expectedReturnType, char *funcName, int *hasReturn) {
    if (blockNode == NULL) return;
    
    if (strcmp(blockNode->token, "RETURN") == 0) {
        *hasReturn = 1;
        if (strcmp(expectedReturnType, "void") == 0) {
            if (blockNode->left != NULL) {
               snprintf(error_msg, sizeof(error_msg),"Semantic Error: Function '%s' is void but has a return value\n", funcName); 
              //  fprintf(stderr, "Semantic Error: Function '%s' is void but has a return value\n", funcName);
                THROW;
            }
        } else {
            if (blockNode->left == NULL) {
              snprintf(error_msg, sizeof(error_msg),"Semantic Error: Function '%s' with return type '%s' has an empty return statement\n", 
                        funcName, expectedReturnType); 
                THROW;
            } else {
                char *actualReturnType;
                if (blockNode->left->left == NULL && blockNode->left->right == NULL) {
                    Symbol *sym = lookup(blockNode->left->token);
                    if (sym != NULL) {
                        actualReturnType = sym->type;
                       // printf("'%s'",blockNode->left->token); 
		            } else {

		                actualReturnType = inferType(blockNode->left->token);
		            }
	        } else {

	            actualReturnType = checkExpressionType(blockNode->left);
	        }
	//	printf("%s ---- %s\n",expectedReturnType, actualReturnType);
                if (!areTypesCompatible(expectedReturnType, actualReturnType)) {
                 snprintf(error_msg, sizeof(error_msg),"Semantic Error: Function '%s' returns '%s', but '%s' was expected\n", 
                            funcName, actualReturnType, expectedReturnType); 
               
                    THROW;
                }
            }
        }
    } else if (strcmp(blockNode->token, "DONT") == 0 || strcmp(blockNode->token, "(BLOCK") == 0) {
        checkFunctionReturnType(blockNode->left, expectedReturnType, funcName, hasReturn);
        checkFunctionReturnType(blockNode->right, expectedReturnType, funcName, hasReturn);
    }
}

Parameter* getParameters(node *params, int *count) {
 //   printf("Getting parameters\n");
    if (params == NULL) {
       // printf("Params is NULL\n");
        *count = 0;
        return NULL;
    }
    
    // First, count the parameters
    int paramCount = 0;
    countParameters(params, &paramCount);
   // printf("Parameter count: %d\n", paramCount);
    
    if (paramCount == 0) {
        *count = 0;
        return NULL;
    }
    
    // Allocate the array
    Parameter *args = (Parameter *)malloc(sizeof(Parameter) * paramCount);
    if (args == NULL) {
    //    printf("Memory allocation failed for args\n");
        *count = 0;
        return NULL;
    }
    
    // Initialize all elements to NULL
    for (int i = 0; i < paramCount; i++) {
        args[i].name = NULL;
        args[i].type = NULL;
    }
    
    // Fill the array
    int index = 0;
    fillParameterArray(params, args, &index);
    
    // Check if all parameters were filled
    if (index != paramCount) {
     //   printf("Warning: Not all parameters were filled. Expected %d, got %d\n", paramCount, index);
    }
    
    *count = paramCount;
    return args;
}

void countParameters(node *params, int *count) {
    if (params == NULL) return;
    
    //printf("countParameters: Processing node with token '%s'\n", params->token);
    
    if (strcmp(params->token, "DONT") == 0) {
        if (params->left && strcmp(params->left->token, "DONT") != 0) {
            // This is a type:id_list structure
            countIdsInList(params->right, count);
        } else {
            // This is a list of parameter groups
            countParameters(params->left, count);
            countParameters(params->right, count);
        }
    } else {
        printf("countParameters: Unexpected node type: %s\n", params->token);
    }
}

void countIdsInList(node *idList, int *count) {
    if (idList == NULL) return;
    
    if (strcmp(idList->token, "DONT") != 0) {
        (*count)++;
    } else {
        countIdsInList(idList->left, count);
        countIdsInList(idList->right, count);
    }
}
void fillParameterArray(node *params, Parameter *args, int *index) {
    if (params == NULL) {
     //   printf("fillParameterArray: params is NULL\n");
        return;
    }
    
    //printf("fillParameterArray: Processing node with token '%s'\n", params->token);
    
    if (strcmp(params->token, "DONT") == 0) {
        if (params->left && strcmp(params->left->token, "DONT") != 0) {
            // This is a type:id_list structure
            node *type = params->left;
            node *idList = params->right;
          //  printf("fillParameterArray: Found type:id_list structure. Type: %s\n", type->token);
            fillIdList(type->token, idList, args, index);
        } else {
            // This is a list of parameter groups
            fillParameterArray(params->left, args, index);
            fillParameterArray(params->right, args, index);
        }
    } else {
        printf("fillParameterArray: Unexpected node type: %s\n", params->token);
    }
}

void fillIdList(char *type, node *idList, Parameter *args, int *index) {
    if (idList == NULL) {
      //  printf("fillIdList: idList is NULL\n");
        return;
    }
    
   // printf("fillIdList: Processing node with token '%s'\n", idList->token);
    
    if (strcmp(idList->token, "DONT") != 0) {
        args[*index].type = strdup(type);
        args[*index].name = strdup(idList->token);
       // printf("fillIdList: Added parameter %s of type %s at index %d\n", args[*index].name, args[*index].type, *index);
        (*index)++;
    } else {
        fillIdList(type, idList->left, args, index);
        fillIdList(type, idList->right, args, index);
    }
}

void insertFunction(char *name, char *access, char *returnType, Parameter *args, int argCount, int isStatic) {
    if (!name || !access || !returnType) {
        printf("Error: NULL pointer passed to insertFunction\n");
        return;
    }
    
    unsigned int index = hash(name);
    
    // Check if function already exists
    Symbol *existing = lookup(name);
    if (existing ) {
    snprintf(error_msg, sizeof(error_msg),"Semantic Error at line %d: Function '%s' is already declared\n", yylineno, name); 
     // fprintf(stderr, "Semantic Error at line %d: Function '%s' is already declared\n", yylineno, name);
        THROW;
    }

    // Create new symbol for the function
    Symbol *newSymbol = (Symbol *)malloc(sizeof(Symbol));
    if (!newSymbol) {
        snprintf(error_msg, sizeof(error_msg),"Error: Memory allocation failed for new symbol\n"); 
  //    fprintf(stderr, "Error: Memory allocation failed for new symbol\n");
        return;
    }
    
    newSymbol->name = strdup(name);
    newSymbol->type = strdup("FUNCTION");
    
    Function *func = (Function *)malloc(sizeof(Function));
    if (!func) {
      //  printf("Error: Memory allocation failed for new function\n");
        free(newSymbol->name);
        free(newSymbol->type);
        free(newSymbol);
        return;
    }
    
    func->access = strdup(access);
    func->name = strdup(name);
    func->returnType = strdup(returnType);
    func->argCount = argCount;
    func->isStatic = isStatic;
     //printf("Inserting function: %s, isStatic: %d\n", name, isStatic);
    if (argCount > 0) {
        func->args = (Parameter *)malloc(sizeof(Parameter) * argCount);
        if (!func->args) {
        //    printf("Error: Memory allocation failed for function arguments\n");
            free(func->access);
            free(func->name);
            free(func->returnType);
            free(func);
            free(newSymbol->name);
            free(newSymbol->type);
            free(newSymbol);
            return;
        }
        
        for (int i = 0; i < argCount; i++) {
            func->args[i].name = strdup(args[i].name);
            func->args[i].type = strdup(args[i].type);
        }
    } else {
        func->args = NULL;
    }
    
    newSymbol->data.func = func;
    newSymbol->next = symbolTable.table[index];
    symbolTable.table[index] = newSymbol;
    
  // printf("Function inserted successfully: %s\n", name);
}

void freeSymbol(Symbol *symbol) {
    free(symbol->name);
    free(symbol->type);
    if (strcmp(symbol->type, "FUNCTION") == 0) {
        Function *func = symbol->data.func;
        free(func->access);
        free(func->name);
        free(func->returnType);
        for (int i = 0; i < func->argCount; i++) {
            free(func->args[i].name);
            free(func->args[i].type);
        }
        free(func->args);
        free(func);
    }
    free(symbol);
}

void freeSymbolTable() {
    for (int i = 0; i < TABLE_SIZE; i++) {
        Symbol *current = symbolTable.table[i];
        while (current != NULL) {
            Symbol *next = current->next;
            freeSymbol(current);
            current = next;
        }
        symbolTable.table[i] = NULL;
    }
}

Symbol *lookupForcalls(char *name) {
    Scope* scope = currentScope;
    while (scope != NULL) {
        // Check current scope
        Symbol* symbol = lookupInTable(&scope->table, name);
        if (symbol) return symbol;
        
        // If this is a function scope, check its parameters
        if (scope->type == FUNCTION_SCOPE) {
            Symbol *sym = lookupGlobal(scope->functionName);
            if (sym && strcmp(sym->type, "FUNCTION") == 0) {
                Function *func = sym->data.func;
                for (int i = 0; i < func->argCount; i++) {
                    if (strcmp(func->args[i].name, name) == 0) {
                        // Create a temporary symbol for the parameter
                        Symbol *paramSym = malloc(sizeof(Symbol));
                        paramSym->name = strdup(func->args[i].name);
                        paramSym->type = strdup(func->args[i].type);
                        return paramSym;
                    }
                }
            }
        }
        
        // Check nested scopes and their siblings
        Scope* nestedScope = scope->NestedScope;
        while (nestedScope != NULL) {
            symbol = lookupInTable(&nestedScope->table, name);
            if (symbol) return symbol;
            
            // Check sibling scopes
            Scope* siblingScope = nestedScope->UpperScope;
            while (siblingScope != NULL) {
                symbol = lookupInTable(&siblingScope->table, name);
                if (symbol) return symbol;
                siblingScope = siblingScope->UpperScope;
            }
            
            nestedScope = nestedScope->NestedScope;
        }
        
        // Move to parent scope
        scope = scope->parent;
    }
    
    // Variable not found in any accessible scope
    return NULL;
}

void handleFunctionCall(node *tree) {
    //printf("handleFunctionCall\n");
    if (strcmp(tree->token, "Function-Call") == 0) {
        node *funcName = tree->left;
        node *argListNode = tree->right;
        
        if (funcName && strcmp(funcName->token, "Function-Name") == 0) {
         //  printf("look up function '%s' \n", funcName->left->token);
            Symbol *sym = lookupForcalls(funcName->left->token);
            if (sym == NULL || strcmp(sym->type, "FUNCTION") != 0) {
                snprintf(error_msg, sizeof(error_msg),"Semantic Error: Function '%s' not declared\n", funcName->left->token); 
                THROW;
            }
            
            Function *func = sym->data.func;
           // Check if we're in a static context calling a non-static function
           //printf("Current functios static?: '%d' the called function static?: '%d'\n", currentFunctionIsStatic,func->isStatic);
            if (currentFunctionIsStatic && !func->isStatic) {
               snprintf(error_msg, sizeof(error_msg),"Semantic Error: Static function cannot call non-static function '%s'\n", func->name); 
            //    fprintf(stderr, "Semantic Error: Static function cannot call non-static function '%s'\n", func->name);
                THROW;
            }

            // Navigate to the actual argument list
            node *actualArgList = NULL;
            if (argListNode && strcmp(argListNode->token, "DONT") == 0) {
                node *paramListNode = argListNode->left;
                if (paramListNode && strcmp(paramListNode->token, "(Parameter_List") == 0) {
                    actualArgList = paramListNode->left;
                }
            }
            
            checkFunctionArguments(func, actualArgList);
        }
    }
}

void checkFunctionArguments(Function *func, node *argList) {
    int argCount = 0;
    countArguments(argList, &argCount);
    
    if (argCount != func->argCount) {
        snprintf(error_msg, sizeof(error_msg), "Semantic Error: Function '%s' called with wrong number of arguments. Expected %d, got %d\n", 
                func->name, func->argCount, argCount);
        THROW;
    }
    
    int argIndex = 0;
    int paramGroupIndex = 0;
    int paramIndexInGroup = 0;
    checkArgumentsRecursive(func, argList, &argIndex, &paramGroupIndex, &paramIndexInGroup);
}
//^^
void checkArgumentsRecursive(Function *func, node *argNode, int *argIndex, int *paramGroupIndex, int *paramIndexInGroup) {
    if (argNode == NULL) return;

    if (strcmp(argNode->token, "DONT") == 0) {
        checkArgumentsRecursive(func, argNode->left, argIndex, paramGroupIndex, paramIndexInGroup);
        checkArgumentsRecursive(func, argNode->right, argIndex, paramGroupIndex, paramIndexInGroup);  
    } else {
        char *argType = checkExpressionType(argNode);
        
        // Find the corresponding parameter group
        int paramIndex = 0;
        int currentGroupIndex = 0;
        for (int i = 0; i < func->argCount; i++) {
            if (i == 0 || strcmp(func->args[i-1].type, func->args[i].type) != 0) {
                if (currentGroupIndex == *paramGroupIndex) {
                    paramIndex = i;
                    break;
                }
                currentGroupIndex++;
            }
        }
        
        // Check if the argument type matches the parameter type
        if (paramIndex + *paramIndexInGroup < func->argCount && !areTypesCompatible(func->args[paramIndex + *paramIndexInGroup].type, argType)) {
            snprintf(error_msg, sizeof(error_msg), "Semantic Error: Type mismatch for argument %d in function call to '%s'. Expected %s, got %s\n", 
                    *argIndex + 1, func->name, func->args[paramIndex + *paramIndexInGroup].type, argType);
            THROW;
        }
        
        (*argIndex)++;
        (*paramIndexInGroup)++;
        
        if (paramIndex + *paramIndexInGroup < func->argCount && strcmp(func->args[paramIndex + *paramIndexInGroup - 1].type, func->args[paramIndex + *paramIndexInGroup].type) != 0) {
            (*paramGroupIndex)++;
            *paramIndexInGroup = 0;
        }
    }
}

void countArguments(node *argList, int *count) {
    if (argList == NULL) return;
    
    if (strcmp(argList->token, "DONT") != 0) {
        (*count)++;
    } else {
        countArguments(argList->left, count);
        countArguments(argList->right, count);
    }
}

void printSymbolTable() {
    printf("Symbol Table:\n");
    for (int i = 0; i < TABLE_SIZE; i++) {
        Symbol *current = symbolTable.table[i];
        while (current != NULL) {
            if (strcmp(current->type, "FUNCTION") == 0) {
                Function *func = current->data.func;
                printf("Function: %s %s%s %s(", func->access, 
                       func->isStatic ? "static " : "", 
                       func->returnType, func->name);
                for (int j = 0; j < func->argCount; j++) {
                    printf("%s %s", func->args[j].type, func->args[j].name);
                    if (j < func->argCount - 1) printf(", ");
                }
                printf(")\n");
            } else {
                printf("Variable: %s, Type: %s\n", current->name, current->type);
            }
            current = current->next;
        }
    }
}
int isPointerType(char *type) {
    return (strstr(type, "Pointer") != NULL);
}

void pushScope(char* functionName) {
    Scope* newScope = (Scope*)malloc(sizeof(Scope));
    if (!newScope) {
    snprintf(error_msg, sizeof(error_msg),"Error: Memory allocation failed for new scope\n");
        //fprintf(stderr, "Error: Memory allocation failed for new scope\n");
        THROW;
    }
    initSymbolTable(&newScope->table);
    newScope->functionName = strdup(functionName);
    newScope->parent = currentScope;
    
    currentScope = newScope;
}

void popScope() {
    if (currentScope) {
        Scope* oldScope = currentScope;
        currentScope = currentScope->parent;
        freeSymbolTable(&oldScope->table);
        free(oldScope->functionName);
        free(oldScope);
    }
}
Symbol *lookupGlobal(char *name) {
    
    Scope *globalScope = currentScope;
    while (globalScope->parent != NULL) {
        globalScope = globalScope->parent;
    }
    return lookupInTable(&globalScope->table, name);
}
void insertFunctionGlobal(char *name, char *access, char *returnType, Parameter *args, int argCount, int isStatic) {
    // Find the global scope
    Scope *globalScope = currentScope;
    while (globalScope->parent != NULL) {
        globalScope = globalScope->parent;
    }

    // Now insert the function into the global scope
    unsigned int index = hash(name);
    
    Symbol *newSymbol = (Symbol *)malloc(sizeof(Symbol));
    if (!newSymbol) {
        snprintf(error_msg, sizeof(error_msg),"Error: Memory allocation failed for new symbol\n");
  //      fprintf(stderr, "Error: Memory allocation failed for new symbol\n");
        return;
    }
    
    newSymbol->name = strdup(name);
    newSymbol->type = strdup("FUNCTION");
    
    Function *func = (Function *)malloc(sizeof(Function));
    if (!func) {
        free(newSymbol->name);
        free(newSymbol->type);
        free(newSymbol);
        return;
    }
    
    func->access = strdup(access);
    func->name = strdup(name);
    func->returnType = strdup(returnType);
    func->argCount = argCount;
    func->isStatic = isStatic;
    
    if (argCount > 0) {
        func->args = (Parameter *)malloc(sizeof(Parameter) * argCount);
        if (!func->args) {
            free(func->access);
            free(func->name);
            free(func->returnType);
            free(func);
            free(newSymbol->name);
            free(newSymbol->type);
            free(newSymbol);
            return;
        }
        
        for (int i = 0; i < argCount; i++) {
            func->args[i].name = strdup(args[i].name);
            func->args[i].type = strdup(args[i].type);
        }
    } else {
        func->args = NULL;
    }
    
    newSymbol->data.func = func;
    newSymbol->next = globalScope->table.table[index];
    globalScope->table.table[index] = newSymbol;
}
void insertFunction1(char *name, char *access, char *returnType, Parameter *args, int argCount, int isStatic) {
    // Find the global scope
    Scope *globalScope = currentScope;
   
    // Now insert the function into the global scope
    unsigned int index = hash(name);
    
    Symbol *newSymbol = (Symbol *)malloc(sizeof(Symbol));
    if (!newSymbol) {
        snprintf(error_msg, sizeof(error_msg),"Error: Memory allocation failed for new symbol\n");
  //      fprintf(stderr, "Error: Memory allocation failed for new symbol\n");
        return;
    }
    
    newSymbol->name = strdup(name);
    newSymbol->type = strdup("FUNCTION");
    
    Function *func = (Function *)malloc(sizeof(Function));
    if (!func) {
        free(newSymbol->name);
        free(newSymbol->type);
        free(newSymbol);
        return;
    }
    
    func->access = strdup(access);
    func->name = strdup(name);
    func->returnType = strdup(returnType);
    func->argCount = argCount;
    func->isStatic = isStatic;
    
    if (argCount > 0) {
        func->args = (Parameter *)malloc(sizeof(Parameter) * argCount);
        if (!func->args) {
            free(func->access);
            free(func->name);
            free(func->returnType);
            free(func);
            free(newSymbol->name);
            free(newSymbol->type);
            free(newSymbol);
            return;
        }
        
        for (int i = 0; i < argCount; i++) {
            func->args[i].name = strdup(args[i].name);
            func->args[i].type = strdup(args[i].type);
        }
    } else {
        func->args = NULL;
    }
    
    newSymbol->data.func = func;
    newSymbol->next = globalScope->table.table[index];
    globalScope->table.table[index] = newSymbol;
}
void printNestedScopes(Scope* scope, int level, int subLevel) {
    while (scope != NULL) {
        printf("\nSymbol Table for nested scope level %d.%d (%s):\n", 
               level, subLevel, scope->functionName);
        printf("----------------------------------------\n");
        
        for (int i = 0; i < TABLE_SIZE; i++) {
            Symbol *current = scope->table.table[i];
            while (current != NULL) {
                if (strcmp(current->type, "FUNCTION") == 0) {
                    Function *func = current->data.func;
                    printf("Function: %s %s%s %s(", func->access, 
                           func->isStatic ? "static " : "", 
                           func->returnType, func->name);
                    for (int j = 0; j < func->argCount; j++) {
                        printf("%s %s", func->args[j].type, func->args[j].name);
                        if (j < func->argCount - 1) printf(", ");
                    }
                    printf(")\n");
                } else {
                    printf("Variable: %s, Type: %s\n", current->name, current->type);
                }
                current = current->next;
            }
        }
        
        // Print nested scopes with incremented subLevel
        if (scope->NestedScope) {
            printNestedScopes(scope->NestedScope, level, subLevel + 1);
        }
        
        scope = NULL;  // Stop after printing this scope and its nested scopes
    }
}
void printAllScopeTables() {
    Scope *currentPrintScope = currentScope;
    int scopeLevel = 0;
    
    // First, count the number of scopes
    while (currentPrintScope != NULL) {
        currentPrintScope = currentPrintScope->parent;
        scopeLevel++;
    }
    
    // Now print scopes from outermost to innermost
    currentPrintScope = currentScope;
    while (currentPrintScope != NULL) {
        printf("\nSymbol Table for scope level %d (%s):\n", 
               scopeLevel - 1, currentPrintScope->functionName);
        printf("----------------------------------------\n");
        
        for (int i = 0; i < TABLE_SIZE; i++) {
            Symbol *current = currentPrintScope->table.table[i];
            while (current != NULL) {
                if (strcmp(current->type, "FUNCTION") == 0) {
                    Function *func = current->data.func;
                    printf("Function: %s %s%s %s(", func->access, 
                           func->isStatic ? "static " : "", 
                           func->returnType, func->name);
                    for (int j = 0; j < func->argCount; j++) {
                        printf("%s %s", func->args[j].type, func->args[j].name);
                        if (j < func->argCount - 1) printf(", ");
                    }
                    printf(")\n");
                } else {
                    printf("Variable: %s, Type: %s\n", current->name, current->type);
                }
                current = current->next;
            }
        }
        
        printNestedScopes(currentPrintScope->NestedScope, scopeLevel - 1, 1);
        
        currentPrintScope = currentPrintScope->parent;
        scopeLevel--;
    }
}

//~
TAC* create_tac(char *op, char *arg1, char *arg2, char *result) {
    TAC *new_tac = (TAC*)malloc(sizeof(TAC));
    new_tac->op = strdup(op);
    new_tac->arg1 = arg1 ? strdup(arg1) : NULL;
    new_tac->arg2 = arg2 ? strdup(arg2) : NULL;
    new_tac->result = strdup(result);
    new_tac->next = NULL;
    return new_tac;
}

void add_tac(TAC *code) {
    if (tac_first == NULL) {
        tac_first = tac_last = code;
    } else {
        tac_last->next = code;
        tac_last = code;
    }
}



char* new_temp() {
    char *temp = malloc(10);
    sprintf(temp, "t%d", temp_var_count++);
    return temp;
}

char* new_label() {
    char *label = malloc(10);
    sprintf(label, "L%d", label_count++);
    return label;
}



void generate_3ac(node *tree) {
    if (!tree) return;

    if (strcmp(tree->token, "Program") == 0) {
        generate_3ac(tree->left);
    } else if (strcmp(tree->token, "DONT") == 0) {
        generate_3ac(tree->left);
        generate_3ac(tree->right);
    } else if (strcmp(tree->token, "(Function") == 0) {
        generate_3ac_function(tree->left);
    }
}

void generate_3ac_function(node *tree) {
    if (strcmp(tree->token, "Function-Definition") == 0) {
        node *signatureNode = tree->left;
        node *bodyNode = tree->right;
        
        if (signatureNode && strcmp(signatureNode->token, "DONT") == 0) {
            node *modifierAndType = signatureNode->left;
            node *funcName = signatureNode->right;
            
            if (modifierAndType && funcName && 
                strcmp(modifierAndType->token, "Function-Modifier-return_type") == 0 &&
                strcmp(funcName->token, "Function-Name") == 0) {
                
                char *returnType = modifierAndType->right ? modifierAndType->right->token : "UNKNOWN";
                char *funcNameStr = funcName->left ? funcName->left->token : "UNKNOWN";

                local_funcs[local_func_count].name = strdup(funcNameStr);
                local_funcs[local_func_count].type = strdup(returnType);
                local_func_count++;

                local_var_count = 0;
                total_size = 0;
                clear_buffer();

                char temp[100];
                printf( "%s:\n", funcNameStr);
                
                
                node *blockStmt = NULL;
                if (bodyNode && bodyNode->right && bodyNode->right->right) {
                    blockStmt = bodyNode->right->right->left; // Navigate to the actual block
                }
//%%%%
                if (blockStmt) {
                    generate_3ac_block(blockStmt);
                }

                sprintf(temp, "         BeginFunc %d\n", total_size);
                printf("%s", temp);

                printf("%s", instruction_buffer);
                clear_buffer();
                sprintf(temp, "         EndFunc\n\n");
                printf("%s", temp);

            }
        }
    }
}




void generate_3ac_block(node *tree) {
    if (!tree) return;
   // printf("         Token : '%s'\n", tree->token);
    if (strcmp(tree->token, "(BLOCK") == 0) {
        generate_3ac_block(tree->left);
        generate_3ac_block(tree->right);
        return;
    } else if (strcmp(tree->token, "DONT") == 0) {
        generate_3ac_block(tree->left);
        generate_3ac_block(tree->right);
        return;
    } else if (strcmp(tree->token, "Declaration") == 0  || strcmp(tree->token, "String Declaration") == 0 ) {

        generate_3ac_declaration(tree);
        return;
	} else if (strcmp(tree->token, "ASSIGN") == 0 && strcmp(tree->left->token, "ARRAY_INDEX") == 0) {
        char *array = tree->left->left->token;
        char *index = generate_3ac_expr(tree->left->right);
        char *value = generate_3ac_expr(tree->right->left);
        char *t1 = new_temp();
        char *t2 = new_temp();
        char *t3 = new_temp();
        char temp[100];
        sprintf(temp, "         %s = 1\n", t1);  // Assuming char array, byte size is 1
        add_to_buffer(temp);
        sprintf(temp, "         %s = %s * %s\n", t2, index, t1);
        add_to_buffer(temp);
        sprintf(temp, "         %s = %s + %s\n", t3, array, t2);
        add_to_buffer(temp);
        sprintf(temp, "         *(%s) = %s\n", t3, value);
        add_to_buffer(temp);
        return;
    }
	 else if (strcmp(tree->token, "ASSIGN") == 0) {
        char *result = generate_3ac_expr(tree->right->left);
        char temp[100];
        if (result[0] == 't' && isdigit(result[1])) {
            // If the result is a temporary variable, use it directly
            sprintf(temp, "         %s = %s\n", tree->left->token, result);
        } else {
            // If it's not a temporary variable, create a new assignment
            sprintf(temp, "         %s = %s\n", tree->left->token, result);
        }
        add_to_buffer(temp);
    } else if (strcmp(tree->token, "IF") == 0) {
        if (strcmp(tree->right->token, "THEN") == 0 && strcmp(tree->right->left->token, "(BLOCK") == 0) {
            generate_3ac_if_block(tree);
            return;
        } else {
            generate_3ac_if_single(tree);
            return;
        }
    } else if (strcmp(tree->token, "IF ELSE STMT") == 0) {
        generate_3ac_if_else_block(tree);
        return;
    } else if (strcmp(tree->token, "IF-ELSE") == 0) {
        generate_3ac_if_else_single(tree);
        return;
    } else if (strcmp(tree->token, "WHILE") == 0) {
        generate_3ac_while(tree);
        return;
    } else if (strcmp(tree->token, "DO-WHILE") == 0) {
        generate_3ac_do_while(tree);
        return;
    } else if (strcmp(tree->token, "FOR") == 0) {
        generate_3ac_for(tree);
        return;
    } else if (strcmp(tree->token, "RETURN") == 0) {
    char *expr = generate_3ac_expr(tree->left);
    char temp[100];
    
    // Check if the expression is a literal (not a variable or temp var)
    if (expr[0] != 't' && !isalpha(expr[0])) {
        // It's likely a literal, so determine its type
        char *literalType = getLiteralType(expr);
        int size = get_type_size(literalType);
        
        // Create a new temp var and assign the literal to it
        char *tempVar = new_temp();
        sprintf(temp, "         %s = %s\n", tempVar, expr);
        add_to_buffer(temp);
        
        // Add the size to totalsize
        total_size += size;
        
        // Now return the temp var
        sprintf(temp, "         Return %s\n", tempVar);
        add_to_buffer(temp);
        
       // printf("Added %d bytes for return value of type %s\n", size, literalType);
    } else {
        // It's already a variable or temp var, return it directly
        sprintf(temp, "         Return %s\n", expr);
        add_to_buffer(temp);
        
        // Try to determine the type and size of the variable
        Symbol *sym = lookup(expr);
        if (sym) {
            int size = get_type_size(sym->type);
            total_size += size;

        } else {
            printf("Warning: Could not determine size of return value %s\n", expr);
        }
    }
    return;

    } else {
        generate_3ac_block(tree->left);
        generate_3ac_block(tree->right);
    }
}

char* generate_3ac_function_call(node *tree) {
    char temp[10000];
    if (strcmp(tree->token, "Function-Call") == 0) {
        node *funcName = tree->left;
        node *argListNode = tree->right->left->left;
        int total_param_size = 0;
        int arg_count = 0;

        // Process arguments if they exist
        if (argListNode != NULL) {
            node *argList = argListNode;
            while (argList != NULL) {
                if (strcmp(argList->token, "DONT") == 0) {
                    if (argList->right) {
                        char *arg = generate_3ac_expr(argList->right);
                        sprintf(temp, "         PushParam %s\n", arg);
                        add_to_buffer(temp);
                        total_param_size += get_type_size(checkExpressionType(argList->right));
                        arg_count++;
                    }
                    argList = argList->left;
                } else {
                    char *arg = generate_3ac_expr(argList);
                    sprintf(temp, "         PushParam %s\n", arg);
                    add_to_buffer(temp);
                    total_param_size += get_type_size(checkExpressionType(argList));
                    arg_count++;
                    break;
                }
            }
        }

        // Call function
        char *result = new_temp();
        sprintf(temp, "         %s = LCall %s\n", result, funcName->left->token);
        add_to_buffer(temp);
        
        // Pop parameters only if there were arguments
        if (arg_count > 0) {
            sprintf(temp, "         PopParams %d\n", total_param_size);
            add_to_buffer(temp);
        }

        // Find the function in local_funcs array
        for (int i = 0; i < local_func_count; i++) {
            if (strcmp(local_funcs[i].name, funcName->left->token) == 0) {
                int size = get_type_size(local_funcs[i].type);
                total_size += size;
                break;
            }
        }
        return result;
    }
    return NULL;
}

int get_type_size(char *type) {
    if (strcmp(type, "INT") == 0) return 4;
    if (strcmp(type, "DOUBLE") == 0) return 8;
    if (strcmp(type, "FLOAT") == 0) return 4;
    if (strcmp(type, "CHAR") == 0) return 1;
    if (strcmp(type, "BOOL") == 0) return 1;

    return 4;  // Default to int size
}

void generate_3ac_declaration(node *tree) {
    if (!tree) {
        return;
    }

    // Check if it's a String Declaration
    if (strcmp(tree->token, "String Declaration") == 0) {
        node *stringDeclList = tree->left;
        handleStringDeclList(stringDeclList);
    } else {
        // Handle other types of declarations
        node *typeNode = tree->left->left;
        node *idList = tree->left->right;
        if (!typeNode || !idList) {
            return;
        }
        handleIdListWithInit1(idList, typeNode->token);
    }
}

void handleStringDeclList(node *stringDeclList) {
    if (!stringDeclList) return;

    if (strcmp(stringDeclList->token, "DONT") == 0) {
        handleStringDeclList(stringDeclList->left);
        handleStringDeclList(stringDeclList->right);
    } else {
        handleStringDecl(stringDeclList);
    }
}

void handleStringDecl(node *stringDecl) {
    if (strcmp(stringDecl->token, "String") == 0) {
        char *stringName = stringDecl->left->token;
        node *sizeNode = stringDecl->right;
        int size = atoi(sizeNode->token);

        local_vars[local_var_count].name = strdup(stringName);
        local_vars[local_var_count].type = strdup("STRING");
        total_size += size;
        local_var_count++;

       // printf("String Declaration: %s[%d]\n", stringName, size);
    } else if (strcmp(stringDecl->token, "String Assignment") == 0) {
        char *stringName = stringDecl->left->token;
        node *sizeNode = stringDecl->right->left;
        int size = atoi(sizeNode->token);

        local_vars[local_var_count].name = strdup(stringName);
        local_vars[local_var_count].type = strdup("STRING");
        total_size += size;
        local_var_count++;

      //  printf("String Assignment: %s[%d]\n", stringName, size);

        // Handle assignment
        node *assignmentNode = stringDecl->right->right;
        if (assignmentNode) {
            char temp[100];
            sprintf(temp, "         %s = %s\n", stringName, assignmentNode->left->token);
            add_to_buffer(temp);
        }
    }
}

void handleIdListWithInit1(node *idList, char *type) {
    if (idList == NULL) return;

   // printf("token dec : '%s'\n", idList->token);

    if (strcmp(idList->token, "DONT") == 0) {
        handleIdListWithInit1(idList->left, type);
        handleIdListWithInit1(idList->right, type);
        return;
    }

    if (strcmp(idList->token, "ID_INIT") == 0) {
        local_vars[local_var_count].name = strdup(idList->left->token);
        local_vars[local_var_count].type = strdup(type);
         int size = get_type_size(local_vars[local_var_count].type);
	   total_size += size;
	  // printf("Total Size: '%d'\n ", total_size);
       // printf("Var: '%s' Type: '%s'\n", local_vars[local_var_count].name, local_vars[local_var_count].type);
        local_var_count++;

        char *result = generate_3ac_expr(idList->right->left);
         char temp[100];
        sprintf(temp,"         %s = %s\n", idList->left->token, result);
        add_to_buffer(temp);
    } else {
        local_vars[local_var_count].name = strdup(idList->token);
        local_vars[local_var_count].type = strdup(type);
     // printf("Var: '%s' Type: '%s'\n", local_vars[local_var_count].name, local_vars[local_var_count].type);
       int size = get_type_size(local_vars[local_var_count].type);
	   total_size += size;
	   	  // printf("Total Size: '%d'\n ", total_size);
        local_var_count++;
    }
}



//&&
char* generate_3ac_expr(node *expr) {
    if (!expr) return "";
  
    char temp[100];  // Temporary buffer for sprintf
    
     
    if (strcmp(expr->token, "+") == 0 || strcmp(expr->token, "-") == 0 ||
        strcmp(expr->token, "*") == 0 || strcmp(expr->token, "/") == 0) {
        char *left = generate_3ac_expr(expr->left);
        char *right = generate_3ac_expr(expr->right);
        
        // Check if left is already a temporary variable
        if (left[0] == 't' && isdigit(left[1])) {
            char *result = new_temp();
            sprintf(temp, "         %s = %s %s %s\n", result, left, expr->token, right);
            add_to_buffer(temp);
            return result;
        } else {
            char *result = new_temp();
            sprintf(temp, "         %s = %s %s %s\n", result, left, expr->token, right);
            add_to_buffer(temp);
            return result;
        }
    } 
    else if (expr->left == NULL && expr->right == NULL) {
        // This is a leaf node (variable or literal)
        return strdup(expr->token);
    }
    else if (strcmp(expr->token, "Function-Call") == 0) {
        return generate_3ac_function_call(expr);
    } 
    else if (strcmp(expr->token, "ARRAY_INDEX") == 0) {
        char *array = expr->left->token;
        char *index = generate_3ac_expr(expr->right);
        char *t1 = new_temp();
        char *t2 = new_temp();
        char *t3 = new_temp();
        char temp[100];
        sprintf(temp, "         %s = %s\n", t1, index);
        add_to_buffer(temp);
        
        sprintf(temp, "         %s = 1\n", t2);  
        add_to_buffer(temp);
        sprintf(temp, "         %s = %s * %s\n", t3, t1, t2);
        add_to_buffer(temp);
        char *result = new_temp();
        sprintf(temp, "         %s = %s + %s\n", result, array, t3);
        add_to_buffer(temp);
        total_size += 20;

         char *deref_result = malloc(strlen(result) + 2);
	    deref_result[0] = '*';
	    strcpy(deref_result + 1, result);

	    return deref_result;
    }
    else if (strcmp(expr->token, "ADDR_ARRAY_ELEM") == 0) {
        char *array = expr->left->token;
        char *index = generate_3ac_expr(expr->right);
        char *result = new_temp();
        sprintf(temp, "         %s = &%s[%s]\n", result, array, index);
        add_to_buffer(temp);
        return result;
    }
    else if (strcmp(expr->token, "& ADDRESS") == 0) {
        char *result = new_temp();
        sprintf(temp, "         %s = &%s\n", result, expr->left->token);
        add_to_buffer(temp);
        return result;
    }
    else if (strcmp(expr->token, "Derefernce") == 0) {
        char *operand = generate_3ac_expr(expr->left);
        char *result = new_temp();
        sprintf(temp, "         %s = *%s\n", result, operand);
        add_to_buffer(temp);
        return result;
    }
    else if (strcmp(expr->token, "UMINUS") == 0) {
        char *operand = generate_3ac_expr(expr->left);
        char *result = new_temp();
        sprintf(temp, "         %s = -%s\n", result, operand);
        add_to_buffer(temp);
        return result;
    }
    else if (strcmp(expr->token, "!") == 0) {
        char *operand = generate_3ac_expr(expr->left);
        char *result = new_temp();
        sprintf(temp, "         %s = !%s\n", result, operand);
        add_to_buffer(temp);
        return result;
    }
    else if (strcmp(expr->token, "&&") == 0 || strcmp(expr->token, "||") == 0) {
        char *label_true = new_label();
        char *label_false = new_label();
      
        generate_3ac_condition(expr, label_true, label_false);
        return ""; // The condition handling is done in generate_3ac_condition
    }
    else if (strcmp(expr->token, "<") == 0 || strcmp(expr->token, ">") == 0 ||
             strcmp(expr->token, "<=") == 0 || strcmp(expr->token, ">=") == 0 ||
             strcmp(expr->token, "==") == 0 || strcmp(expr->token, "!=") == 0) {
        char *left = generate_3ac_expr(expr->left);
        char *right = generate_3ac_expr(expr->right);
        char *result = new_temp();
        for (int i = 0; i < local_var_count; i++) {
            if (strcmp(local_vars[i].name, left) == 0) {
                int size = get_type_size(local_vars[i].type);
                total_size += size;
              
            }
        }
        sprintf(temp, "         %s = %s %s %s\n", result, left, expr->token, right);
        add_to_buffer(temp);
        return result;
    }
    else if (expr->left == NULL && expr->right == NULL) {
        if (isLiteral(expr->token)) {
            char *result = new_temp();
            char* literalType = getLiteralType(expr->token);
            int size = get_type_size(literalType);
            //printf("token: '%s' , type '%s' , size '%d' \n",expr->token,literalType,size);
            total_size += size;
         
            sprintf(temp, "         %s = %s\n", result, expr->token);
            add_to_buffer(temp);
            return result;
        } else {
            return strdup(expr->token);
        }
    }
    
    return "";
}

////^^
char* generate_3ac_expr_for_condition(node *expr) {
    if (!expr) return "";
   // printf("generate_3ac_expr_for_condition token: %s\n",expr->token);
    char temp[100];
   
    if (strcmp(expr->token, "==") == 0 || strcmp(expr->token, "!=") == 0 ||
        strcmp(expr->token, "<") == 0 || strcmp(expr->token, ">") == 0 ||
        strcmp(expr->token, "<=") == 0 || strcmp(expr->token, ">=") == 0) {
        
        char *left = generate_3ac_expr(expr->left);
        char *right = generate_3ac_expr(expr->right);
        
        sprintf(temp, "%s %s %s", left, expr->token, right);
        return strdup(temp);
    } else  if(strcmp(expr->token,"(") == 0 ){
      return generate_3ac_expr_for_condition(expr->left);
    }
    
    return generate_3ac_expr(expr);
}

void generate_3ac_condition(node *condition, char *label_true, char *label_false) {
    if (!condition) return;

    if (strcmp(condition->token, "||") == 0) {
        generate_3ac_or_condition(condition, label_true, label_false);
        return;
    } else if (strcmp(condition->token, "&&") == 0) {
        generate_3ac_and_condition(condition, label_true, label_false);
        return;
    } else if (strcmp(condition->token, "(") == 0) {
        // Handle parenthesized expression
        generate_3ac_condition(condition->left, label_true, label_false);
        return;
    } else {
   
        printf("Condition token : %s \n" , condition->token);
        char *cond = generate_3ac_expr_for_condition(condition);
      
        char temp[100];
        sprintf(temp, "         if %s Goto %s\n", cond, label_true);
        
        add_to_buffer(temp);
        sprintf(temp, "         Goto %s\n", label_false);
        add_to_buffer(temp);
        free(cond);
        return;

    }
}

void generate_3ac_or_condition(node *condition, char *label_true, char *label_false) {
    char *label_next = new_label();
       char *cond = generate_3ac_expr_for_condition(condition->left);
    
    char temp[100];
    sprintf(temp, "         if %s Goto %s\n", cond, label_true);
        
        add_to_buffer(temp);
  
    
    generate_3ac_condition(condition->right, label_true, label_false);
}

void generate_3ac_and_condition(node *condition, char *label_true, char *label_false) {
    char *label_next = new_label();
    char *temp_var = new_temp();
	  //  printf("left_cond '%s' \n ",condition->left->token); 
    char *left_cond = generate_3ac_expr_for_condition(condition->left);
        //	    printf("left_cond '%s' \n ",left_cond); 
    char temp[100];
    sprintf(temp, "         %s = %s\n", temp_var, left_cond);
    add_to_buffer(temp);
    sprintf(temp, "         ifZ %s Goto %s\n", temp_var, label_false);
    add_to_buffer(temp);
    //printf("condition token '%s' \n ",condition->right->token); 
    generate_3ac_condition(condition->right, label_true, label_false);
    
    
}

void generate_3ac_if_block(node *tree) {
    char *label_true = new_label();
    char *label_false = new_label();
    char *label_end = new_label();
    
    char temp[100];

    generate_3ac_condition(tree->left, label_true, label_false);

    // True branch
    sprintf(temp, "%s:\n", label_true);
    add_to_buffer(temp);
    generate_3ac_block(tree->right->left);  // THEN part
    sprintf(temp, "         Goto %s\n", label_end);
    add_to_buffer(temp);

    // False branch
    sprintf(temp, "%s:\n", label_false);
    add_to_buffer(temp);
    if (tree->right->right) {  // If there's an ELSE part
        generate_3ac_block(tree->right->right->left);
    }

 
}

void generate_3ac_if_else_single(node *tree) {
    char *label_true = new_label();
    char *label_false = new_label();
    char *label_end = new_label();
    
    char temp[100];

    generate_3ac_condition(tree->left, label_true, label_false);

    sprintf(temp, "%s:\n", label_true);
    add_to_buffer(temp);
    generate_3ac_block(tree->right->left);  // THEN part
    sprintf(temp, "         Goto %s\n", label_end);
    add_to_buffer(temp);

    sprintf(temp, "%s:\n", label_false);
    add_to_buffer(temp);
    generate_3ac_block(tree->right->right);  // ELSE part

    sprintf(temp, "%s:\n", label_end);
    add_to_buffer(temp);
}

void generate_3ac_if_single(node *tree) {
    char *label_true = new_label();
    char *label_end = new_label();
    
    char temp[100];

    generate_3ac_condition(tree->left, label_true, label_end);

    sprintf(temp, "%s:\n", label_true);
    add_to_buffer(temp);
    generate_3ac_block(tree->right);  // single_stmt

    sprintf(temp, "%s:\n", label_end);
    add_to_buffer(temp);
}

void generate_3ac_if_else_block(node *tree) {
    //char *label1 = new_label();
    char *label_true = new_label();
    char *label_false = new_label();
    char *label_end = new_label();
    
    char temp[100];

    generate_3ac_condition(tree->left->left, label_true, label_false);

    sprintf(temp, "%s:\n", label_true);
    add_to_buffer(temp);
    generate_3ac_block(tree->left->right->left);  // THEN block_stmt
    sprintf(temp, "         Goto %s\n", label_end);
    add_to_buffer(temp);

    sprintf(temp, "%s:\n", label_false);
    add_to_buffer(temp);
    generate_3ac_block(tree->right->left);  // ELSE block_stmt

    sprintf(temp, "%s:\n", label_end);
    add_to_buffer(temp);
}
void generate_3ac_while(node *tree) {
    char *label_start = new_label();
    char *label_body = new_label();
    char *label_end = new_label();
    
    char temp[100];
    sprintf(temp, "%s:\n", label_start);
    add_to_buffer(temp);

    // Generate condition with short-circuit evaluation
    generate_3ac_condition(tree->left, label_body, label_end);

    sprintf(temp, "%s:\n", label_body);
    add_to_buffer(temp);
    generate_3ac_block(tree->right->left);  // Loop body
    sprintf(temp, "         Goto %s\n", label_start);
    add_to_buffer(temp);
    sprintf(temp, "%s:\n", label_end);
    add_to_buffer(temp);
}

void generate_3ac_do_while(node *tree) {
    char *label_start = new_label();
    char *label_cond = new_label();
    char *label_end = new_label();
    
    char temp[100];
    sprintf(temp, "%s:\n", label_start);
    add_to_buffer(temp);
    generate_3ac_block(tree->left->left);  // BODY part
    sprintf(temp, "%s:\n", label_cond);
    add_to_buffer(temp);

    // Generate condition with short-circuit evaluation
    generate_3ac_condition(tree->right->left, label_start, label_end);

    sprintf(temp, "%s:\n", label_end);
    add_to_buffer(temp);
}

void generate_3ac_for(node *tree) {
    char *label_init = new_label();
    char *label_cond = new_label();
    char *label_body = new_label();
    char *label_update = new_label();
    char *label_end = new_label();
    
    char temp[100];

    // Initialization
    sprintf(temp, "%s:\n", label_init);
    add_to_buffer(temp);
    generate_3ac_block(tree->left);

    // Condition
    sprintf(temp, "%s:\n", label_cond);
    add_to_buffer(temp);
    generate_3ac_condition(tree->right->left, label_body, label_end);

    // Body
    sprintf(temp, "%s:\n", label_body);
    add_to_buffer(temp);
    generate_3ac_block(tree->right->right->right->left);

    // Update
    sprintf(temp, "%s:\n", label_update);
    add_to_buffer(temp);
    generate_3ac_block(tree->right->right->left);
    sprintf(temp, "         Goto %s\n", label_cond);
    add_to_buffer(temp);

    // End of loop
    sprintf(temp, "%s:\n", label_end);
    add_to_buffer(temp);
}



int isLiteral(const char* token) {
    // Check if the token is a number (integer or float)
    char* endptr;
    strtol(token, &endptr, 10);
    if (*endptr == '\0') return 1;  // It's an integer
    strtod(token, &endptr);
    if (*endptr == '\0') return 1;  // It's a float

    // Check for other literal types (true, false, string literals, etc.)
    if (strcmp(token, "true") == 0 || strcmp(token, "false") == 0) return 1;
    if (token[0] == '"' && token[strlen(token)-1] == '"') return 1;  // String literal

    return 0;  // Not a literal
}
char* getLiteralType(const char* token) {
    char* endptr;
    
    // Check for integer
    strtol(token, &endptr, 10);
    if (*endptr == '\0') return "INT";
    

    // Check for float/double
    strtod(token, &endptr);
    if (*endptr == '\0') {
      strtod(token, &endptr);
        if ((strchr(token, 'f') != NULL || strchr(token, 'F') != NULL )&& strchr(token, '.') != NULL ) {
        char *endptr;
        strtof(token, &endptr);
        if (*endptr == 'f' || *endptr == 'F') {
           
            return "FLOAT";
        }

    	}else{
            return "DOUBLE";}
    }
    
    // Check for boolean
    if (strcmp(token, "true") == 0 || strcmp(token, "false") == 0) return "BOOL";
    
    // Check for char (assuming it's enclosed in single quotes)
    if (token[0] == '\'' && token[strlen(token)-1] == '\'' && strlen(token) == 3) return "CHAR";
    
    // If it's not any of the above, it might be a string or an identifier
    return "UNKNOWN";
}
void add_to_buffer(const char* instruction) {
    int len = strlen(instruction);
    if (buffer_index + len >= MAX_BUFFER_SIZE - 1) {
        fprintf(stderr, "Buffer overflow prevented. Current size: %d, Trying to add: %d\n", buffer_index, len);
        return;
    }
    strcpy(instruction_buffer + buffer_index, instruction);
    buffer_index += len;
   // printf("Buffer size after addition: %d\n", buffer_index);
  //  printf("'%s'\n",instruction);
}
void clear_buffer() {
    memset(instruction_buffer, 0, MAX_BUFFER_SIZE);
    buffer_index = 0;
}
