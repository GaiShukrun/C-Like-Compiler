%{
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>
#include <ctype.h>
#define TABLE_SIZE 100 


jmp_buf exception_buf;
#define TRY if (setjmp(exception_buf) == 0)
#define CATCH else
#define THROW longjmp(exception_buf, 1)


int yylex(void);
int yyerror();
char *yytext;
int mainFunctionCount = 0;

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
        // You can add more types here if needed
    } data;
    struct Symbol *next;
} Symbol;

typedef struct {
    Symbol *table[TABLE_SIZE];
} SymbolTable;



SymbolTable symbolTable;

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


node *syntax_tree;


void postorderTraversal(node *tree) ;
void processNode(node *tree);
void handleDeclaration(node *tree);
void handleStringDeclaration(node *tree);
void handleAssignment(node *tree);
void handleFunctionDeclaration(node *tree) ;
void handleFunctionDefinition(node *tree) ;
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
void checkArgumentsRecursive(Function *func, node *argNode, int argIndex);

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
           | stmt { $$ = mknode("DONT",mknode("(",$1,NULL),mknode(")",NULL,NULL));  }
           | declaration { $$ = $1; }
           ;

function: function_declaration { $$ = $1; }
        | function_definition { $$ = $1; }
        ;
function_call: ID '(' argument_list ')' { $$ = mknode("Function-Call", mknode("Function-Name",$1,NULL),
mknode("DONT",mknode("(Parameter_List",$3,NULL),mknode(")",NULL,NULL))); }
             ;
             
function_declaration: access_modifier return_type ID '(' args parameter_list ')' optional_static ';'
                      { $$ = mknode("Function-Declaration", 
                                    mknode("Function_Signature", mknode("DONT",$1,$2),mknode("Function-Name",$3,NULL)),mknode("DONT",mknode("(Args>>",$6,NULL),mknode(")",$7,$8))); }

                    ;

function_definition: access_modifier return_type ID '(' args parameter_list ')' optional_static block_stmt
                  {$$ = mknode("Function-Definition",mknode("DONT",mknode("Function-Modifier-return_type",$1,$2),mknode("Function-Name",$3,NULL)),mknode("DONT",$8,mknode("DONT",
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
    | exp ';' { 
     $$ = $1; 
     }
    | RETURN exp ';' { $$ = mknode("RETURN", $2, NULL); }
    | RETURN ';' { $$ = mknode("RETURN", NULL, NULL); }
    ;
//single stmt for specific conditions like if(..)stmt , while(..)stmt etc.
single_stmt: ass { $$ = $1; }
           | exp ';' { 
           $$ = $1;
           
           
           }
           | declaration { $$ = $1;}
           ;
           
//declaration: VAR type ':' id_list ';' { $$ = mknode("Declaration", mknode("(",$2, $4),mknode(")",NULL,NULL)); } |
 //            STRING string_decl_list ';' { $$ = mknode("String Declaration", $2, NULL); }
  //                ;

declaration: VAR type ':' id_list ';' 
             { 
               $$ = mknode("Declaration", mknode("(",$2, $4),mknode(")",NULL,NULL));          
            }
           | STRING string_decl_list ';' 
             { 
               $$ = mknode("String Declaration", $2, NULL);               
             }
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
 
block_stmt: '{' declarations statements '}' { $$ = mknode("(BLOCK", $2, $3); }
//block_stmt: '{' global_list '}' { $$ = mknode("(BLOCK", $2, NULL); }
          ;
          
declarations: declaration declarations { $$ = mknode("DONT", $1, $2); }
            | /* empty */ { $$ = mknode("DONT", NULL, NULL); }
            ;

statements: stmt statements { $$ = mknode("DONT", $1, $2); }
          | /* empty */ { $$ = mknode("DONT", NULL, NULL); }
          ; 
//ass:ID ASS exp ';' { $$ = mknode("ASSIGN", $1, mknode("<-",$3,NULL)); }
  //  ;
ass: ID ASS exp ';' 
     { 
       $$ = mknode("ASSIGN", $1, mknode("<-",$3,NULL)); 
     }
   ;
ass_no_semi: ID ASS exp { 
        $$ = mknode("ASSIGN", $1, mknode("<-",$3,NULL)); 
        }
           | 
           ;


exp: exp PLUS exp { $$ = mknode("+", $1, $3); }
   | exp MINUS exp { $$ = mknode("-", $1, $3); }
   | exp MUL exp { $$ = mknode("*", $1, $3); }
   | exp DIV exp { $$ = mknode("/", $1, $3); }
   | '(' exp ')' { $$ = mknode("DONT",mknode("Left Parenthesis",$2,NULL),mknode("Right Parenthesis",NULL,NULL)); } // You asked to print ( and ) for indentation  purposes ,
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
   | '&' ID {$$ =mknode("& ADDRESS",$2,NULL);}
   | ID { $$ = $1; }
   | MUL ID {$$ = mknode("Derefernce",$2,NULL);}
   | NULL_T { $$ = mknode("NULL", NULL, NULL); }
   | function_call { $$ = $1; }
   | '|'ID'|' {
       $$ = $2;
   }
   ;

argument_list: argument_list ',' exp { $$ = mknode("DONT", $1, $3); }
             | exp { $$ = $1; }
             | /* empty */ { $$ = mknode("DONT", NULL, NULL); }
             ;
%%
#include "lex.yy.c"
int main() {
    initSymbolTable();
    int result = yyparse();
     mainFunctionCount = 0;
    if (result == 0) {  // If parsing was successful
        postorderTraversal(syntax_tree);
    }
    //printtree(syntax_tree,0);
    printSymbolTable();
    freeSymbolTable();
    return result;
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
    fprintf(stderr, "Parse error at line %d: %s near '%s'\n", yylineno, msg, yytext);
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
    if(lookup(name) == NULL){
    unsigned int index = hash(name);
    Symbol *newSymbol = (Symbol *)malloc(sizeof(Symbol));
    newSymbol->name = strdup(name);
    newSymbol->type = strdup(type);
    newSymbol->next = symbolTable.table[index];
    symbolTable.table[index] = newSymbol;
    }else{
      fprintf(stderr, "Error: Identifier '%s' already declared.\n", name);
      THROW;
    }
}
void insertIdList(node *idList, char *type) {
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

Symbol *lookup(char *name) {
    unsigned int index = hash(name);
    Symbol *current = symbolTable.table[index];
    while (current != NULL) {
        if (strcmp(current->name, name) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

int areTypesCompatible(char *type1, char *type2) {
    return strcmp(type1, type2) == 0;
}

void semanticCheck(char *leftSide, char *rightSide,int line) {
    Symbol *leftSymbol = lookup(leftSide);
    Symbol *rightSymbol = lookup(rightSide);

    if (leftSymbol == NULL ) {
        fprintf(stderr, "Semantic Error1: Variable '%s' is not declared\n", leftSide);
        THROW;
    }


    char *rightType;
    if (strcmp(rightSide, "DOUBLE") == 0 || 
        strcmp(rightSide, "FLOAT") == 0 || 
        strcmp(rightSide, "INT") == 0 || 
        strcmp(rightSide, "BOOL") == 0 || 
        strcmp(rightSide, "CHAR") == 0 || 
        strcmp(rightSide, "STRING") == 0) {
        rightType = rightSide;
    }else{    
	    if (rightSymbol != NULL) {
	     // 115 and 49 is for | | , we need to convert the exp to int when a |string| accurs .
		if (rightSide[0] == 115 && rightSide[strlen(rightSide)-1] == 49) {
		    if (strcmp(rightSymbol->type, "STRING") == 0) {
		        rightType = "INT";  // String length is always an integer
		    } else {
		       
		        fprintf(stderr, "Semantic Error at line %d: | | Operator works only on STRING, got '%s'\n",line, rightSymbol->type);
		        THROW;
		    }
		} else {
		    rightType = rightSymbol->type;
		}
	    } else {
		// Right side is a literal or expression, infer its type
		rightType = inferType(rightSide);
		if(strcmp(rightType,"UNKNOWN") == 0){
			fprintf(stderr, "Semantic Error at like %d: Variable '%s' is not declared\n",line, rightSide);
			THROW;
		}
	    }
	}
    if (!areTypesCompatible(leftSymbol->type, rightType)) {
        fprintf(stderr, "Semantic Error at line %d: Type mismatch in assignment. '%s' (%s) <- '%s' (%s)\n",
                line,leftSide, leftSymbol->type, rightSide, rightType);
        THROW;
    }
}

char* inferType(char *value) {
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
    if (strchr(value, 'f') != NULL || strchr(value, 'F') != NULL) {
        char *endptr;
        strtof(value, &endptr);
        if (*endptr == 'f' || *endptr == 'F') {
            return "FLOAT";
        }
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
    if (expr == NULL) {
        return "UNKNOWN";
    }
  
    if( strcmp(expr->token, "DONT") == 0 && expr->left !=NULL && strcmp(expr->left->token,"Left Parenthesis") == 0 ){
    
       return checkExpressionType(expr->left->left);
    }

   
    if (expr->left == NULL && expr->right == NULL) {
        //fprintf(stderr, "'%s'\n",expr->token);
        // For literals, the token itself should be the type
        if (strcmp(expr->token, "INT_LITERAL") == 0) return "INT";
      
       if (strcmp(expr->token, "NULL") == 0) return "NULL";
       if (strcmp(expr->token, "true") == 0 || strcmp(expr->token, "false") == 0) {
             return "BOOL"; // Boolean literal
	    }
	if (expr->token[0] == '\'' && expr->token[2] == '\'' && strlen(expr->token) == 3) {
		return "CHAR"; // Character literal
	    }
	if (expr->token[0] == '\"' && expr->token[strlen(expr->token) - 1] == '\"') {
		return "STRING"; // String literal
	    }
        
        
         // If it's a number literal, determine its type
        if (isdigit(expr->token[0]) || expr->token[0] == '-' || expr->token[0] == '+') {
           
            return inferType(expr->token);
        }
        
        
        
		// If it's an identifier, look up its type
	Symbol *sym = lookup(expr->token);
	   if (sym != NULL) {    
           return sym->type;
	   }else{
	   
	      return expr->token;
	   }
        
        
        return "UNKNOWN";
    }

    // Handle unary operators
    if (expr->left != NULL && expr->right == NULL) {
        if (strcmp(expr->token, "!") == 0) return "BOOL";
        if (strcmp(expr->token, "UMINUS") == 0) return checkExpressionType(expr->left);
        if (strcmp(expr->token, "& ADDRESS") == 0) {
            char* type = checkExpressionType(expr->left);
            // This should return a pointer type based on the operand type
            return type;  // Modify this to return the correct pointer type
        }
        if (strcmp(expr->token, "Derefernce") == 0) {
            char* type = checkExpressionType(expr->left);
            // This should return the dereferenced type
            return type;  // Modify this to return the correct dereferenced type
        }
        if (strcmp(expr->token, "String-Length-of") == 0) return "INT";
    }

    // Handle binary operators
    char *leftType = checkExpressionType(expr->left);
  //  char *leftType = checkExpresint isStatic;  // 1 if static, 0 if notsionType(expr->left);
    char *rightType = checkExpressionType(expr->right);

    // Arithmetic operators
    if (strcmp(expr->token, "+") == 0 || strcmp(expr->token, "-") == 0 ||
        strcmp(expr->token, "*") == 0 || strcmp(expr->token, "/") == 0) {
	    int doubleCount = 0;
	    int hasFloat = 0;
	    int allInt = 1;

	    // Check left operand
	    if (strcmp(leftType, "DOUBLE") == 0) doubleCount++;
	    else if (strcmp(leftType, "FLOAT") == 0) hasFloat = 1;
	    else if (strcmp(leftType, "INT") != 0) allInt = 0;

	    // Check right operand
	    if (strcmp(rightType, "DOUBLE") == 0) doubleCount++;
	    else if (strcmp(rightType, "FLOAT") == 0) hasFloat = 1;
	    else if (strcmp(rightType, "INT") != 0) allInt = 0;

	    if (doubleCount > 1) return "FLOAT";
	    if (doubleCount == 1) return "DOUBLE";
	    if (hasFloat) return "FLOAT";
	    if (allInt) return "INT";

	    fprintf(stderr, "Semantic Error: Invalid operands for arithmetic operation\n");
	    THROW;
    }
    
    // Comparison operators
    if (strcmp(expr->token, "<") == 0 || strcmp(expr->token, ">") == 0 ||
        strcmp(expr->token, "<=") == 0 || strcmp(expr->token, ">=") == 0 ||
        strcmp(expr->token, "==") == 0 || strcmp(expr->token, "!=") == 0 ||
        strcmp(expr->token, "&&") == 0 || strcmp(expr->token, "||") == 0
     //   || strcmp(expr->token, "true") == 0 || strcmp(expr->token, "false") == 0 
         )
        {
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

    if (strcmp(tree->token, "Declaration") == 0 || 
        strcmp(tree->token, "String Declaration") == 0) {
        handleDeclaration(tree);
    } else if (strcmp(tree->token, "ASSIGN") == 0) {
        handleAssignment(tree);
    } else if (strcmp(tree->token, "Function-Declaration") == 0) {
        handleFunctionDeclaration(tree);
    } else if (strcmp(tree->token, "Function-Definition") == 0) {
        handleFunctionDefinition(tree);
    } else if (strcmp(tree->token, "Function-Call") == 0) {
        handleFunctionCall(tree);
    }
}

void handleDeclaration(node *tree) {
    if (strcmp(tree->token, "Declaration") == 0) {
        // Regular variable declaration
        if (tree->left && strcmp(tree->left->token, "(") == 0) {
            node *typeNode = tree->left->left;
            node *idListNode = tree->left->right;
            if (typeNode && idListNode) {
                insertIdList(idListNode, typeNode->token);
            }
        }
    } else if (strcmp(tree->token, "String Declaration") == 0) {
        // String declaration
        handleStringDeclaration(tree->left);
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
    char *leftSide = tree->left->token;
    node *rightSide = tree->right->left;
    
    char *rightType;
    if (strcmp(rightSide->token, "Function-Call") == 0) {
        rightType = getFunctionReturnType(rightSide);
    } else {
        rightType = checkExpressionType(rightSide);
    }
    
    semanticCheck(leftSide, rightType, yylineno);
}
char* getFunctionReturnType(node *functionCall) {
    node *funcNameNode = functionCall->left;
    if (funcNameNode && strcmp(funcNameNode->token, "Function-Name") == 0) {
        Symbol *sym = lookup(funcNameNode->left->token);
        if (sym && strcmp(sym->type, "FUNCTION") == 0) {
            return sym->data.func->returnType;
        }
    }
    return "UNKNOWN";
}
void handleFunctionDeclaration(node *tree) {
    node *functionSignature = tree->left;
    node *argsList = tree->right;
    
    if (functionSignature && strcmp(functionSignature->token, "Function_Signature") == 0) {
        node *modifierAndType = functionSignature->left;
        node *funcName = functionSignature->right;
        
        if (modifierAndType && funcName && 
            strcmp(modifierAndType->token, "DONT") == 0 &&
            strcmp(funcName->token, "Function-Name") == 0) {
            
            char *access = modifierAndType->left ? modifierAndType->left->token : "UNKNOWN";
            char *returnType = modifierAndType->right ? modifierAndType->right->token : "UNKNOWN";
            char *funcNameStr = funcName->left ? funcName->left->token : "UNKNOWN";
            
            int isStatic = 0;
            if (argsList && strcmp(argsList->token, "DONT") == 0) {
                node *staticNode = argsList->right->right; // The optional_static is the right child of the ")" node
                if (staticNode && strcmp(staticNode->token, "STATIC") == 0) {
                    isStatic = 1;
                }
            }
            
            // Handle parameters
            Parameter *args = NULL;
            int argCount = 0;
            if (argsList && strcmp(argsList->token, "DONT") == 0) {
                node *argsNode = argsList->left;
                if (argsNode && strcmp(argsNode->token, "(Args>>") == 0) {
                    args = getParameters(argsNode->left, &argCount);
                }
            }
            
            // Insert function declaration into symbol table
            insertFunction(funcNameStr, access, returnType, args, argCount, isStatic);
            
            // Free the temporary args array
            if (args) {
                for (int i = 0; i < argCount; i++) {
                    free(args[i].name);
                    free(args[i].type);
                }
                free(args);
            }
        }
    }
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
            
            // Handle parameters
            Parameter *args = NULL;
            int argCount = 0;
            if (bodyNode && bodyNode->right && strcmp(bodyNode->right->token, "DONT") == 0) {
                node *argsNode = bodyNode->right->left;
                if (argsNode && strcmp(argsNode->token, "(Args>>") == 0) {
                    args = getParameters(argsNode->left, &argCount);
                }
            }
            
            // Check if it's the main function
            if (strcmp(funcNameStr, "main") == 0) {
                if (strcmp(access, "Public") != 0 || !isStatic || 
                    strcmp(returnType, "void") != 0 || argCount != 0) {
                    fprintf(stderr, "Error: main function must be public static void main() with no arguments\n");
                    THROW;
                }
                if (mainFunctionCount > 0) {
                    fprintf(stderr, "Error: Multiple main functions defined\n");
                    THROW;
                }
                mainFunctionCount++;
            } else {
                // For non-main functions, check if they were declared
                Symbol *existing = lookup(funcNameStr);
                if (!existing || strcmp(existing->type, "FUNCTION") != 0) {
                    fprintf(stderr, "Error: Function '%s' defined without declaration\n", funcNameStr);
                    THROW;
                }
                
                // Check if the definition matches the declaration
                Function *declaredFunc = existing->data.func;
                if (strcmp(declaredFunc->access, access) != 0) {
                    fprintf(stderr, "Error: Access modifier mismatch for function '%s'\n", funcNameStr);
                    THROW;
                }
                if (strcmp(declaredFunc->returnType, returnType) != 0) {
                    fprintf(stderr, "Error: Return type mismatch for function '%s'\n", funcNameStr);
                    THROW;
                }
                if (declaredFunc->isStatic != isStatic) {
                    fprintf(stderr, "Error: Static modifier mismatch for function '%s'\n", funcNameStr);
                    THROW;
                }
                if (declaredFunc->argCount != argCount) {
                    fprintf(stderr, "Error: Argument count mismatch for function '%s'\n", funcNameStr);
                    THROW;
                }
                for (int i = 0; i < argCount; i++) {
                    if (strcmp(declaredFunc->args[i].type, args[i].type) != 0) {
                        fprintf(stderr, "Error: Argument type mismatch for function '%s', argument %d\n", funcNameStr, i+1);
                        THROW;
                    }
                    // Note: We don't check argument names as they can be different in declaration and definition
                }
            }
            node *blockNode = NULL;
            if (bodyNode && bodyNode->right && bodyNode->right->right) {
                blockNode = bodyNode->right->right->left; // Navigate to the actual block
            }
            
            if (blockNode) {
                int hasReturn = 0;
                checkFunctionReturnType(blockNode, returnType, funcNameStr, &hasReturn);
                
                if (!hasReturn && strcmp(returnType, "void") != 0) {
                    fprintf(stderr, "Semantic Error: Non-void function '%s' has no return statement\n", funcNameStr);
                    THROW;
                }
            }
            
            // Free the temporary args array
            if (args) {
                for (int i = 0; i < argCount; i++) {
                    free(args[i].name);
                    free(args[i].type);
                }
                free(args);
            }
        }
    }
}
void checkFunctionReturnType(node *blockNode, char *expectedReturnType, char *funcName, int *hasReturn) {
    if (blockNode == NULL) return;
    
    if (strcmp(blockNode->token, "RETURN") == 0) {
        *hasReturn = 1;
        if (blockNode->left == NULL) {
            // Empty return statement
            if (strcmp(expectedReturnType, "void") != 0) {
                fprintf(stderr, "Semantic Error: Function '%s' with return type '%s' has an empty return statement\n", 
                        funcName, expectedReturnType);
                THROW;
            }
        } else {
            // Return with expression
            char *actualReturnType = checkExpressionType(blockNode->left);
            if (!areTypesCompatible(expectedReturnType, actualReturnType)) {
                fprintf(stderr, "Semantic Error: Function '%s' returns '%s', but '%s' was expected\n", 
                        funcName, actualReturnType, expectedReturnType);
                THROW;
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
    if (existing && strcmp(existing->type, "FUNCTION") == 0) {
       // printf("Warning: Function '%s' already declared. Ignoring redeclaration.\n", name);
        return;
    }

    // Create new symbol for the function
    Symbol *newSymbol = (Symbol *)malloc(sizeof(Symbol));
    if (!newSymbol) {
      //  printf("Error: Memory allocation failed for new symbol\n");
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



void handleFunctionCall(node *tree) {
    if (strcmp(tree->token, "Function-Call") == 0) {
        node *funcName = tree->left;
        node *argListNode = tree->right;
        
        if (funcName && strcmp(funcName->token, "Function-Name") == 0) {
            Symbol *sym = lookup(funcName->left->token);
            if (sym == NULL || strcmp(sym->type, "FUNCTION") != 0) {
                fprintf(stderr, "Semantic Error: Function '%s' not declared\n", funcName->left->token);
                THROW;
            }
            
            Function *func = sym->data.func;
          
            
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
        fprintf(stderr, "Semantic Error: Function '%s' called with wrong number of arguments. Expected %d, got %d\n", 
                func->name, func->argCount, argCount);
        THROW;
    }
    
    checkArgumentsRecursive(func, argList, 0);
}

void checkArgumentsRecursive(Function *func, node *argNode, int argIndex) {
    if (argNode == NULL) return;

    if (strcmp(argNode->token, "DONT") == 0) {
        checkArgumentsRecursive(func, argNode->left, argIndex);
        checkArgumentsRecursive(func, argNode->right, argIndex + 1);
    } else {
        Symbol *sym = lookup(argNode->token);
        if (sym == NULL) {
            fprintf(stderr, "Semantic Error: Undeclared variable '%s' used as argument in function call to '%s'\n", 
                    argNode->token, func->name);
            THROW;
        }
        
        // Check if the argument type matches the parameter type
        if (argIndex < func->argCount && !areTypesCompatible(func->args[argIndex].type, sym->type)) {
            fprintf(stderr, "Semantic Error: Type mismatch for argument '%s' in function call to '%s'. Expected %s, got %s\n", 
                    argNode->token, func->name, func->args[argIndex].type, sym->type);
            THROW;
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
//~
