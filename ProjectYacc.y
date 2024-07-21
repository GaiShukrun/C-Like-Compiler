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
typedef struct node {
    char *token;
    struct node *left;
    struct node *right;
} node;

typedef struct Symbol {
    char *name;
    char *type;
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
mknode("Program", $1, NULL);
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
                                    mknode("Function_Signature", mknode("DONT",$1,$2),mknode("Function-Name",$3,NULL)),mknode("DONT",mknode("(Args>>",$6,NULL),mknode(")",$7,NULL))); }

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
           | VOID { $$ = $1; }
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
     char* expType = checkExpressionType($1);
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
         
               insertIdList($4, $2->token);
              
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
             char* expType = checkExpressionType($3);
             
	       if(strcmp(expType,"INT") != 0 ){ 
	       fprintf(stderr, "Semantic Error at line %d: [ ] must contain a int literal , got '%s' \n", yylineno, expType);
	       THROW;     
	     }
             insert($1->token, "STRING");
           }
           | ID '[' exp ']' ASS exp  
           { 
             $$ = mknode("String Assignment", $1, mknode("[",$3,mknode("]",$6,NULL)));
              char* expType = checkExpressionType($3);
	       if(strcmp(expType,"INT") != 0 ){ 
	       fprintf(stderr, "Semantic Error at line %d: [ ] must contain a int literal , got '%s' \n", yylineno, expType);
	       THROW;     
	     }
	     expType = checkExpressionType($6);
	     if(strcmp(expType,"STRING") != 0 ){ 
	       fprintf(stderr, "Semantic Error at line %d : incorrect assignment, must assign STRING, got '%s'\n", yylineno,expType);
	       THROW;     
	     }
             //semanticCheck($1->token, $6->token,yylineno);
             insert($1->token, "STRING");
             
           }
           ;


       
type: BOOL {$$ =mknode("BOOL",NULL,NULL);}| CHAR {$$ =mknode("CHAR",NULL,NULL);}| INT {$$ =mknode("INT",NULL,NULL);} 
    | DOUBLE {$$ =mknode("DOUBLE",NULL,NULL);}|FLOAT {$$ =mknode("FLOAT",NULL,NULL);}
    | INT_PTR {$$ =mknode("INT Pointer",NULL,NULL);}  | CHAR_PTR {$$ =mknode("CHAR Pointer",NULL,NULL);}| DOUBLE_PTR {$$ =mknode("DOUBLE Pointer",NULL,NULL);}| FLOAT_PTR {$$ =mknode("FLOAT Pointer",NULL,NULL);}
    ;
    
ST: IF '(' exp ')' block_stmt { 
	      $$ = mknode("IF", $3, mknode("THEN", $5, mknode("BLOCK)",NULL,NULL)));
	       char* expType = checkExpressionType($3);
	       if(strcmp(expType,"BOOL") != 0 ){
		       fprintf(stderr, "Semantic Error at line %d: Condition expression must be of type BOOL, got '%s' \n", yylineno, expType);
		       THROW; 
	       }
}

  | IF '(' exp ')' single_stmt { 
	  $$ = mknode("IF", $3, mknode("THEN", $5, NULL)); 
	  char* expType = checkExpressionType($3);
	  if(strcmp(expType,"BOOL") != 0 ){
		     fprintf(stderr, "Semantic Error at line %d: Condition expression must be of type BOOL, got '%s' \n", yylineno, expType);
		     THROW;
	    }
  }
  
  | IF '(' exp ')' block_stmt ELSE block_stmt{
	  $$=mknode("IF ELSE STMT",mknode("IF",$3,mknode("THEN",$5,mknode("BLOCK)",NULL,NULL))),mknode("ELSE",     $7,mknode("BLOCK)",NULL,NULL)) );
	  char* expType = checkExpressionType($3);
	  if(strcmp(expType,"BOOL") != 0 ){  
		       fprintf(stderr, "Semantic Error at line %d: Condition expression must be of type BOOL, got '%s' \n", yylineno, expType);
		       THROW;
	       }
       }
  | IF '(' exp ')' single_stmt ELSE single_stmt { 
       $$ = mknode("IF-ELSE", $3, mknode("THEN", $5, mknode("ELSE", $7, NULL))); 
       char* expType = checkExpressionType($3);
       if(strcmp(expType,"BOOL") != 0 ){
		      fprintf(stderr, "Semantic Error at line %d: Condition expression must be of type BOOL, got '%s' \n", yylineno, expType);
		      THROW;
              }
       }
  | IF '(' exp')' block_stmt ELSE single_stmt { 
       $$ = mknode("IF ELSE STMT",mknode("IF",$3,mknode("THEN",$5,mknode("BLOCK)",NULL,NULL))),mknode("ELSE",$7,NULL));
       char* expType = checkExpressionType($3);
       if(strcmp(expType,"BOOL") != 0 ){
	       fprintf(stderr, "Semantic Error at line %d: Condition expression must be of type BOOL, got '%s' \n", yylineno, expType);
	       THROW;
               }
       }
  | IF '(' exp ')' single_stmt ELSE block_stmt { 
       $$ = mknode("IF-ELSE",mknode("IF", $3, mknode("THEN", $5, NULL)),mknode("ELSE", $7, mknode("BLOCK)",NULL,NULL)));
       char* expType = checkExpressionType($3);
       if(strcmp(expType,"BOOL") != 0 ){
	       fprintf(stderr, "Semantic Error at line %d: Condition expression must be of type BOOL, got '%s' \n", yylineno, expType);
	       THROW;  
               }
       }
  
  
  | WHILE '(' exp ')' block_stmt { 
      $$ = mknode("WHILE", $3, mknode("THEN", $5, mknode("BLOCK)",NULL,NULL))); 
      char* expType = checkExpressionType($3);
       if(strcmp(expType,"BOOL") != 0 ){  
	       fprintf(stderr, "Semantic Error at line %d: Condition expression must be of type BOOL, got '%s' \n", yylineno, expType);
	       THROW;
       
               }
       }
       
  
  | DO block_stmt  WHILE '(' exp ')' ';'
    { 
       $$ = mknode("DO-WHILE",mknode("BODY", $2,mknode("BLOCK)",NULL,NULL)),mknode("CONDITION", $5, NULL));
       char* expType = checkExpressionType($5);
       if(strcmp(expType,"BOOL") != 0 ){
	       fprintf(stderr, "Semantic Error at line %d: Condition expression must be of type BOOL, got '%s' \n", yylineno, expType);
	       THROW;   
             }
    }
  

  
  | FOR '(' ass_no_semi ';' exp ';' ass_no_semi ')' block_stmt 
    { 
    	$$ = mknode("FOR",$3,mknode("COND", $5, mknode("UPDATE", $7, mknode("THEN", $9, mknode("BLOCK)",NULL,NULL)))));
    	char* expType = checkExpressionType($5);
        if(strcmp(expType,"BOOL") != 0 ){
        fprintf(stderr, "Semantic Error at line %d: Condition expression must be of type BOOL, got '%s' \n", yylineno, expType);
        THROW;
       }
    }
  | FOR '(' ass_no_semi ';' exp ';' ass_no_semi ')' stmt
    { $$ = mknode("FOR", $3, mknode("COND", $5,mknode("UPDATE", $7, mknode("THEN", $9, NULL))));
       char* expType = checkExpressionType($5);
        if(strcmp(expType,"BOOL") != 0 ){
        fprintf(stderr, "Semantic Error at line %d: Condition expression must be of type BOOL, got '%s' \n", yylineno, expType);
        THROW;
       }
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
       char* expType = checkExpressionType($3);
       semanticCheck($1->token, expType,yylineno);
     }
   ;
ass_no_semi: ID ASS exp { 
        $$ = mknode("ASSIGN", $1, mknode("<-",$3,NULL)); 
        char* expType = checkExpressionType($3);
         semanticCheck($1->token, expType,yylineno);
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
   // return yyparse();
    initSymbolTable();
    int result = yyparse();
    printSymbolTable();  // Print symbol table after parsing
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







void printSymbolTable() {
    printf("Symbol Table:\n");
    for (int i = 0; i < TABLE_SIZE; i++) {
        Symbol *current = symbolTable.table[i];
        while (current != NULL) {
            printf("Name: %s, Type: %s\n", current->name, current->type);
            current = current->next;
        }
    }
}

void freeSymbolTable() {
    for (int i = 0; i < TABLE_SIZE; i++) {
        Symbol *current = symbolTable.table[i];
        while (current != NULL) {
            Symbol *next = current->next;
            free(current->name);
            free(current->type);
            free(current);
            current = next;
        }
        symbolTable.table[i] = NULL;
    }
}




char* checkExpressionType(node *expr) {
    if (expr == NULL) {
        return "UNKNOWN";
    }
  
    if( strcmp(expr->token, "DONT") == 0 && expr->left !=NULL && strcmp(expr->left->token,"Left Parenthesis") == 0 ){
    
       return checkExpressionType(expr->left->left);
    }
    // Handle string array declaration
  //  if (strcmp(expr->token, "String") == 0) {
        
        // Check if the size expression is an integer
    //    char* sizeType = checkExpressionType(expr->right);
        //if (strcmp(sizeType, "INT") != 0) {
      //      fprintf(stderr, "Semantic Error: Array size must be an integer\n");
          //  THROW;
        //}
        //return "STRING";
   // }

   
    if (expr->left == NULL && expr->right == NULL) {
        //fprintf(stderr, "'%s'\n",expr->token);
        // For literals, the token itself should be the type
        if (strcmp(expr->token, "INT_LITERAL") == 0) return "INT";
        //if (strcmp(expr->token, "HEX_LITERAL") == 0) return "INT";
        //if (strcmp(expr->token, "DOUBLE_LITERAL") == 0) return "DOUBLE";
        //if (strcmp(expr->token, "FLOAT_LITERAL") == 0) return "FLOAT";
        //if (strcmp(expr->token, "BOOL_LITERAL") == 0) return "BOOL";
        //if (strcmp(expr->token, "CHAR_LITERAL") == 0) return "CHAR";
        //if (strcmp(expr->token, "STRING_LITERAL") == 0) return "STRING";
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
