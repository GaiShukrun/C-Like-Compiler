%{
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int yylex(void);
int yyerror();
char *yytext;
typedef struct node {
    char *token;
    struct node *left;
    struct node *right;
} node;
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
program: global_list { printtree(mknode("Program", $1, NULL), 0); }
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
    | exp ';' { $$ = $1; }
    | RETURN exp ';' { $$ = mknode("RETURN", $2, NULL); }
    | RETURN ';' { $$ = mknode("RETURN", NULL, NULL); }
    ;
//single stmt for specific conditions like if(..)stmt , while(..)stmt etc.
single_stmt: ass { $$ = $1; }
           | exp ';' { $$ = $1; }
           | declaration { $$ = $1;}
           ;
           
declaration: VAR type ':' id_list ';' { $$ = mknode("Declaration", mknode("(",$2, $4),mknode(")",NULL,NULL)); } |
             STRING string_decl_list ';' { $$ = mknode("String Declaration", $2, NULL); }
                  ;

string_decl_list: string_decl { $$ = $1; }
                | string_decl_list ',' string_decl { $$ = mknode("DONT", $1, $3); }
                ;

string_decl: ID '[' exp ']' { $$ = mknode("String", $1, $3); }
           | ID '[' exp ']' ASS STRING_LITERAL  { $$ = mknode("String Assignment", NULL,mknode($1->token,
mknode("[",$3,NULL),mknode("]",$6,NULL))); }
           ;


       
type: BOOL {$$ =mknode("BOOL",NULL,NULL);}| CHAR {$$ =mknode("CHAR",NULL,NULL);}| INT {$$ =mknode("INT",NULL,NULL);} 
    | DOUBLE {$$ =mknode("DOUBLE",NULL,NULL);}|FLOAT {$$ =mknode("FLOAT",NULL,NULL);}
    | INT_PTR {$$ =mknode("INT Pointer",NULL,NULL);}  | CHAR_PTR {$$ =mknode("CHAR Pointer",NULL,NULL);}| DOUBLE_PTR {$$ =mknode("DOUBLE Pointer",NULL,NULL);}| FLOAT_PTR {$$ =mknode("FLOAT Pointer",NULL,NULL);}
    ;
    
ST: IF '(' cond_exp ')' block_stmt { $$ = mknode("IF", $3, mknode("THEN", $5, mknode("BLOCK)",NULL,NULL))); }
  | IF '(' cond_exp ')' single_stmt { $$ = mknode("IF", $3, mknode("THEN", $5, NULL)); }
  | IF '(' cond_exp ')' block_stmt ELSE block_stmt{$$=mknode("IF ELSE STMT",mknode("IF",$3,mknode("THEN",$5,mknode("BLOCK)",NULL,NULL))),mknode("ELSE",$7,mknode("BLOCK)",NULL,NULL)) );}
  | IF '(' cond_exp ')' single_stmt ELSE single_stmt { $$ = mknode("IF-ELSE", $3, mknode("THEN", $5, mknode("ELSE", $7, NULL))); }
  | IF '(' cond_exp')' block_stmt ELSE single_stmt {$$ = mknode("IF ELSE STMT",mknode("IF",$3,mknode("THEN",$5,mknode("BLOCK)",NULL,NULL))),mknode("ELSE",$7,NULL));}
  | IF '(' cond_exp ')' single_stmt ELSE block_stmt { $$ = mknode("IF-ELSE",mknode("IF", $3, mknode("THEN", $5, NULL)),mknode("ELSE", $7, mknode("BLOCK)",NULL,NULL))); }
  
  
  | WHILE '(' cond_exp ')' block_stmt { $$ = mknode("WHILE", $3, mknode("THEN", $5, mknode("BLOCK)",NULL,NULL))); }
  
  | DO block_stmt  WHILE '(' exp ')' ';'
    { $$ = mknode("DO-WHILE", 
                  mknode("BODY", $2, mknode("BLOCK)",NULL,NULL)), 
                  mknode("CONDITION", $5, NULL)); }
  

  
  | FOR '(' ass_no_semi ';' exp ';' ass_no_semi ')' block_stmt 
    { $$ = mknode("FOR", 
                  $3,  // INIT
                  mknode("COND", $5, 
                         mknode("UPDATE", $7, 
                                mknode("THEN", $9, mknode("BLOCK)",NULL,NULL))))); }
  | FOR '(' ass_no_semi ';' exp ';' ass_no_semi ')' stmt
    { $$ = mknode("FOR", 
                  $3,  // INIT
                  mknode("COND", $5, 
                         mknode("UPDATE", $7, 
                                mknode("THEN", $9, NULL)))); };
 
block_stmt: '{' declarations statements '}' { $$ = mknode("(BLOCK", $2, $3); }
//block_stmt: '{' global_list '}' { $$ = mknode("(BLOCK", $2, NULL); }
          ;
          
declarations: declaration declarations { $$ = mknode("DONT", $1, $2); }
            | /* empty */ { $$ = mknode("DONT", NULL, NULL); }
            ;

statements: stmt statements { $$ = mknode("DONT", $1, $2); }
          | /* empty */ { $$ = mknode("DONT", NULL, NULL); }
          ; 
ass:ID ASS exp ';' { $$ = mknode("ASSIGN", $1, mknode("<-",$3,NULL)); }
    ;
ass_no_semi: ID ASS exp { $$ = mknode("ASSIGN", $1, mknode("<-",$3,NULL)); }
           | 
           ;
cond_exp: cond {$$ = mknode("DONT",mknode("(",$1,NULL),mknode(")",NULL,NULL));};

cond:
    '(' exp ')' { $$ = mknode("DONT",mknode("(",$2,NULL),mknode(")",NULL,NULL)); }
   |exp '<' exp { $$ = mknode("<", $1, $3); }
   | exp '>' exp { $$ = mknode(">", $1, $3); }
   | exp EQ exp { $$ = mknode("==", $1, $3); }
   | exp LE exp { $$ = mknode("<=", $1, $3); }
   | exp GE exp { $$ = mknode(">=", $1, $3); }
   | exp NEQ exp { $$ = mknode("!=",$1,$3);}
   | '!'exp { $$ = mknode("!",$2,NULL);}
   | exp AND exp {$$ = mknode("&&",$1,$3);}
   | exp OR exp {$$ = mknode("||",$1,$3);}
   | NULL_T { $$ = mknode("NULL", NULL, NULL); }
   | function_call { $$ = $1; }
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
   | '|'ID'|' {$$ = mknode("String-Length-of",$1,NULL);}
   ;

argument_list: argument_list ',' exp { $$ = mknode("DONT", $1, $3); }
             | exp { $$ = $1; }
             | /* empty */ { $$ = mknode("DONT", NULL, NULL); }
             ;
%%
#include "lex.yy.c"
int main() {
    return yyparse();
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
    return 0;
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
