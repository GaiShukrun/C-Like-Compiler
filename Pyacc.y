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

#define YYSTYPE struct node*
%}

%token NUM PLUS MINUS ID IF ELSE EQ LE GE '(' ')' '{' '}' DIV MUL ASS
%left PLUS MINUS
%left DIV MUL
%nonassoc UMINUS
%nonassoc IFX
%nonassoc ELSE

%%

program: stmt_list { printtree(mknode("Program", $1, NULL), 0); }
       ;

stmt_list: stmt_list stmt { $$ = mknode("Sequence", $1, $2); }
         | stmt { $$ = $1; }
         ;

stmt: ass { $$ = $1; }
    | ST { $$ = $1; }
    | exp ';' { $$ = $1; }
    ;

ST: IF '(' cond ')' block_stmt { $$ = mknode("IF", $3, mknode("THEN", $5, mknode("BLOCK",NULL,NULL))); }
  | IF '(' cond ')' single_stmt { $$ = mknode("IF", $3, mknode("THEN", $5, NULL)); }
  | IF '(' cond ')' block_stmt ELSE block_stmt{$$=mknode("IF ELSE STMT",mknode("IF",$3,mknode("THEN",$5,mknode("BLOCK",NULL,NULL))),mknode("ELSE",$7,mknode("BLOCK",NULL,NULL)) );}

  | IF '(' cond ')' single_stmt ELSE single_stmt { $$ = mknode("IF-ELSE", $3, mknode("THEN", $5, mknode("ELSE", $7, NULL))); }
  | IF '(' cond ')' block_stmt ELSE single_stmt {$$ = mknode("IF ELSE STMT",mknode("IF",$3,mknode("THEN",$5,mknode("BLOCK",NULL,NULL))),mknode("ELSE",$7,NULL));}
  | IF '(' cond ')' single_stmt ELSE block_stmt { $$ = mknode("IF-ELSE",mknode("IF", $3, mknode("THEN", $5, NULL)),mknode("ELSE", $7, mknode("BLOCK",NULL,NULL))); }
  ;

block_stmt: '{' stmt_list '}' { $$ = mknode("BLOCK", $2, NULL); }
          ;

single_stmt: ass { $$ = $1; }
           | exp ';' { $$ = $1; }
           ;

ass:ID ASS exp ';' { $$ = mknode("ASSIGN", $1, $3); }
    ;

exp: exp PLUS exp { $$ = mknode("+", $1, $3); }
   | exp MINUS exp { $$ = mknode("-", $1, $3); }
   | exp MUL exp { $$ = mknode("*", $1, $3); }
   | exp DIV exp { $$ = mknode("/", $1, $3); }
   | '(' exp ')' { $$ = $2; }
   | MINUS exp %prec UMINUS { $$ = mknode("UMINUS", $2, NULL); }
   | NUM { $$ = $1 ;}
   | ID { $$ = $1 ;}
   ;

cond: exp '<' exp { $$ = mknode("<", $1, $3); }
    | exp '>' exp { $$ = mknode(">", $1, $3); }
    | exp EQ exp { $$ = mknode("==", $1, $3); }
    | exp LE exp { $$ = mknode("<=", $1, $3); }
    | exp GE exp { $$ = mknode(">=", $1, $3); }
    | exp { $$ = $1; }
    ;
%%
#include "lex.yy.c"

int main() {
    return yyparse();
}
void printtree(node *tree, int depth) {
    if (tree == NULL) return;

    
    for (int i = 0; i < depth; ++i){
        printf("| ");
        
    }
    printf("%s\n", tree->token);
    
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


