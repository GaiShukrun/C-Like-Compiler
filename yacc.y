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
%token NUM PLUS MINUS ID IF ELSE EQ '(' ')' '{' '}' DIV MUL
%left PLUS MINUS
%left DIV MUL

%%
s: exp { printf("OK\n"); printtree($1, 0); }
 | ST {  printtree(mknode("Program",$1,NULL), 0);} 
 ;
 
exp: exp PLUS exp{ $$ = mknode("+", $1, $3); }
    | exp MINUS exp{ $$ = mknode("-", $1, $3); }
    | exp MUL exp { $$ = mknode("*", $1, $3); }
    | exp DIV exp { $$ = mknode("/", $1, $3); }
    | '(' exp ')' { $$ = mknode(" ",mknode("(",$2,NULL),mknode(")",NULL,NULL)); }
    | NUM { $$ = mknode(yytext, NULL, NULL); }
    ;
    
ST: IF '(' cond ')' '{' stmt_list '}' ELSE '{' stmt_list '}' 
                                 { $$ = mknode("IF-ELSE", $3, mknode("BLOCK", $6, mknode("BLOCK", $10, NULL))); }
   | IF '(' cond ')' '{' stmt_list '}' { $$ = mknode("IF", $3, mknode("BLOCK", $6, NULL)); }
   ;
	
//else_op: ELSE '{' ass '}' { $$ = mknode("ELSE", $3, NULL); }
//        | /* empty */  { $$ = NULL; }
//        ;
stmt_list: stmt_list stmt { $$ = mknode("", $1, $2); }
         | /* empty */ { $$ = NULL; }
         ;

stmt: ass { $$ = $1; }
     | ST { $$ = $1; }
     ;

ass: temp1 '=' exp ';' { $$ = mknode("", mknode("(ASSIGN",$1, $3),mknode(")",NULL,NULL)); }

    | exp ';' { $$ = $1; }
    ;

    
cond: temp '<' temp { $$ = mknode(" ", mknode("(<", $1, $3), mknode(")", NULL, NULL)); }
    | temp '>' temp { $$ = mknode(">", $1, $3); }
    | temp EQ temp { $$ = mknode("EQ", $1, $3); }
    ;
    
temp:exp 
    | ID { $$ = mknode(yytext, NULL, NULL); }
    ;
temp1:ID { $$ = mknode(yytext, NULL, NULL); }
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

