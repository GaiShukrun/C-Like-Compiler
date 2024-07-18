%{

#include <string.h>
#include "y.tab.h"
extern YYSTYPE yylval;

%}
%x COMMENT
%option yylineno
%%
"/*"            { BEGIN(COMMENT); }
<COMMENT>"*/"   { BEGIN(INITIAL); }
<COMMENT>.|\n   { /* Ignore everything inside comments */ }
<COMMENT><<EOF>> { fprintf(stderr, "Error: Unclosed comment\n"); return 0; }
[ \t\n]+    { /* Ignore whitespace */ }

"if"        { return IF; }
"else"      { return ELSE; }
"while"     { return WHILE; }
"for"       { return FOR; }
"var"       { return VAR; }
"args>>"    { return ARGS; }
"public"    { return PUBLIC; }
"private"   { return PRIVATE; }
"static"    { return STATIC; }
"return"    { return RETURN; }
"null"      { return NULL_T; }
"void"      { return VOID; }
"do"        { return DO; }
"bool"      { return BOOL; }
"char"      { return CHAR; }
"int"       { return INT; }
"double"    { return DOUBLE; }
"float"     { return FLOAT; }
"string"    { return STRING; }
"int*"      { return INT_PTR; }
"char*"     { return CHAR_PTR; }
"double*"   { return DOUBLE_PTR; }
"float*"    { return FLOAT_PTR; }

"+"         { return PLUS; }
"-"         { return MINUS; }
"*"         { return MUL; }
"/"         { return DIV; }
"<-"        { return ASS; }
"=="        { return EQ; }
"!="        { return NEQ; }
"<="        { return LE; }
">="        { return GE; }
"("         { return '('; }
")"         { return ')'; }
"{"         { return '{'; }
"}"         { return '}'; }
"["	    {return '[';}
"]"         { return ']' ;}
"||"        { return OR; }
"&&"        { return AND; }
"!"         { return '!'; }
"<"         { return '<'; }
">"         { return '>'; }
"&"         { return '&'; }

"true"|"false" { yylval = mknode(strdup(yytext), NULL, NULL); return BOOL_LITERAL; }
'.'         { yylval = mknode(strdup(yytext), NULL, NULL); return CHAR_LITERAL; }
[0-9]+      { yylval = mknode(strdup(yytext), NULL, NULL); return INT_LITERAL; }
0[xX][0-9A-Fa-f]+ { yylval = mknode(strdup(yytext), NULL, NULL); return HEX_LITERAL; }
[0-9]+\.[0-9]+([eE][-+]?[0-9]+)? { yylval = mknode(strdup(yytext), NULL, NULL); return DOUBLE_LITERAL; }
[0-9]+(\.[0-9]+)?[fF] { yylval = mknode(strdup(yytext), NULL, NULL); return FLOAT_LITERAL; }
\"[^\"]*\"  { yylval = mknode(strdup(yytext), NULL, NULL); return STRING_LITERAL; }
[a-zA-Z][a-zA-Z0-9_]* { yylval = mknode(strdup(yytext), NULL, NULL); return ID; }



","         { return ','; }
.           { return yytext[0]; }

%%

int yywrap() {
    return 1;
}
