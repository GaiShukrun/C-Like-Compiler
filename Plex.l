%{
#include "y.tab.h"
#include <string.h>
extern YYSTYPE yylval;
%}

%%
[ \t\n]+    { /* Ignore whitespace */ }
"if"        { return IF; }
"else"      { return ELSE; }
"+"         { return PLUS; }
"-"         { return MINUS; }
"*"         { return MUL; }
"/"         { return DIV; }
"<-"        { return ASS; }
"=="        { return EQ; }
"<="        { return LE; }
">="        { return GE; }
"("         { return '('; }
")"         { return ')'; }
"{"         { return '{'; }
"}"         { return '}'; }
[0-9]+      { yylval = mknode(strdup(yytext), NULL, NULL); return NUM; }
[a-zA-Z]+[a-zA-Z0-9_]* { yylval = mknode(strdup(yytext), NULL, NULL); return ID; }
.           { return yytext[0]; }

%%

int yywrap() {
    return 1;
}
