%%
if return IF;
else return ELSE;
"==" return EQ;
[ \t] ;
[ /n] ;
"(" return '(';
")" return ')';
"{" return '{';
"}" return '}';
[0-9]+ {return NUM; }
[a-zA-Z]+[a-zA-Z0-9_]* return ID;
"+" return PLUS;
"-" return MINUS;
"*" return MUL;

. return yytext[0];

%%

int yywrap(){
	return 1;
}
