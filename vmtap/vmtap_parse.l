%{

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <xenctrl.h>

char *yy_domain;
char *yy_symbol;
unsigned long yy_offset;
domid_t yy_domid;
bool yy_return;

%}

id        [A-Za-z_][A-Za-z_0-9]*
digit     [0-9]
nzd       [1-9]
hexdigit  {digit}|[A-Fa-f]
decint    {nzd}{digit}*|0+
hexint    "0"[xX]{hexdigit}+
intnum    {decint}|{hexint}

ws        [ \t]
delim     "."

dom_name  {id}
dom_id    {decint}

kernel    "kernel"

fn        "function"
fn_open   "("
fn_close  ")"
fn_name   {id}
fn_delim  ":"
fn_offset {intnum}

call      "call"
return    "return"

%x KERNEL FN_OPEN FN_NAME FN_DELIM FN_OFFSET FN_CLOSE FN_VAR

%%

<INITIAL>^{ws}+ { /* Do nothing. */ }
<INITIAL>{dom_name} { BEGIN(KERNEL); strcpy(yy_domain, yytext); }
<INITIAL>{dom_id} { BEGIN(KERNEL); yy_domid = atoi(yytext); }

<KERNEL>{ws}*{delim}{ws}*{kernel} { BEGIN(FN_OPEN); }

<FN_OPEN>{ws}*{delim}{ws}*{fn}{ws}*{fn_open}{ws}* { BEGIN(FN_NAME); }
<FN_NAME>{fn_name} { BEGIN(FN_DELIM); strcpy(yy_symbol, yytext); }
<FN_DELIM>{ws}*{fn_close} { BEGIN(FN_VAR); }
<FN_DELIM>{fn_delim} { BEGIN(FN_OFFSET); }
<FN_OFFSET>{fn_offset} { BEGIN(FN_CLOSE); yy_offset = atoi(yytext); }
<FN_CLOSE>{ws}*{fn_close} { BEGIN(FN_VAR); }

<FN_VAR>{ws}*{delim}{ws}*{call}{ws}* { BEGIN(INITIAL); yy_return = false; }
<FN_VAR>{ws}*{delim}{ws}*{return}{ws}* { BEGIN(INITIAL); yy_return = true; }

<*>. { return -1; }

%%

int yywrap(void)
{
    /* Called at EOF. */
	BEGIN(0);
	YY_FLUSH_BUFFER;
    return 1 ;
}

bool
__parse_probepoint(const char *probepoint, /* in */
                   char *domain, /* out */
                   char *symbol, /* out */
                   unsigned long *offset, /* out */
                   domid_t *domid) /* out */
{
    YY_BUFFER_STATE yybs;
    int ret;
    (void)yyunput;

    yy_domain = domain;
    yy_symbol = symbol;
    yy_offset = 0;
    yy_domid = 0;
    yy_return = false;

    yybs = yy_scan_string(probepoint);
    ret = yylex();
    yy_delete_buffer(yybs);

    if (ret == -1)
    {
        fprintf(stderr, "failed to parse probepoint \"%s\"", probepoint);
        return false;
    }

    *offset = yy_offset;
    *domid = yy_domid;

    return true;
}
