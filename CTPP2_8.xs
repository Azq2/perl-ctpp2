extern "C" {
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
}
#include "ctpp2.hpp"

#define RETURN_CLASS()

MODULE = HTML::CTPP2_8  PACKAGE = HTML::CTPP2_8
CTPP2 *
CTPP2::new(...)
CODE:
	if (items % 2 != 1)
		croak("Hash expected. ");
	
	unsigned int arg_stack_size = 10240, code_stack_size = 10240, 
		steps_limit = 1048576, max_functions = 1024;
	STLW::string source_charset, destination_charset;
	
	for (int i = 1; i < items; i += 2) {
		STRLEN key_len, val_len;
		const char *key = SvPV_const(ST(i), key_len);
		if (strncasecmp("arg_stack_size", key, key_len) == 0) {
			arg_stack_size = SvIV(ST(i + 1));
		} else if (strncasecmp("code_stack_size", key, key_len) == 0) {
			code_stack_size = SvIV(ST(i + 1));
		} else if (strncasecmp("steps_limit", key, key_len) == 0) {
			steps_limit = SvIV(ST(i + 1));
		} else if (strncasecmp("max_functions", key, key_len) == 0) {
			max_functions = SvIV(ST(i + 1));
		} else if (strncasecmp("source_charset", key, key_len) == 0) {
			source_charset = SvPV_const(ST(i + 1), val_len);
		} else if (strncasecmp("destination_charset", key, key_len) == 0) {
			destination_charset = SvPV_const(ST(i + 1), val_len);
		} else {
			croak("CTPP2: Unknown parameter name: `%s`", key);
		}
	}
	
	RETVAL = new CTPP2(arg_stack_size, code_stack_size, steps_limit, max_functions, source_charset, destination_charset);
OUTPUT:
	RETVAL

void
CTPP2::DESTROY()

SV *
CTPP2::load_bytecode(const char *filename)
CODE:
	Bytecode *b = THIS->parse(NULL, filename, Bytecode::T_BYTECODE);
	ST(0) = sv_newmortal();
	sv_setref_pv(ST(0), "HTML::CTPP2_8::Bytecode", (void*) b);
	XSRETURN(1);


SV *
CTPP2::parse_template(const char *filename)
CODE:
	Bytecode *b = THIS->parse(NULL, filename, Bytecode::T_SOURCE);
	ST(0) = sv_newmortal();
	sv_setref_pv(ST(0), "HTML::CTPP2_8::Bytecode", (void*) b);
	XSRETURN(1);



SV *
CTPP2::load_bytecode_string(SV *text)
CODE:
	Bytecode *b = THIS->parse(text, "direct source", Bytecode::T_TEXT_BYTECODE);
	ST(0) = sv_newmortal();
	sv_setref_pv(ST(0), "HTML::CTPP2_8::Bytecode", (void*) b);
	XSRETURN(1);


SV *
CTPP2::parse_text(SV *text)
CODE:
   Bytecode *b = THIS->parse(text, "direct source", Bytecode::T_TEXT_SOURCE);
	ST(0) = sv_newmortal();
	sv_setref_pv(ST(0), "HTML::CTPP2_8::Bytecode", (void*) b);
	XSRETURN(1);


SV *
CTPP2::dump_params()
CODE:
	RETVAL = THIS->dumpParams();
OUTPUT:
	RETVAL


SV *
CTPP2::get_last_error()
CODE:
	RETVAL = THIS->getLastError();
OUTPUT:
	RETVAL


int
CTPP2::include_dirs(AV *include_dirs)
CODE:
	THIS->setIncludeDirs(include_dirs);
	RETVAL = 0;
OUTPUT:
	RETVAL


SV *
CTPP2::output(Bytecode *bytecode, ...)
CODE:
	if (items != 2 && items != 4)
		croak("usage: output($bytecode) or output($bytecode, $charset_from, $charset_to)");
	
	SV *charset_src = NULL, *charset_dst = NULL;
	if (items == 4) {
		charset_src = ST(2);
		charset_dst = ST(3);
	}
	RETVAL = THIS->output(bytecode, charset_src, charset_dst);
OUTPUT:
	RETVAL

int
CTPP2::load_udf(const char *udf_path)
CODE:
	RETVAL = THIS->loadUDF(udf_path);
OUTPUT:
	RETVAL

int
CTPP2::json_param(SV *text)
CODE:
	STRLEN len;
	const char *json = SvPV_const(text, len);
	RETVAL = THIS->json(json, len);
OUTPUT:
	RETVAL


void
CTPP2::bind(const char *name, CV *func)


void
CTPP2::unbind(const char *name)


int
CTPP2::param(HV *params)
CODE:
	RETVAL = THIS->param((SV *) params);
OUTPUT:
	RETVAL


void
CTPP2::reset()
CODE:
	THIS->reset();


void
CTPP2::clear_params()
CODE:
	THIS->reset();


MODULE = HTML::CTPP2_8  PACKAGE = HTML::CTPP2_8::Bytecode
int
Bytecode::save(const char *filename)

SV *
Bytecode::data()

void
Bytecode::DESTROY()