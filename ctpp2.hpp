#pragma once

#include <CDT.hpp>
#include <CTPP2Exception.hpp>
#include <CTPP2FileSourceLoader.hpp>
#include <CTPP2Parser.hpp>
#include <CTPP2ParserException.hpp>
#include <CTPP2StringOutputCollector.hpp>
#include <CTPP2SyscallFactory.hpp>
#include <CTPP2VM.hpp>
#include <CTPP2VMDebugInfo.hpp>
#include <CTPP2VMDumper.hpp>
#include <CTPP2VMException.hpp>
#include <CTPP2VMStackException.hpp>
#include <CTPP2VMExecutable.hpp>
#include <CTPP2VMMemoryCore.hpp>
#include <CTPP2VMOpcodeCollector.hpp>
#include <CTPP2VMSTDLib.hpp>
#include <CTPP2ErrorCodes.h>
#include <CTPP2Error.hpp>
#include <CTPP2SourceLoader.hpp>
#include <CTPP2Logger.hpp>
#include <CTPP2StringIconvOutputCollector.hpp>
#include <CTPP2JSONParser.hpp>

extern "C" {
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
}

#define cpp_free(a) if (a) { delete a; a = NULL; }
#define c_free(a) if (a) { free(a); a = NULL; }
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

using namespace CTPP;

class CTPP2;

// CTPPPerlSyscallHandler
class CTPPPerlSyscallHandler: public SyscallHandler {
	public:
		friend class STDLibInitializer;
		CTPPPerlSyscallHandler(const char *func_name, CV *perl_sub, CTPP2 *ctpp_ref);
		~CTPPPerlSyscallHandler() throw();
		INT_32 Handler(CDT *args, const UINT_32 args_n, CDT &ret, Logger &logger);
		CCHAR_P GetName() const;
	protected:
		CV *perl_sub;
		char *name;
		CTPP2 *ctpp;
};

// CTPPPerlLogger
class CTPPPerlLogger: public Logger {
	public:
		~CTPPPerlLogger() throw();
	private:
		INT_32 WriteLog(const UINT_32 priority, CCHAR_P str, const UINT_32 len);
};

// CTPPPerlOutputCollector
class CTPPPerlOutputCollector: public OutputCollector {
	public:
		CTPPPerlOutputCollector(SV *var);
		~CTPPPerlOutputCollector() throw();
		INT_32 Collect(const void *raw, const UINT_32 len);
	protected:
		SV *var;
};


// Загрузчик текстового исходного кода для CTPP2 (по указателю, без копирования)
class CTPP2RefTextSourceLoader: public CTPP2SourceLoader {
	protected:
		const char *text;
		STRLEN length;
		CTPP2FileSourceLoader file_loader;
	public:
		CTPP2RefTextSourceLoader(const char *txt, STRLEN len);
		CTPP2RefTextSourceLoader(SV *txt);
		CCHAR_P GetTemplate(UINT_32 &size);
		
		// Костыли для <TMPL_include>
		INT_32 LoadTemplate(CCHAR_P filename);
		void SetIncludeDirs(const STLW::vector<STLW::string> &include_dirs);
		CTPP2SourceLoader *Clone();
		
		~CTPP2RefTextSourceLoader() throw();
};

// Bytecode
class Bytecode {
	protected:
		VMMemoryCore *mem;
		VMExecutable *exe;
		unsigned int exe_size;
		
		void _compiler(CTPP2SourceLoader &loader, const char *name);
	public:
		friend class CTPP2;
		
		enum SourceType {
			T_TEXT_SOURCE = 0, 
			T_SOURCE = 1, 
			T_BYTECODE = 2, 
			T_TEXT_BYTECODE = 3
		};
		
		inline const VMMemoryCore *getCode() {
			return mem;
		}
		
		Bytecode(STLW::vector<STLW::string> &inc_dirs, SV *text, const char *filename, SourceType type);
		SV *data();
		int save(const char *filename);
		~Bytecode();
};

// CTPP2
class CTPP2 {
	protected:
		typedef STLW::map<STLW::string, SyscallHandler *> UserSyscallList;
		CTPPError error;
		CDT *params;
		VM *vm;
		SyscallFactory *syscalls;
		struct {
			bool convert;
			STLW::string src;
			STLW::string dst;
		} charset;
		STLW::vector<STLW::string> include_dirs;
		STLW::map<STLW::string, SyscallHandler *> user_syscalls;
		bool string_zero_to_int;
		Bytecode *last_bytecode;
		
		friend class Bytecode;
	public:
		typedef SyscallHandler *(*FnHandler)();
		
		static const FnHandler functions[];
		
		CTPP2(unsigned int arg_stack_size, unsigned int code_stack_size, unsigned int steps_limit, unsigned int max_functions, 
			STLW::string src_charset, STLW::string dst_charset, bool string_zero_to_int);
		int param(SV *var);
		int json(const char *json, unsigned int length);
		int loadUDF(const char *filename);
		void perl2cdt(SV *var, CDT *param);
		SV *cdt2perl(CDT *cdt);
		void json2cdt(const char *json, unsigned int length, CDT *cdt);
		static const char *svTypeName(SV *svt);
		CTPP2 *reset();
		Bytecode *parse(SV *text, const char *filename, Bytecode::SourceType type);
		SV *output(Bytecode *bytecode, SV *src_enc, SV *dst_enc);
		SV *dump();
		SV *getLastError();
		SV *dumpParams();
		void bind(const char *name, CV *func);
		void bind(SyscallHandler *sys);
		void unbind(const char *name);
		CTPP2 *setIncludeDirs(STLW::vector<STLW::string> &include_dirs);
		CTPP2 *setIncludeDirs(AV *include_dirs);
		~CTPP2();
};
