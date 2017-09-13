#include "ctpp2.hpp"
using namespace CTPP;

// CTPPPerlSyscallHandler
CTPPPerlSyscallHandler::CTPPPerlSyscallHandler(const char *func_name, CV *sub, CTPP2 *ctpp_ref) {
	name = strdup(func_name);
	perl_sub = sub;
	ctpp = ctpp_ref;
}
INT_32 CTPPPerlSyscallHandler::Handler(CDT *args, const UINT_32 args_n, CDT &ret, Logger &logger) {
	ret = CDT(CTPP::CDT::UNDEF);
	
	dSP;
	ENTER; SAVETMPS; PUSHMARK(SP);
	
	for (unsigned int i = args_n; i-- > 0; )
		XPUSHs(sv_2mortal(ctpp->cdt2perl(&args[i])));
	
	PUTBACK;
	call_sv((SV *) perl_sub, G_SCALAR);
	SPAGAIN;
	
	SV *ret_sv_var = POPs;
	try {
		ctpp->perl2cdt(ret_sv_var, &ret);
	} catch (...) {
		PUTBACK;
		FREETMPS; LEAVE;
		warn("CTPPPerlSyscallHandler: Some bullshit when callings perl sub. ");
		throw;
	}
	PUTBACK;
	FREETMPS; LEAVE;
	
	return 0;
}
CCHAR_P CTPPPerlSyscallHandler::GetName() const {
	return name;
}
CTPPPerlSyscallHandler::~CTPPPerlSyscallHandler() throw() {
	free(name);
}

// CTPPPerlLogger
CTPPPerlLogger::~CTPPPerlLogger() throw() { }
INT_32 CTPPPerlLogger::WriteLog(const UINT_32 priority, CCHAR_P str, const UINT_32 len) {
	warn("ERROR: %.*s", len, str);
	return 0;
}

// CTPP2RefTextSourceLoader
CTPP2RefTextSourceLoader::CTPP2RefTextSourceLoader(const char *txt, STRLEN len) {
	text = txt;
	length = len;
}
CTPP2RefTextSourceLoader::CTPP2RefTextSourceLoader(SV *txt) {
	text = SvPV_const(txt, length);
}
CCHAR_P CTPP2RefTextSourceLoader::GetTemplate(UINT_32 &size) {
	size = length;
	return text;
}
INT_32 CTPP2RefTextSourceLoader::LoadTemplate(CCHAR_P filename) {
	return file_loader.LoadTemplate(filename);
}
void CTPP2RefTextSourceLoader::SetIncludeDirs(const STLW::vector<STLW::string> &include_dirs) {
	file_loader.SetIncludeDirs(include_dirs);
}
CTPP2SourceLoader *CTPP2RefTextSourceLoader::Clone() {
	// Возвращает лоадер для include()
	return file_loader.Clone();
}
CTPP2RefTextSourceLoader::~CTPP2RefTextSourceLoader() throw() { }


// CTPPPerlOutputCollector
CTPPPerlOutputCollector::CTPPPerlOutputCollector(SV *v) {
	this->var = v;
}
INT_32 CTPPPerlOutputCollector::Collect(const void *raw, const UINT_32 len) {
	sv_catpvn(var, (const char *) raw, len);
	return 0;
}
CTPPPerlOutputCollector::~CTPPPerlOutputCollector() throw() { }

// CTPP2
CTPP2::CTPP2(unsigned int arg_stack_size, unsigned int code_stack_size, unsigned int steps_limit, unsigned int max_functions, 
	STLW::string src_charset, STLW::string dst_charset, bool arg_string_zero_to_int) {
	
	string_zero_to_int = arg_string_zero_to_int;
	
	try {
		params = new CDT(CDT::HASH_VAL);
		syscalls = new SyscallFactory(max_functions);
		STDLibInitializer::InitLibrary(*syscalls);
		vm = new VM(syscalls, arg_stack_size, code_stack_size, steps_limit);
		
		int i = 0;
		while (functions[i])
			bind(functions[i++]());
		
		if (src_charset.size() && dst_charset.size()) {
			charset.src = src_charset;
			charset.dst = dst_charset;
			charset.convert = true;
		} else {
			// Конвертирование не требуется
			charset.convert = false;
		}
	} catch (...) {
		cpp_free(params);
		if (syscalls) {
			STDLibInitializer::DestroyLibrary(*syscalls);
			cpp_free(syscalls);
		}
		cpp_free(vm);
		
		croak("CTPP2: Unrecoverable error at %s:%d (%s)", __FILE__, __LINE__, __FUNCTION__);
	}
}

void CTPP2::bind(SyscallHandler *sys) {
	SyscallHandler *h = syscalls->GetHandlerByName(sys->GetName());
	if (h) {
		throw CTPPLogicError("Cannot redefine function!");
	} else {
		syscalls->RegisterHandler(sys);
		user_syscalls[sys->GetName()] = sys;
	}
}

void CTPP2::bind(const char *name, CV *func) {
	SyscallHandler *h = syscalls->GetHandlerByName(name);
	if (h) {
		croak("CTPP2: Cannot redefine udf %s", name);
	} else {
		CTPPPerlSyscallHandler *handler = new CTPPPerlSyscallHandler(name, func, this);
		syscalls->RegisterHandler(handler);
		user_syscalls[name] = handler;
	}
}

void CTPP2::unbind(const char *name) {
	SyscallHandler *h = syscalls->GetHandlerByName(name);
	if (!h) {
		croak("CTPP2: Cannot unbind unknown udf %s", name);
	} else {
		UserSyscallList::iterator it;
		if ((it = user_syscalls.find(name)) != user_syscalls.end()) {
			delete h;
			user_syscalls.erase(it);
		}
		syscalls->RemoveHandler(name);
	}
}

int CTPP2::loadUDF(const char *filename) {
	croak("CTPP2: // Nothing todo. =)\n");
}

Bytecode *CTPP2::parse(SV *text, const char *filename, Bytecode::SourceType type) {
	try {
		return new Bytecode(include_dirs, text, filename, type);
	} catch (CTPPParserSyntaxError &e) {
		error = CTPPError(filename, e.what(), CTPP_COMPILER_ERROR | CTPP_SYNTAX_ERROR, e.GetLine(), e.GetLinePos(), 0);
	} catch (CTPPParserOperatorsMismatch& e) {
		error = CTPPError(filename, STLW::string("Expected ") + e.Expected() + ", but found " + e.Found(), CTPP_COMPILER_ERROR | CTPP_SYNTAX_ERROR, e.GetLine(), e.GetLinePos(), 0);
	} catch (CTPPUnixException &e) {
		error = CTPPError(filename, e.what(), CTPP_COMPILER_ERROR | CTPP_UNIX_ERROR, 0, 0, 0);
	} catch (CDTRangeException &e) {
		error = CTPPError(filename, e.what(), CTPP_COMPILER_ERROR | CTPP_RANGE_ERROR, 0, 0, 0);
	} catch (CDTAccessException &e) {
		error = CTPPError(filename, e.what(), CTPP_COMPILER_ERROR | CTPP_ACCESS_ERROR, 0, 0, 0);
	} catch (CDTTypeCastException &e) {
		error = CTPPError(filename, e.what(), CTPP_COMPILER_ERROR | CTPP_TYPE_CAST_ERROR, 0, 0, 0);
	} catch (CTPPLogicError &e) {
		error = CTPPError(filename, e.what(), CTPP_COMPILER_ERROR | CTPP_LOGIC_ERROR, 0, 0, 0);
	} catch (CTPPException &e) {
		error = CTPPError(filename, e.what(), CTPP_COMPILER_ERROR | CTPP_UNKNOWN_ERROR, 0, 0, 0);
	} catch (STLW::exception &e) {
		error = CTPPError(filename, e.what(), CTPP_COMPILER_ERROR | STL_UNKNOWN_ERROR, 0, 0, 0);
	} catch (...) {
		error = CTPPError(filename, "Unknown Error", CTPP_COMPILER_ERROR | STL_UNKNOWN_ERROR, 0, 0, 0);
	}
	
	warn("CTPP2: In file %s at line %d, pos %d: %s (error code 0x%08X)", 
		error.template_name.c_str(), error.line, error.pos, error.error_descr.c_str(), error.error_code);
	return NULL;
}

CTPP2 *CTPP2::setIncludeDirs(AV *include_dirs) {
	int len = av_len(include_dirs) + 1;
	
	if (this->include_dirs.size() > 0)
		this->include_dirs.clear();
	
	const char *val; STRLEN val_len;
	for (int i = 0; i < len; ++i) {
		SV *el = *(av_fetch(include_dirs, i, FALSE));
		if (!SvPOK(el) || SvTYPE(el) != SVt_PV) {
			warn("CTPP2: Not string at array index %d", i);
			continue;
		}
		val = SvPV_const(el, val_len);
		this->include_dirs.push_back(STLW::string(val, val_len));
	}
	
	return this;
}

SV *CTPP2::output(Bytecode *bytecode, SV *src_enc, SV *dst_enc) {
	unsigned int IP = 0;
	try {
		if (charset.convert || (src_enc && dst_enc)) {
			STLW::string src_charset, dst_charset;
			if (src_enc && dst_enc) {
				const char *val; STRLEN len;
				val = SvPV_const(src_enc, len);
				src_charset = STLW::string(val, len);
				val = SvPV_const(dst_enc, len);
				dst_charset = STLW::string(val, len);
			} else {
				src_charset = charset.src;
				dst_charset = charset.dst;
			}
			
			STLW::string result;
			CTPPPerlLogger logger;
			StringIconvOutputCollector output_collector(result, src_charset, dst_charset, 3);
			vm->Init(bytecode->getCode(), &output_collector, &logger);
			vm->Run(bytecode->getCode(), &output_collector, IP, *params, &logger);
			return newSVpv(result.data(), result.length());
		} else {
			SV *out = newSVpv("", 0);
			CTPPPerlLogger logger;
			CTPPPerlOutputCollector output_collector(out);
			vm->Init(bytecode->mem, &output_collector, &logger);
			vm->Run(bytecode->mem, &output_collector, IP, *params, &logger);
			return out;
		}
	} catch (ZeroDivision &e) {
		error = CTPPError(e.GetSourceName(), e.what(), CTPP_VM_ERROR | CTPP_ZERO_DIVISION_ERROR, VMDebugInfo(e.GetDebugInfo()).GetLine(), 
			VMDebugInfo(e.GetDebugInfo()).GetLinePos(), e.GetIP());
	} catch (ExecutionLimitReached &e) {
		error = CTPPError(e.GetSourceName(), e.what(), CTPP_VM_ERROR | CTPP_EXECUTION_LIMIT_REACHED_ERROR, VMDebugInfo(e.GetDebugInfo()).GetLine(), 
			VMDebugInfo(e.GetDebugInfo()).GetLinePos(), e.GetIP());
	} catch (CodeSegmentOverrun &e) {
		error = CTPPError(e.GetSourceName(), e.what(), CTPP_VM_ERROR | CTPP_CODE_SEGMENT_OVERRUN_ERROR, VMDebugInfo(e.GetDebugInfo()).GetLine(), 
			VMDebugInfo(e.GetDebugInfo()).GetLinePos(), e.GetIP());
	} catch (InvalidSyscall &e) {
		if (e.GetIP() != 0) {
			error = CTPPError(e.GetSourceName(), e.what(), CTPP_VM_ERROR | CTPP_INVALID_SYSCALL_ERROR, VMDebugInfo(e.GetDebugInfo()).GetLine(), 
				VMDebugInfo(e.GetDebugInfo()).GetLinePos(), e.GetIP());
		} else {
			error = CTPPError(e.GetSourceName(), STLW::string("Unsupported syscall: \"") + e.what() + "\"", CTPP_VM_ERROR | CTPP_INVALID_SYSCALL_ERROR, 
				VMDebugInfo(e.GetDebugInfo()).GetLine(), VMDebugInfo(e.GetDebugInfo()).GetLinePos(), e.GetIP());
		}
	} catch (IllegalOpcode &e) {
		error = CTPPError(e.GetSourceName(), e.what(), CTPP_VM_ERROR | CTPP_ILLEGAL_OPCODE_ERROR, VMDebugInfo(e.GetDebugInfo()).GetLine(), 
			VMDebugInfo(e.GetDebugInfo()).GetLinePos(), e.GetIP());
	} catch (StackOverflow &e) {
		error = CTPPError(e.GetSourceName(), e.what(), CTPP_VM_ERROR | CTPP_STACK_OVERFLOW_ERROR, VMDebugInfo(e.GetDebugInfo()).GetLine(), 
			VMDebugInfo(e.GetDebugInfo()).GetLinePos(), e.GetIP());
	} catch (StackUnderflow &e) {
		error = CTPPError(e.GetSourceName(), e.what(), CTPP_VM_ERROR | CTPP_STACK_UNDERFLOW_ERROR, VMDebugInfo(e.GetDebugInfo()).GetLine(),
			VMDebugInfo(e.GetDebugInfo()).GetLinePos(), e.GetIP());
	} catch (VMException &e) {
		error = CTPPError(e.GetSourceName(), e.what(), CTPP_VM_ERROR | CTPP_VM_GENERIC_ERROR, VMDebugInfo(e.GetDebugInfo()).GetLine(),
			VMDebugInfo(e.GetDebugInfo()).GetLinePos(), e.GetIP());
	} catch (CTPPUnixException &e) {
		error = CTPPError("", e.what(), CTPP_VM_ERROR | CTPP_UNIX_ERROR, 0, 0, IP);
	} catch (CDTRangeException &e) {
		error = CTPPError("", e.what(), CTPP_VM_ERROR | CTPP_RANGE_ERROR, 0, 0, IP);
	} catch (CDTAccessException &e) {
		error = CTPPError("", e.what(), CTPP_VM_ERROR | CTPP_ACCESS_ERROR, 0, 0, IP);
	} catch (CDTTypeCastException &e) {
		error = CTPPError("", e.what(), CTPP_VM_ERROR | CTPP_TYPE_CAST_ERROR, 0, 0, IP);
	} catch (CTPPLogicError &e) {
		error = CTPPError("", e.what(), CTPP_VM_ERROR | CTPP_LOGIC_ERROR, 0, 0, IP);
	} catch(CTPPCharsetRecodeException &e) {
		error = CTPPError("", e.what(), CTPP_VM_ERROR | CTPP_CHARSET_RECODE_ERROR, 0, 0, 0);
	} catch (CTPPException &e) {
		error = CTPPError("", e.what(), CTPP_VM_ERROR | CTPP_UNKNOWN_ERROR, 0, 0, IP);
	} catch (STLW::exception &e) {
		error = CTPPError("", e.what(), CTPP_VM_ERROR | STL_UNKNOWN_ERROR, 0, 0, IP);
	} catch (...) {
		error = CTPPError("", "Unknown Error", CTPP_VM_ERROR | STL_UNKNOWN_ERROR, 0, 0, IP);
	}
	vm->Reset();
	
	if (error.line > 0) {
		warn("output(): %s (error code 0x%08X); IP: 0x%08X, file %s line %d pos %d", error.error_descr.c_str(),
			error.error_code, error.ip, error.template_name.c_str(), error.line, error.pos);
	} else {
		warn("output(): %s (error code 0x%08X); IP: 0x%08X", error.error_descr.c_str(), error.error_code, error.ip);
	}
	
	return newSVpv("", 0);
}

CTPP2::~CTPP2() {
	for (UserSyscallList::iterator it = user_syscalls.begin(), end = user_syscalls.end(); it != end; ++it)
		delete it->second;
	if (vm)
		delete vm;
	if (params)
		delete params;
	if (syscalls) {
		STDLibInitializer::DestroyLibrary(*syscalls);
		delete syscalls;
	}
}

SV *CTPP2::dumpParams() {
	try {
		STLW::string str = params->RecursiveDump();
		return newSVpv(str.data(), str.length());
	} catch (...) {
		warn("CTPP2: Dump params failed. ");
	}
	return newSVpv("", 0);
}

CTPP2 *CTPP2::reset() {
	delete params;
	params = new CDT(CDT::HASH_VAL);
	return this;
}

int CTPP2::param(SV *var) {
	perl2cdt(var, params);
	return  0;
}

int CTPP2::json(const char *json, unsigned int length) {
	try {
		json2cdt(json, length, params);
		return -1;
	} catch (CTPPParserSyntaxError &e) {
		error = CTPPError("{inline json}", e.what(), CTPP_COMPILER_ERROR | CTPP_SYNTAX_ERROR, e.GetLine(), e.GetLinePos(), 0);
	} catch (...) {
		error = CTPPError("{inline json}", "Unknown JSON Error", CTPP_COMPILER_ERROR | STL_UNKNOWN_ERROR, 0, 0, 0);
	}
	if (error.line > 0) {
		warn("json_param(): %s (error code 0x%08X)", error.error_descr.c_str(), error.error_code);
	} else {
		warn("json_param(): %s (error code 0x%08X) at line %d pos %d", 
			error.error_descr.c_str(), error.error_code, error.line, error.pos);
	}
	return  0;
}

SV *CTPP2::getLastError() {
	HV *error_hash = newHV();
	hv_store_ent(error_hash, newSVpvf("%s", "template_name"), newSVpv(error.template_name.c_str(), error.template_name.size()), 0);
	hv_store_ent(error_hash, newSVpvf("%s", "line"         ), newSViv(error.line), 0);
	hv_store_ent(error_hash, newSVpvf("%s", "pos"          ), newSViv(error.pos), 0);
	hv_store_ent(error_hash, newSVpvf("%s", "ip"           ), newSViv(error.ip), 0);
	hv_store_ent(error_hash, newSVpvf("%s", "error_code"   ), newSViv(error.error_code), 0);
	hv_store_ent(error_hash, newSVpvf("%s", "error_str"    ), newSVpv(error.error_descr.c_str(), error.error_descr.size()), 0);
	return newRV_noinc((SV *) error_hash);
}

void CTPP2::json2cdt(const char *json, unsigned int length, CDT *cdt) {
	CTPP2JSONParser jparser(*cdt);
	jparser.Parse(json, json + length);
}

SV *CTPP2::cdt2perl(CDT *cdt) {
	SV *ret = NULL;
	switch (cdt->GetType()) {
		case CDT::INT_VAL:
			ret = newSViv(cdt->GetInt());
		break;
		
		case CDT::REAL_VAL:
			ret = newSVnv(cdt->GetFloat());
		break;
		
		case CDT::STRING_REAL_VAL:
		case CDT::STRING_INT_VAL:
		case CDT::STRING_VAL:
			ret = newSVpv(cdt->GetString().c_str(), cdt->GetString().size());
		break;
		
		case CDT::ARRAY_VAL:
		{
			AV *av = newAV();
			unsigned int array_size = cdt->Size();
			for (unsigned i = 0; i < array_size; ++i)
				av_push(av, cdt2perl(&(cdt->operator[](i))));
			ret = newRV_inc((SV *) av);
		}
		break;
		
		case CDT::HASH_VAL:
		{
			HV *hash = newHV();
			for (CDT::ConstIterator it = cdt->Begin(), end = cdt->End(); it != end; ++it)
				hv_store_ent(hash, newSVpv(it->first.c_str(), it->first.size()), cdt2perl((CTPP::CDT *) &it->second), 0);
			ret = newRV_inc((SV *) hash);
		}
		break;
		
		case CDT::POINTER_VAL:
			ret = &PL_sv_undef;
		break;
		
		case CDT::UNDEF:
			ret = &PL_sv_undef;
		break;
		
		default:
			ret = &PL_sv_undef;
		break;
	}
	return ret;
}

void CTPP2::perl2cdt(SV *sv, CDT *cdt) {
	if (!sv)
		return;
	
	if (SvPOKp(sv)) { // Строка
		STRLEN len;
		const char *val = SvPV_const(sv, len);
		
		if (string_zero_to_int && len == 1 && val[0] == '0') {
			cdt->operator=(INT_64(0));
		} else {
			cdt->operator=(STLW::string(val, len));
		}
	} else if (SvNOKp(sv)) { // Float
		cdt->operator=(W_FLOAT(SvNV(sv)));
	} else if (SvIOKp(sv)) { // Int
		cdt->operator=(INT_64(SvIV(sv)));
	} else if (SvROK(sv)) { // Ссылка на что-то
		SV *tmp_sv = SvRV(sv);
		
		if (SvOBJECT(tmp_sv)) { // Объект
			HV *stash = SvSTASH(tmp_sv);
			
			// Ищем перегруженный метод для стрингификации объекта
			GV *to_string = gv_fetchmethod_autoload(stash, "\x28\x22\x22", 0);
			if (to_string) {
				dSP;
				ENTER; SAVETMPS; PUSHMARK(SP);
				XPUSHs(sv_bless(sv_2mortal(newRV_inc(tmp_sv)), stash));
				PUTBACK;
				call_sv((SV *) GvCV(to_string), G_SCALAR);
				SPAGAIN;
				
				SV *new_sv = POPs;
				perl2cdt(new_sv, cdt);
				
				PUTBACK;
				FREETMPS; LEAVE;
				return;
			}
			
			// Объект не поддаётся стрингификации
			cdt->operator=(STLW::string("*OBJECT*", 8));
		} else { // Какой-то скаляр
			perl2cdt(tmp_sv, cdt);
		}
	} else if (SvTYPE(sv) == SVt_PVHV) { // Хэш
		HE *entry;
		HV *hash = (HV *) sv;
		
		if (cdt->GetType() != CTPP::CDT::HASH_VAL)
			cdt->operator=(CTPP::CDT(CTPP::CDT::HASH_VAL));
			
		// Пройдёмся по всем элементам хэша, конвертируя всё в CDT на своём пути
		while ((entry = hv_iternext(hash)) != NULL) {
			SV *value = hv_iterval(hash, entry);
			I32 key_len;
			const char *key_name = hv_iterkey(entry, &key_len);
			if (value) {
				CTPP::CDT tmp;
				perl2cdt(value, &tmp);
				cdt->operator[](STLW::string(key_name, key_len)) = tmp;
			}
		}
	} else if (SvTYPE(sv) == SVt_PVAV) { // Массив
		AV *array = (AV *) sv;
		UINT_32 len = av_len(array) + 1;
		
		if (cdt->GetType() != CTPP::CDT::ARRAY_VAL)
			cdt->operator=(CTPP::CDT(CTPP::CDT::ARRAY_VAL));
		
		// Пройдёмся по всем элементам массива, конвертируя всё в CDT на своём пути
		for (UINT_32 i = 0; i < len; ++i) {
			SV **el = av_fetch(array, i, FALSE);
			if (el) {
				CTPP::CDT tmp;
				perl2cdt(*el, &tmp);
				cdt->operator[](i) = tmp;
			}
		}
	} else if (SvTYPE(sv) == SVt_PVCV) { // Функция
		dSP;
		ENTER; SAVETMPS; PUSHMARK(SP);
		PUTBACK;
		call_sv(sv, G_SCALAR);
		SPAGAIN;
		
		SV *new_sv = POPs;
		perl2cdt(new_sv, cdt);
		
		PUTBACK;
		FREETMPS; LEAVE;
	} else if (SvTYPE(sv) == SVt_NULL || !SvOK(sv)) { // undef
		// Ничего не делаем
	} else if (SvSTASH(sv)) { // Stash
		return perl2cdt((SV *) SvSTASH(sv), cdt);
	} else {
		warn("%s: Unknown type (svtype=%d, flags=%d)", __func__, SvTYPE(sv), SvFLAGS(sv));
	}
}

// Bytecode
Bytecode::Bytecode(STLW::vector<STLW::string> &inc_dirs, SV *text, const char *filename, SourceType type) {
	exe = NULL; mem = NULL;
	
	if (type == T_TEXT_SOURCE) {
		if (!SvPOK(text))
			throw CTPPLogicError("Invalid template source (is not text!)");
		CTPP2RefTextSourceLoader loader(text);
		loader.SetIncludeDirs(inc_dirs);
		_compiler(loader, "direct source");
	} else if (type == T_SOURCE) {
		CTPP2FileSourceLoader loader;
		loader.SetIncludeDirs(inc_dirs);
		loader.LoadTemplate(filename);
		_compiler(loader, filename);
	} else if (type == T_BYTECODE) {
		struct stat st;
		if (stat(filename, &st) != 0) {
			throw CTPPUnixException("No such file", errno);
		} else {
			if (st.st_size < 5)
				throw CTPPLogicError("Empty file");
			
			FILE *fp = fopen(filename, "r");
			if (!fp)
				throw CTPPUnixException("fopen", errno);
			
			exe = (VMExecutable *) malloc(st.st_size);
			int readed = fread(exe, st.st_size, 1, fp);
			if (readed != 1) {
				c_free(exe);
				fclose(fp);
				throw CTPPLogicError("File read error (truncated)");
			}
			fclose(fp);
			
			if (exe->magic[0] == 'C' && exe->magic[1] == 'T' && exe->magic[2] == 'P' && exe->magic[3] == 'P') {
				mem = new VMMemoryCore(exe);
			} else {
				c_free(exe);
				throw CTPPLogicError("Not an CTPP bytecode file!");
			}
		}
	} else if (type == T_TEXT_BYTECODE) {
		if (!SvPOK(text))
			throw CTPPLogicError("Invalid template bytecode (is not text!)");
		
		STRLEN size;
		const char *data = SvPV_const(text, size);
		
		if (size < 5)
			throw CTPPLogicError("File read error (truncated)");
		exe = (VMExecutable *) malloc(size);
		memcpy(exe, data, size);
		
		if (exe->magic[0] == 'C' && exe->magic[1] == 'T' && exe->magic[2] == 'P' && exe->magic[3] == 'P') {
			mem = new VMMemoryCore(exe);
		} else {
			c_free(exe);
			throw CTPPLogicError("Not an CTPP bytecode!");
		}
	}
}

// Bytecode
void Bytecode::_compiler(CTPP2SourceLoader &loader, const char *name) {
	// Компилятор
	VMOpcodeCollector  vm_op_collector;
	StaticText         syscalls;
	StaticData         static_data;
	StaticText         static_text;
	HashTable          hash_table;
	CTPP2Compiler compiler(vm_op_collector, syscalls, static_data, static_text, hash_table);
	
	// Создаём парсер и компилим
	CTPP2Parser parser(&loader, &compiler, name);
	parser.Compile();
	
	// Сам код шаблона
	unsigned int code_size = 0;
	const VMInstruction * vm_instructions = vm_op_collector.GetCode(code_size);
	
	// Дампим в байткод
	VMDumper dumper(code_size, vm_instructions, syscalls, static_data, static_text, hash_table);
	const VMExecutable *bytecode = dumper.GetExecutable(exe_size);
	
	// Аллочим память
	exe = (VMExecutable *) malloc(exe_size);
	memcpy(exe, bytecode, exe_size);
	mem = new VMMemoryCore(exe);
}
int Bytecode::save(const char *filename) {
	FILE *fp = fopen(filename, "w");
	if (!fp) {
		warn("CTPP2: fopen(%s): %s", filename, strerror(errno));
		return -1;
	}
	fwrite(exe, exe_size, 1, fp);
	fclose(fp);
	return 0;
}
SV *Bytecode::data() {
	if (exe)
		return newSVpv((const char *) exe, exe_size);
	return NULL;
}
Bytecode::~Bytecode() {
	if (mem) delete mem;
	if (exe) free(exe);
}
