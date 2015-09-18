#include "ctpp2_functions.hpp"

// Список функций
const CTPP2::FnHandler CTPP2::functions[] = {
	CTPP2_HANDLER<CTPP::FN_CoNaN>, 
	NULL
};

// Разрабочтки CTPP2 - наркоманы, аргументы передаются задом-наперёд
#define CTPP_ARG(N) args[args_n - 1 - (N)]

using namespace STLW;

namespace CTPP {
	// Combination of Numerals and Nouns
	const unsigned char FN_CoNaN::cases[] = {2, 0, 1, 1, 1, 2};
	FN_CoNaN::FN_CoNaN() { }
	INT_32 FN_CoNaN::Handler(CDT *args, const UINT_32 args_n, CDT &ret, Logger &logger) {
		if ((args_n < 2 || args_n > 5))
			return Usage(logger);
		int num = CTPP_ARG(0).GetInt();
		unsigned char n = (num % 100 > 4 && num % 100 < 20) ? 2 : cases[min(num % 10, 5)];
		bool concat_num = true;
		
		if (args_n > 3) {
			ret = CTPP_ARG(n + 1);
			
			if (args_n > 4)
				concat_num = CTPP_ARG(4).GetInt() != 0;
			
			if (concat_num) {
				string str = CTPP_ARG(n + 1).GetString();
				size_t it = str.find('#');
				if (it != string::npos) {
					str.replace(it, 1, CTPP_ARG(0).GetString());
					ret = str;
				} else {
					ret = CTPP_ARG(0).GetString() + " " + str;
				}
			} else {
				ret = CTPP_ARG(n + 1);
			}
		} else if (args_n > 1) {
			if (CTPP_ARG(1).GetType() != CDT::ARRAY_VAL || CTPP_ARG(1).Size() != 3)
				return Usage(logger);
			
			if (args_n > 2)
				concat_num = CTPP_ARG(2).GetInt() != 0;
			
			if (concat_num) {
				string str = CTPP_ARG(1)[n].GetString();
				size_t it = str.find('#');
				if (it != string::npos) {
					str.replace(it, 1, CTPP_ARG(0).GetString());
					ret = str;
				} else {
					ret = CTPP_ARG(0).GetString() + " " + str;
				}
			} else {
				ret = CTPP_ARG(1)[n];
			}
		}
		return 0;
	}
	INT_32 FN_CoNaN::Usage(Logger &logger) {
		logger.Emerg("Usage: CoNaN(N, LIST(\"язык\", \"языка\", \"языков\"), [concat_num = true]) or CoNaN(N, \"язык\", \"языка\", \"языков\", [concat_num = true])");
		return -1;
	}
	CCHAR_P FN_CoNaN::GetName() const {
		return "conan";
	}
	FN_CoNaN::~FN_CoNaN() throw() { }
};
