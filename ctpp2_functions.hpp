#pragma once
#include "ctpp2.hpp"

using namespace CTPP;

namespace CTPP {
	template<typename T> SyscallHandler *CTPP2_HANDLER() { return new T; }
	
	// FN_CoNaN
	class FN_CoNaN: public SyscallHandler {
		public:
			friend class STDLibInitializer;
			FN_CoNaN();
			~FN_CoNaN() throw();
			INT_32 Handler(CDT *args, const UINT_32 args_n, CDT &ret, Logger &logger);
			INT_32 Usage(Logger &logger);
			CCHAR_P GetName() const;
		protected:
			static const unsigned char cases[];
	};
};