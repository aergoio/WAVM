#pragma once

#include <vector>

#include "WAVM/IR/Value.h"
#include "WAVM/Runtime/Runtime.h"

namespace WAVM { namespace IR {
	struct Module;
}}

namespace WAVM { namespace ASCL {
	struct Instance
	{
		Runtime::GCPointer<Runtime::ModuleInstance> system;

		Runtime::GCPointer<Runtime::Memory> asclMemory;
	};

    ASCLVM_API Instance* instantiate(Runtime::Compartment* compartment,
                                     const IR::Module& module);
    ASCLVM_API void initializeGlobals(Runtime::Context* context,
                                      const IR::Module& module,
                                      Runtime::ModuleInstance* moduleInstance);
    ASCLVM_API void injectCommandArgs(ASCL::Instance* instance,
                                      const std::vector<const char*>& argStrings,
                                      std::vector<IR::Value>& outInvokeArgs);
}}
