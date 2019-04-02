#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <initializer_list>
#include <memory>
#include <new>
#include <string>
#include <utility>
#include <iostream>
#ifndef _WIN32
#include <sys/uio.h>
#endif

#include "ASCL.h"
#include "WAVM/IR/IR.h"
#include "WAVM/IR/Module.h"
#include "WAVM/IR/Types.h"
#include "WAVM/IR/Value.h"
#include "WAVM/Inline/BasicTypes.h"
#include "WAVM/Inline/FloatComponents.h"
#include "WAVM/Inline/Hash.h"
#include "WAVM/Inline/HashMap.h"
#include "WAVM/Logging/Logging.h"
#include "WAVM/Platform/Defines.h"
#include "WAVM/Runtime/Intrinsics.h"
#include "WAVM/Runtime/Runtime.h"

using namespace WAVM;
using namespace WAVM::IR;
using namespace WAVM::Runtime;

DEFINE_INTRINSIC_MODULE(system)

static U32 coerce32bitAddress(Memory* memory, Uptr address)
{
	if(address >= UINT32_MAX)
	{ throwException(ExceptionTypes::outOfBoundsMemoryAccess, {asObject(memory), U64(address)}); }
	return (U32)address;
}

//  0..62  = static data
// 63..63  = MutableGlobals
// 64..128 = aliased stack
// 129..   = dynamic memory
enum
{
	minStaticASCLMemoryPages = 128
};

struct MutableGlobals
{
	enum
	{
		address = 63 * IR::numBytesPerPage
	};

	U32 HEAP_ADDR;
	I32 _stderr;
	I32 _stdin;
	I32 _stdout;
};

DEFINE_INTRINSIC_GLOBAL(system, "STACK_MAX", I32, STACK_MAX, 128 * IR::numBytesPerPage);

DEFINE_INTRINSIC_GLOBAL(system, "_stderr", I32, _stderr,
						MutableGlobals::address + offsetof(MutableGlobals, _stderr));
DEFINE_INTRINSIC_GLOBAL(system, "_stdin", I32, _stdin,
						MutableGlobals::address + offsetof(MutableGlobals, _stdin));
DEFINE_INTRINSIC_GLOBAL(system, "_stdout", I32, _stdout,
						MutableGlobals::address + offsetof(MutableGlobals, _stdout));

DEFINE_INTRINSIC_GLOBAL(system, "HEAP_ADDR", U32, HEAP_ADDR,
						MutableGlobals::address + offsetof(MutableGlobals, HEAP_ADDR))

static thread_local Memory* asclMemory = nullptr;

static U32 heapAlloc(Memory* memory, U32 numBytes)
{
	MutableGlobals& mutableGlobals = memoryRef<MutableGlobals>(memory, MutableGlobals::address);

	const U32 allocationAddress = mutableGlobals.HEAP_ADDR;
	const U32 endAddress = (allocationAddress + numBytes + 15) & -16;

	mutableGlobals.HEAP_ADDR = endAddress;

	const Uptr endPage = (endAddress + IR::numBytesPerPage - 1) / IR::numBytesPerPage;
	if(endPage >= getMemoryNumPages(memory) && endPage < getMemoryMaxPages(memory))
	{ growMemory(memory, endPage - getMemoryNumPages(memory) + 1); }

	return allocationAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "malloc", U32, _malloc, U32 numBytes)
{
    wavmAssert(asclMemory);

    return coerce32bitAddress(asclMemory, heapAlloc(asclMemory, numBytes));
}

DEFINE_INTRINSIC_FUNCTION(system, "memcpy", void, _memcpy,
                          U32 destAddress, U32 srcAddress, U32 numBytes)
{
    wavmAssert(asclMemory);

    U8* srcMemory = getMemoryBaseAddress(asclMemory) + srcAddress;
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    memcpy(destMemory, srcMemory, numBytes);
}

DEFINE_INTRINSIC_FUNCTION(system, "concat", U32, _concat,
						  U32 stringAddress1, U32 stringAddress2)
{
    wavmAssert(asclMemory);

    U8* stringPointer1 = &memoryRef<U8>(asclMemory, stringAddress1);
    auto stringSize1 = strlen((const char*)stringPointer1);
    U8* stringPointer2 = &memoryRef<U8>(asclMemory, stringAddress2);
    auto stringSize2 = strlen((const char*)stringPointer2);

    U32 destAddress = coerce32bitAddress(asclMemory, heapAlloc(asclMemory, stringSize1 + stringSize2 + 1));
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    memcpy(destMemory, stringPointer1, stringSize1);
    memcpy(destMemory + stringSize1, stringPointer2, stringSize2);
    destMemory[stringSize1 + stringSize2] = '\0';

    return destAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "_print", void, _print,
						  U32 formatAddress, I32 argList)
{
    std::cout << &memoryRef<U8>(asclMemory, formatAddress);
}

DEFINE_INTRINSIC_FUNCTION(system, "_println", void, _println,
						  U32 formatAddress, I32 argList)
{
    std::cout << &memoryRef<U8>(asclMemory, formatAddress) << "\n";
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_get_i32", U32, _mpz_get_i32, U32 mpzAddress)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_get_i64", U64, _mpz_get_i64, U32 mpzAddress)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_get_str", U32, _mpz_get_str, U32 mpzAddress)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_set_i32", U32, _mpz_set_i32,
                          U32 value, U32 isSigned)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_set_i64", U32, _mpz_set_i64, U64 value, U32 isSigned)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_set_str", U32, _mpz_set_str, U32 valueAddress)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_add", U32, _mpz_add,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_sub", U32, _mpz_sub,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_mul", U32, _mpz_mul,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_div", U32, _mpz_div,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_mod", U32, _mpz_mod,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_and", U32, _mpz_and,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_or", U32, _mpz_or,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_xor", U32, _mpz_xor,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_rshift", U32, _mpz_rshift,
                          U32 mpzAddress1, U32 bitCnt)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_lshift", U32, _mpz_lshift,
                          U32 mpzAddress1, U32 bitCnt)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_cmp", U32, _mpz_cmp,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    return 0;
}

DEFINE_INTRINSIC_FUNCTION(system, "mpz_neg", U32, _mpz_neg, U32 mpzAddress)
{
    return 0;
}

enum class ioStreamVMHandle
{
    StdErr = 1,
    StdIn = 2,
    StdOut = 3
};

ASCL::Instance* ASCL::instantiate(Compartment* compartment, const IR::Module& module)
{
	MemoryType memoryType(false, SizeConstraints{0, 0});
	if(module.memories.imports.size() && module.memories.imports[0].moduleName == "system"
	   && module.memories.imports[0].exportName == "memory")
	{
		memoryType = module.memories.imports[0].type;
		if(memoryType.size.max >= minStaticASCLMemoryPages)
		{
			if(memoryType.size.min <= minStaticASCLMemoryPages)
			{
				// Enlarge the initial memory to make space for the stack and mutable globals.
				memoryType.size.min = minStaticASCLMemoryPages;
			}
		}
		else
		{
			Log::printf(Log::error, "module's memory is too small for ASCL emulation");
			return nullptr;
		}
	}
	else
	{
		return nullptr;
	}

	TableType tableType(ReferenceType::funcref, false, SizeConstraints{0, 0});
	if(module.tables.imports.size() && module.tables.imports[0].moduleName == "system"
	   && module.tables.imports[0].exportName == "table")
	{ tableType = module.tables.imports[0].type; }

	Memory* memory = Runtime::createMemory(compartment, memoryType, "system.memory");
	Table* table = Runtime::createTable(compartment, tableType, "system.table");

	HashMap<std::string, Runtime::Object*> extraEnvExports = {
		{"memory", Runtime::asObject(memory)},
		{"table", Runtime::asObject(table)},
	};

	Instance* instance = new Instance;
	instance->system = Intrinsics::instantiateModule(
		compartment, INTRINSIC_MODULE_REF(system), "system", extraEnvExports);

	unwindSignalsAsExceptions([=] {
		MutableGlobals& mutableGlobals = memoryRef<MutableGlobals>(memory, MutableGlobals::address);

		mutableGlobals.HEAP_ADDR = STACK_MAX.getValue().i32;
		mutableGlobals._stderr = (U32)ioStreamVMHandle::StdErr;
		mutableGlobals._stdin = (U32)ioStreamVMHandle::StdIn;
		mutableGlobals._stdout = (U32)ioStreamVMHandle::StdOut;
	});

	instance->asclMemory = memory;
	asclMemory = instance->asclMemory;

	return instance;
}

void ASCL::injectCommandArgs(ASCL::Instance* instance,
                             const std::vector<const char*>& argStrings,
                             std::vector<IR::Value>& outInvokeArgs)
{
	Memory* memory = instance->asclMemory;
	U8* asclMemoryBaseAdress = getMemoryBaseAddress(memory);

	U32* argvOffsets = (U32*)(asclMemoryBaseAdress
							  + heapAlloc(memory, (U32)(sizeof(U32) * (argStrings.size() + 1))));
	for(Uptr argIndex = 0; argIndex < argStrings.size(); ++argIndex)
	{
		auto stringSize = strlen(argStrings[argIndex]) + 1;
		auto stringMemory = asclMemoryBaseAdress + heapAlloc(memory, (U32)stringSize);
		memcpy(stringMemory, argStrings[argIndex], stringSize);
		argvOffsets[argIndex] = (U32)(stringMemory - asclMemoryBaseAdress);
	}
	argvOffsets[argStrings.size()] = 0;
	outInvokeArgs = {(U32)argStrings.size(), (U32)((U8*)argvOffsets - asclMemoryBaseAdress)};
}
