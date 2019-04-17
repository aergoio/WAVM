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
#include "gmp.h"

#define MPZ_MAX_BITS                128

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
// 64..127 = aliased stack
// 128..   = dynamic memory
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

	U32 HEAP_PTR;
	I32 _stderr;
	I32 _stdin;
	I32 _stdout;
};

DEFINE_INTRINSIC_GLOBAL(system, "STACK_MAX", I32, STACK_MAX, 127 * IR::numBytesPerPage);

DEFINE_INTRINSIC_GLOBAL(system, "_stderr", I32, _stderr,
						MutableGlobals::address + offsetof(MutableGlobals, _stderr));
DEFINE_INTRINSIC_GLOBAL(system, "_stdin", I32, _stdin,
						MutableGlobals::address + offsetof(MutableGlobals, _stdin));
DEFINE_INTRINSIC_GLOBAL(system, "_stdout", I32, _stdout,
						MutableGlobals::address + offsetof(MutableGlobals, _stdout));

DEFINE_INTRINSIC_GLOBAL(system, "HEAP_PTR", U32, HEAP_PTR,
						MutableGlobals::address + offsetof(MutableGlobals, HEAP_PTR))

static thread_local Memory* asclMemory = nullptr;

static Runtime::ExceptionType* outOfBoundsArrayAccess = nullptr;

static bool resizeHeap(U32 desiredNumBytes)
{
	const Uptr desiredNumPages
		= (Uptr(desiredNumBytes) + IR::numBytesPerPage - 1) / IR::numBytesPerPage;
	const Uptr currentNumPages = Runtime::getMemoryNumPages(asclMemory);
	if(desiredNumPages > currentNumPages)
	{
		if(Runtime::growMemory(asclMemory, desiredNumPages - currentNumPages) == -1)
		{ return false; }

		return true;
	}
	else if(desiredNumPages < currentNumPages)
	{
		if(Runtime::shrinkMemory(asclMemory, currentNumPages - desiredNumPages) == -1)
		{ return false; }

		return true;
	}
	else
	{
		return true;
	}
}

static U32 heapAlloc(U32 numBytes)
{
	MutableGlobals& mutableGlobals
		= memoryRef<MutableGlobals>(asclMemory, MutableGlobals::address);

	const U32 allocationAddress = mutableGlobals.HEAP_PTR;
	const U32 endAddress = (allocationAddress + numBytes + 15) & -16;

	mutableGlobals.HEAP_PTR = endAddress;

	if(endAddress > getMemoryNumPages(asclMemory) * IR::numBytesPerPage)
	{
		if(endAddress > getMemoryMaxPages(asclMemory) * IR::numBytesPerPage
		   || !resizeHeap(endAddress))
		{ throwException(ExceptionTypes::outOfMemory); }
	}

	return allocationAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__assert", void, _assert, I32 condition, U32 condStringAddress,
                          U32 descAddress)
{
    if (!condition) {
		wavmAssert(asclMemory);
        throwException(ExceptionTypes::failedAssertion,
                       {asObject(asclMemory), U32(condStringAddress), U32(descAddress)});
    }
}

DEFINE_INTRINSIC_FUNCTION(system, "__malloc", U32, _malloc, U32 numBytes)
{
    wavmAssert(asclMemory);
    return coerce32bitAddress(asclMemory, heapAlloc(numBytes));
}

DEFINE_INTRINSIC_FUNCTION(system, "__memcpy", void, _memcpy,
                          U32 destAddress, U32 srcAddress, U32 numBytes)
{
    wavmAssert(asclMemory);

    U8* srcMemory = getMemoryBaseAddress(asclMemory) + srcAddress;
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    memcpy(destMemory, srcMemory, numBytes);
}

DEFINE_INTRINSIC_FUNCTION(system, "__strcmp", U32, _strcmp, U32 stringAddress1, U32 stringAddress2)
{
    wavmAssert(asclMemory);

    U8* stringPointer1 = &memoryRef<U8>(asclMemory, stringAddress1);
    U8* stringPointer2 = &memoryRef<U8>(asclMemory, stringAddress2);

    return strcmp((const char*)stringPointer1, (const char*)stringPointer2);
}

DEFINE_INTRINSIC_FUNCTION(system, "__strcat", U32, _strcat, U32 stringAddress1, U32 stringAddress2)
{
    wavmAssert(asclMemory);

    U8* stringPointer1 = &memoryRef<U8>(asclMemory, stringAddress1);
    auto stringSize1 = strlen((const char*)stringPointer1);
    U8* stringPointer2 = &memoryRef<U8>(asclMemory, stringAddress2);
    auto stringSize2 = strlen((const char*)stringPointer2);

    U32 destAddress = coerce32bitAddress(asclMemory, heapAlloc(stringSize1 + stringSize2 + 1));
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    memcpy(destMemory, stringPointer1, stringSize1);
    memcpy(destMemory + stringSize1, stringPointer2, stringSize2);
    destMemory[stringSize1 + stringSize2] = '\0';

    return destAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__atoi32", I32, _atoi32, U32 stringAddress)
{
    wavmAssert(asclMemory);

    U8* stringPointer = &memoryRef<U8>(asclMemory, stringAddress);
    I32 ival;

    sscanf((const char*)stringPointer, "%" SCNd32, &ival);

    return ival;
}

DEFINE_INTRINSIC_FUNCTION(system, "__atoi64", I64, _atoi64, U32 stringAddress)
{
    wavmAssert(asclMemory);

    U8* stringPointer = &memoryRef<U8>(asclMemory, stringAddress);
    I64 intValue;

    sscanf((const char*)stringPointer, "%" SCNd64, &intValue);

    return intValue;
}

DEFINE_INTRINSIC_FUNCTION(system, "__itoa32", U32, _itoa32, I32 intValue)
{
    wavmAssert(asclMemory);

    const char *strValue = std::to_string(intValue).c_str();

    U32 destAddress = coerce32bitAddress(asclMemory, heapAlloc(strlen(strValue)));
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    memcpy(destMemory, strValue, strlen(strValue) + 1);

    return destAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__itoa64", U32, _itoa64, I64 intValue)
{
    wavmAssert(asclMemory);

    const char *strValue = std::to_string(intValue).c_str();

    U32 destAddress = coerce32bitAddress(asclMemory, heapAlloc(strlen(strValue)));
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    memcpy(destMemory, strValue, strlen(strValue) + 1);

    return destAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__print", void, _print, U32 formatAddress, I32 argList)
{
    wavmAssert(asclMemory);

    std::cout << &memoryRef<U8>(asclMemory, formatAddress);
}

DEFINE_INTRINSIC_FUNCTION(system, "__println", void, _println, U32 formatAddress, I32 argList)
{
    wavmAssert(asclMemory);

    std::cout << &memoryRef<U8>(asclMemory, formatAddress) << "\n";
}

static void* mpzAlloc(size_t size)
{
    return getMemoryBaseAddress(asclMemory) + heapAlloc(size);
}

static void* mpzRealloc(void* ptr, size_t oldSize, size_t newSize)
{
    return getMemoryBaseAddress(asclMemory) + heapAlloc(newSize);
}

static void mpzFree(void* ptr, size_t size)
{
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_get_i32", U32, _mpz_get_i32, U32 mpzAddress)
{
    wavmAssert(asclMemory);

    return (I32)mpz_get_si((mpz_srcptr)(getMemoryBaseAddress(asclMemory) + mpzAddress));
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_get_i64", U64, _mpz_get_i64, U32 mpzAddress)
{
    wavmAssert(asclMemory);

    return mpz_get_si((mpz_srcptr)(getMemoryBaseAddress(asclMemory) + mpzAddress));
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_get_str", U32, _mpz_get_str, U32 mpzAddress)
{
    wavmAssert(asclMemory);

	MutableGlobals& mutableGlobals = memoryRef<MutableGlobals>(asclMemory, MutableGlobals::address);
	const U32 allocationAddress = mutableGlobals.HEAP_PTR;

    mpz_get_str(NULL, 10, (mpz_srcptr)(getMemoryBaseAddress(asclMemory) + mpzAddress));

    return allocationAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_set_i32", U32, _mpz_set_i32,
                          I32 value, U32 isSigned)
{
    wavmAssert(asclMemory);

    U32 mpzAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress);

    if (isSigned)
        mpz_init_set_si(mpz, value);
    else
        mpz_init_set_ui(mpz, value);

    return mpzAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_set_i64", U32, _mpz_set_i64, I64 value, U32 isSigned)
{
    wavmAssert(asclMemory);

    U32 mpzAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress);

    if (isSigned)
        mpz_init_set_si(mpz, value);
    else
        mpz_init_set_ui(mpz, value);

    return mpzAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_set_str", U32, _mpz_set_str, U32 valueAddress)
{
    U32 mpzAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress);
    U8* valueString = &memoryRef<U8>(asclMemory, valueAddress);

    mpz_init_set_str(mpz, (const char*)valueString, 0);

    return mpzAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_add", U32, _mpz_add,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_add(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_sub", U32, _mpz_sub,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_sub(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_mul", U32, _mpz_mul,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_mul(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_div", U32, _mpz_div,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_tdiv_q(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_mod", U32, _mpz_mod,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_mod(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_and", U32, _mpz_and,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_and(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_or", U32, _mpz_or,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_ior(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_xor", U32, _mpz_xor,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_xor(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_rshift", U32, _mpz_rshift,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_tdiv_q_2exp(r_mpz, mpz1, mpz_get_ui(mpz2));

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_lshift", U32, _mpz_lshift,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_mul_2exp(r_mpz, mpz1, mpz_get_ui(mpz2));

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_cmp", U32, _mpz_cmp,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);

    return mpz_cmp(mpz1, mpz2);
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_neg", U32, _mpz_neg, U32 mpzAddress)
{
    mpz_ptr mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress);
    U32 resAddress = coerce32bitAddress(asclMemory, heapAlloc(sizeof(mpz_t)));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_neg(r_mpz, mpz);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_sign", I32, _mpz_sign, U32 mpzAddress)
{
    return mpz_sgn((mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress));
}

template<typename T> static U32 array_get(U32 arrayAddress, U32 index)
{
    wavmAssert(asclMemory);

    U32* arrayPointer = &memoryRef<U32>(asclMemory, arrayAddress);

    U32 dimension = arrayPointer[0];
    U32 elemCount = arrayPointer[1];

    if (index >= elemCount)
        throwException(outOfBoundsArrayAccess, {U32(index), U32(elemCount)});

    if (dimension == 1)
        return arrayAddress + sizeof(U64) + index * sizeof(T);

    U32 unitSize = 0;
    for (U32 i = dimension, j = 2; i > 1; i--, j += 2) {
        unitSize += sizeof(U64) + arrayPointer[j + 1] * sizeof(T);
    }

    return arrayAddress + sizeof(U64) + (unitSize * index);
}

DEFINE_INTRINSIC_FUNCTION(system, "__array_get_i32", U32, _array_get_i32,
                          U32 arrayAddress, U32 index)
{
    return array_get<U32>(arrayAddress, index);
}

DEFINE_INTRINSIC_FUNCTION(system, "__array_get_i64", U32, _array_get_i64,
                          U32 arrayAddress, U32 index)
{
    return array_get<U64>(arrayAddress, index);
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

		mutableGlobals.HEAP_PTR = STACK_MAX.getValue().i32;
		mutableGlobals._stderr = (U32)ioStreamVMHandle::StdErr;
		mutableGlobals._stdin = (U32)ioStreamVMHandle::StdIn;
		mutableGlobals._stdout = (U32)ioStreamVMHandle::StdOut;
	});

	instance->asclMemory = memory;
	asclMemory = instance->asclMemory;

    mp_set_memory_functions(mpzAlloc, mpzRealloc, mpzFree);

    outOfBoundsArrayAccess = Runtime::createExceptionType(
        compartment,
        IR::ExceptionType{IR::TypeTuple({ValueType::i32, ValueType::i32})},
        "outOfBoundsArrayAccess");

	return instance;
}

void ASCL::injectCommandArgs(ASCL::Instance* instance,
                             const std::vector<const char*>& argStrings,
                             std::vector<IR::Value>& outInvokeArgs)
{
	Memory* memory = instance->asclMemory;
	U8* asclMemoryBaseAdress = getMemoryBaseAddress(memory);

	U32* argvOffsets = (U32*)(asclMemoryBaseAdress +
                              heapAlloc((U32)(sizeof(U32) * (argStrings.size() + 1))));
	for(Uptr argIndex = 0; argIndex < argStrings.size(); ++argIndex)
	{
		auto stringSize = strlen(argStrings[argIndex]) + 1;
		auto stringMemory = asclMemoryBaseAdress + heapAlloc((U32)stringSize);
		memcpy(stringMemory, argStrings[argIndex], stringSize);
		argvOffsets[argIndex] = (U32)(stringMemory - asclMemoryBaseAdress);
	}
	argvOffsets[argStrings.size()] = 0;
	outInvokeArgs = {(U32)argStrings.size(), (U32)((U8*)argvOffsets - asclMemoryBaseAdress)};
}
