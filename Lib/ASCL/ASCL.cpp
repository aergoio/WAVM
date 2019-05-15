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
#define ERR_DESC_MAX_LEN            512

using namespace WAVM;
using namespace WAVM::IR;
using namespace WAVM::Runtime;

DEFINE_INTRINSIC_MODULE(system)

U8* FILENAME = nullptr;
U32 STACK_MAX = 0;
U32 STACK_TOP = 0;
U32 HEAP_ADDR = 0;

static thread_local Memory* asclMemory = nullptr;

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

static void checkHeapAddress(U32 allocationAddress, U32 endAddress)
{
	if (endAddress > getMemoryNumPages(asclMemory) * IR::numBytesPerPage) {
		if (endAddress > getMemoryMaxPages(asclMemory) * IR::numBytesPerPage ||
            !resizeHeap(endAddress))
            throwException(ExceptionTypes::outOfMemory);
	}

	if (allocationAddress >= UINT32_MAX)
        throwException(ExceptionTypes::outOfBoundsMemoryAccess,
                       {asObject(asclMemory), U64(allocationAddress)});
}

static U32 heapAlloc(U32 numBytes)
{
	const U32 allocationAddress = HEAP_ADDR;
	const U32 endAddress = allocationAddress + numBytes;

	HEAP_ADDR = endAddress;

    checkHeapAddress(allocationAddress, endAddress);

	return allocationAddress;
}

#define heapAlloc32(n)          heapAllocAligned((n), 4)
#define heapAlloc64(n)          heapAllocAligned((n), 8)
#define heapAllocPtr(n)         heapAllocAligned((n), sizeof(void*))

static U32 heapAllocAligned(U32 numBytes, U8 align)
{
    errorUnless(align > 0);

	const U32 allocationAddress = (HEAP_ADDR + align - 1) & ~(align - 1);
	const U32 endAddress = allocationAddress + numBytes;

	HEAP_ADDR = endAddress;

    checkHeapAddress(allocationAddress, endAddress);

	return allocationAddress;
}

static void throwFormattedException(U32 line, U32 column, U32 offset, const char* format, ...)
{
    va_list vargs;
    U32 messageAddress = heapAlloc(ERR_DESC_MAX_LEN);
    U8* message = getMemoryBaseAddress(asclMemory) + messageAddress;

    va_start(vargs, format);
    vsnprintf((char *)message, ERR_DESC_MAX_LEN, format, vargs);
    va_end(vargs);

    throwException(ExceptionTypes::abortedExecution,
                   {asObject(asclMemory), messageAddress, line, column, offset});
}

static void checkNull(U32 address)
{
    if (address == 0)
        throwFormattedException(1, 1, 0, "cannot access uninitialized variable");
}

DEFINE_INTRINSIC_FUNCTION(system, "__malloc32", U32, _malloc32, U32 numBytes)
{
    return heapAlloc32(numBytes);
}

DEFINE_INTRINSIC_FUNCTION(system, "__malloc64", U32, _malloc64, U32 numBytes)
{
    return heapAlloc64(numBytes);
}

DEFINE_INTRINSIC_FUNCTION(system, "__memcpy", void, _memcpy,
                          U32 destAddress, U32 srcAddress, U32 numBytes)
{
    U8* srcMemory = getMemoryBaseAddress(asclMemory) + srcAddress;
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    memcpy(destMemory, srcMemory, numBytes);
}

DEFINE_INTRINSIC_FUNCTION(system, "__memset", void, _memset,
                          U32 destAddress, I32 byte, U32 numBytes)
{
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    memset(destMemory, byte, numBytes);
}

DEFINE_INTRINSIC_FUNCTION(system, "__stack_overflow", void, _stack_overflow)
{
    throwFormattedException(1, 1, 0, "stack overflow");
}

DEFINE_INTRINSIC_FUNCTION(system, "__assert", void, _assert, I32 condition, U32 condAddress,
                          U32 descAddress, U32 line, U32 column, U32 offset)
{
    if (!condition) {
        if (descAddress > 0)
            throwFormattedException(line, column, offset,
                                    "assertion failed with condition '%s': %s",
                                    (char *)&memoryRef<U8>(asclMemory, condAddress),
                                    (char *)&memoryRef<U8>(asclMemory, descAddress));
        else
            throwFormattedException(line, column, offset,
                                    "assertion failed with condition '%s'",
                                    (char *)&memoryRef<U8>(asclMemory, condAddress));
    }
}

DEFINE_INTRINSIC_FUNCTION(system, "__strlen", U32, _strlen, U32 stringAddress)
{
    U8* stringPointer = &memoryRef<U8>(asclMemory, stringAddress);

    return strlen((const char*)stringPointer);
}

DEFINE_INTRINSIC_FUNCTION(system, "__strcmp", U32, _strcmp, U32 stringAddress1, U32 stringAddress2)
{
    U8* stringPointer1 = &memoryRef<U8>(asclMemory, stringAddress1);
    U8* stringPointer2 = &memoryRef<U8>(asclMemory, stringAddress2);

    return strcmp((const char*)stringPointer1, (const char*)stringPointer2);
}

DEFINE_INTRINSIC_FUNCTION(system, "__strcat", U32, _strcat, U32 stringAddress1, U32 stringAddress2)
{
    U8* stringPointer1 = &memoryRef<U8>(asclMemory, stringAddress1);
    auto stringSize1 = strlen((const char*)stringPointer1);
    U8* stringPointer2 = &memoryRef<U8>(asclMemory, stringAddress2);
    auto stringSize2 = strlen((const char*)stringPointer2);

    U32 destAddress = heapAlloc(stringSize1 + stringSize2 + 1);
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    memcpy(destMemory, stringPointer1, stringSize1);
    memcpy(destMemory + stringSize1, stringPointer2, stringSize2);
    destMemory[stringSize1 + stringSize2] = '\0';

    return destAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__strdup", U32, _strdup, U32 stringAddress)
{
    U8* stringPointer = &memoryRef<U8>(asclMemory, stringAddress);
    auto stringSize = strlen((const char*)stringPointer);

    U32 destAddress = heapAlloc(stringSize + 1);
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    memcpy(destMemory, stringPointer, stringSize);

    return destAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__strcpy", void, _strcpy, U32 destAddress, U32 stringAddress)
{
    checkNull(destAddress);

    U8* destMemory = &memoryRef<U8>(asclMemory, destAddress);
    U8* stringPointer = &memoryRef<U8>(asclMemory, stringAddress);

    strcpy((char*)destMemory, (char*)stringPointer);
}

DEFINE_INTRINSIC_FUNCTION(system, "__atoi32", I32, _atoi32, U32 stringAddress)
{
    if (stringAddress == 0)
        return 0;

    U8* stringPointer = &memoryRef<U8>(asclMemory, stringAddress);
    I32 ival;

    sscanf((const char*)stringPointer, "%" SCNd32, &ival);

    return ival;
}

DEFINE_INTRINSIC_FUNCTION(system, "__atoi64", I64, _atoi64, U32 stringAddress)
{
    if (stringAddress == 0)
        return 0;

    U8* stringPointer = &memoryRef<U8>(asclMemory, stringAddress);
    I64 intValue;

    sscanf((const char*)stringPointer, "%" SCNd64, &intValue);

    return intValue;
}

DEFINE_INTRINSIC_FUNCTION(system, "__itoa32", U32, _itoa32, I32 intValue)
{
    const char *strValue = std::to_string(intValue).c_str();

    U32 destAddress = heapAlloc(strlen(strValue) + 1);
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    memcpy(destMemory, strValue, strlen(strValue));

    return destAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__itoa64", U32, _itoa64, I64 intValue)
{
    const char *strValue = std::to_string(intValue).c_str();

    U32 destAddress = heapAlloc(strlen(strValue) + 1);
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    memcpy(destMemory, strValue, strlen(strValue));

    return destAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__ctoa", U32, _ctoa, U32 charValue)
{
    U32 destAddress = heapAlloc(2);
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    destMemory[0] = (U8)charValue;
    destMemory[1] = '\0';

    return destAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__abs32", I32, _abs32, I32 value)
{
    return value >= 0 ? value : -value;
}

DEFINE_INTRINSIC_FUNCTION(system, "__abs64", I64, _abs64, I64 value)
{
    return value >= 0 ? value : -value;
}

DEFINE_INTRINSIC_FUNCTION(system, "__pow32", I32, _pow32, I32 base, I32 exponent)
{
    return pow(base, exponent);
}

DEFINE_INTRINSIC_FUNCTION(system, "__pow64", I64, _pow64, I64 base, I32 exponent)
{
    return pow(base, exponent);
}

DEFINE_INTRINSIC_FUNCTION(system, "__sign32", I32, _sign32, I32 value)
{
    return value > 0 ? 1 : (value < 0 ? -1 : 0);
}

DEFINE_INTRINSIC_FUNCTION(system, "__sign64", I64, _sign64, I64 value)
{
    return value > 0 ? 1 : (value < 0 ? -1 : 0);
}

DEFINE_INTRINSIC_FUNCTION(system, "__lower", U32, _lower, U32 stringAddress)
{
    if (stringAddress == 0)
        return 0;

    U8* stringPointer = &memoryRef<U8>(asclMemory, stringAddress);
    auto stringSize = strlen((const char*)stringPointer);

    U32 destAddress = heapAlloc(stringSize + 1);
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    for (U32 i = 0; i < stringSize; i++) {
        destMemory[i] = tolower(stringPointer[i]);
    }
    destMemory[stringSize] = '\0';

    return destAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__upper", U32, _upper, U32 stringAddress)
{
    if (stringAddress == 0)
        return 0;

    U8* stringPointer = &memoryRef<U8>(asclMemory, stringAddress);
    auto stringSize = strlen((const char*)stringPointer);

    U32 destAddress = heapAlloc(stringSize + 1);
    U8* destMemory = getMemoryBaseAddress(asclMemory) + destAddress;

    for (U32 i = 0; i < stringSize; i++) {
        destMemory[i] = toupper(stringPointer[i]);
    }
    destMemory[stringSize] = '\0';

    return destAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__print", void, _print, U32 formatAddress, I32 argList)
{
    std::cout << &memoryRef<U8>(asclMemory, formatAddress);
}

DEFINE_INTRINSIC_FUNCTION(system, "__println", void, _println, U32 formatAddress, I32 argList)
{
    std::cout << &memoryRef<U8>(asclMemory, formatAddress) << "\n";
}

static void* mpzAlloc(size_t size)
{
    return getMemoryBaseAddress(asclMemory) + heapAlloc(size);
}

static void* mpzRealloc(void* ptr, size_t oldSize, size_t newSize)
{
    void* newPtr = getMemoryBaseAddress(asclMemory) + heapAlloc(newSize);

    memcpy(newPtr, ptr, oldSize);

    return newPtr;
}

static void mpzFree(void* ptr, size_t size)
{
}

static I64 mpz_get_i(U32 mpzAddress)
{
    checkNull(mpzAddress);

    mpz_ptr mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress);

    return mpz_fits_slong_p(mpz) ? mpz_get_si(mpz) : mpz_get_ui(mpz);
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_get_i32", I32, _mpz_get_i32, U32 mpzAddress)
{
    return (I32)mpz_get_i(mpzAddress);
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_get_i64", I64, _mpz_get_i64, U32 mpzAddress)
{
    return mpz_get_i(mpzAddress);
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_get_str", U32, _mpz_get_str, U32 mpzAddress)
{
    checkNull(mpzAddress);

	const U32 allocationAddress = HEAP_ADDR;

    mpz_get_str(NULL, 10, (mpz_srcptr)(getMemoryBaseAddress(asclMemory) + mpzAddress));

    wavmAssert(HEAP_ADDR > allocationAddress);

    return allocationAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_set_i32", U32, _mpz_set_i32, I32 value)
{
    U32 mpzAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress);

    mpz_init_set_si(mpz, value);

    return mpzAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_set_i64", U32, _mpz_set_i64, I64 value)
{
    U32 mpzAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress);

    mpz_init_set_si(mpz, value);

    return mpzAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_set_str", U32, _mpz_set_str, U32 valueAddress)
{
    U32 mpzAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress);
    U8* valueString = &memoryRef<U8>(asclMemory, valueAddress);

    mpz_init_set_str(mpz, (const char*)valueString, 0);

    return mpzAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_add", U32, _mpz_add, U32 mpzAddress1, U32 mpzAddress2)
{
    checkNull(mpzAddress1);
    checkNull(mpzAddress2);

    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_add(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_sub", U32, _mpz_sub, U32 mpzAddress1, U32 mpzAddress2)
{
    checkNull(mpzAddress1);
    checkNull(mpzAddress2);

    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_sub(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_mul", U32, _mpz_mul, U32 mpzAddress1, U32 mpzAddress2)
{
    checkNull(mpzAddress1);
    checkNull(mpzAddress2);

    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_mul(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_div", U32, _mpz_div, U32 mpzAddress1, U32 mpzAddress2)
{
    checkNull(mpzAddress1);
    checkNull(mpzAddress2);

    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_tdiv_q(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_mod", U32, _mpz_mod, U32 mpzAddress1, U32 mpzAddress2)
{
    checkNull(mpzAddress1);
    checkNull(mpzAddress2);

    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_mod(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_and", U32, _mpz_and, U32 mpzAddress1, U32 mpzAddress2)
{
    checkNull(mpzAddress1);
    checkNull(mpzAddress2);

    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_and(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_or", U32, _mpz_or, U32 mpzAddress1, U32 mpzAddress2)
{
    checkNull(mpzAddress1);
    checkNull(mpzAddress2);

    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_ior(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_xor", U32, _mpz_xor, U32 mpzAddress1, U32 mpzAddress2)
{
    checkNull(mpzAddress1);
    checkNull(mpzAddress2);

    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_xor(r_mpz, mpz1, mpz2);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_rshift", U32, _mpz_rshift,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    checkNull(mpzAddress1);
    checkNull(mpzAddress2);

    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_tdiv_q_2exp(r_mpz, mpz1, mpz_get_ui(mpz2));

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_lshift", U32, _mpz_lshift,
                          U32 mpzAddress1, U32 mpzAddress2)
{
    checkNull(mpzAddress1);
    checkNull(mpzAddress2);

    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_init2(r_mpz, MPZ_MAX_BITS);
    mpz_mul_2exp(r_mpz, mpz1, mpz_get_ui(mpz2));

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_cmp", U32, _mpz_cmp, U32 mpzAddress1, U32 mpzAddress2)
{
    checkNull(mpzAddress1);
    checkNull(mpzAddress2);

    mpz_ptr mpz1 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress1);
    mpz_ptr mpz2 = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress2);

    return mpz_cmp(mpz1, mpz2);
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_neg", U32, _mpz_neg, U32 mpzAddress)
{
    checkNull(mpzAddress);

    mpz_ptr mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_neg(r_mpz, mpz);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_sign", I32, _mpz_sign, U32 mpzAddress)
{
    checkNull(mpzAddress);

    return mpz_sgn((mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress));
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_abs", U32, _mpz_abs, U32 mpzAddress)
{
    checkNull(mpzAddress);

    mpz_ptr mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_abs(r_mpz, mpz);

    return resAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__mpz_pow", U32, _mpz_pow, U32 mpzAddress, I32 exponent)
{
    checkNull(mpzAddress);

    mpz_ptr mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + mpzAddress);
    U32 resAddress = heapAllocPtr(sizeof(mpz_t));
    mpz_ptr r_mpz = (mpz_ptr)(getMemoryBaseAddress(asclMemory) + resAddress);

    mpz_pow_ui(r_mpz, mpz, exponent);

    return resAddress;
}

template<typename T> static U32 array_get(U32 arrayAddress, U32 dimension, U32 index, U32 typeSize)
{
    checkNull(arrayAddress);

    T* arrayPointer = &memoryRef<T>(asclMemory, arrayAddress);

    if (index >= arrayPointer[0])
        throwFormattedException(1, 1, 0, "index out of bounds: %d", index);

    U32 unitSize;
    if (dimension == 0)
        unitSize = typeSize;
    else
        unitSize = dimension * sizeof(T) + arrayPointer[dimension] * typeSize;

    return arrayAddress + sizeof(T) + (unitSize * index);
}

DEFINE_INTRINSIC_FUNCTION(system, "__array_get_i32", U32, _array_get_i32,
                          U32 arrayAddress, U32 dimension, U32 index, U32 typeSize)
{
    return array_get<U32>(arrayAddress, dimension, index, typeSize);
}

DEFINE_INTRINSIC_FUNCTION(system, "__array_get_i64", U32, _array_get_i64,
                          U32 arrayAddress, U32 dimension, U32 index, U32 typeSize)
{
    return array_get<U64>(arrayAddress, dimension, index, typeSize);
}

DEFINE_INTRINSIC_FUNCTION(system, "__char_get", U32, _char_get, U32 stringAddress, U32 index)
{
    checkNull(stringAddress);

    U8* stringPointer = getMemoryBaseAddress(asclMemory) + stringAddress;

    if (index >= strlen((const char*)stringPointer))
        throwFormattedException(1, 1, 0, "index out of bounds: %d", index);

    return stringPointer[index];
}

DEFINE_INTRINSIC_FUNCTION(system, "__char_set", void, _char_set,
                          U32 stringAddress, U32 index, U32 character)
{
    checkNull(stringAddress);

    U8* stringPointer = getMemoryBaseAddress(asclMemory) + stringAddress;

    if (index >= strlen((const char*)stringPointer))
        throwFormattedException(1, 1, 0, "index out of bounds: %d", index);

    stringPointer[index] = character;
}

template<typename K,typename V> static U32 map_new(void)
{
    HashMap<K, V> hashmap = {};

    U32 mapAddress = heapAllocPtr(sizeof(HashMap<K, V>));
    U8* map = getMemoryBaseAddress(asclMemory) + mapAddress;

    memcpy(map, &hashmap, sizeof(HashMap<K, V>));

    return mapAddress;
}

DEFINE_INTRINSIC_FUNCTION(system, "__map_new_i32_i32", U32, _map_new_i32_i32)
{
    return map_new<I32, I32>();
}

DEFINE_INTRINSIC_FUNCTION(system, "__map_new_i32_i64", U32, _map_new_i32_i64)
{
    return map_new<I32, I64>();
}

DEFINE_INTRINSIC_FUNCTION(system, "__map_new_i64_i32", U32, _map_new_i64_i32)
{
    return map_new<I64, I32>();
}

DEFINE_INTRINSIC_FUNCTION(system, "__map_new_i64_i64", U32, _map_new_i64_i64)
{
    return map_new<I64, I64>();
}

template<typename K, typename V> static void map_put(U32 mapAddress, K key, V value)
{
    checkNull(mapAddress);

    HashMap<K, V>* map =
        reinterpret_cast<HashMap<K, V>*>(getMemoryBaseAddress(asclMemory) + mapAddress);

    (*map).set(key, value);
}

DEFINE_INTRINSIC_FUNCTION(system, "__map_put_i32_i32", void, _map_put_i32_i32, U32 mapAddress,
                          I32 key, I32 value)
{
    map_put<I32, I32>(mapAddress, key, value);
}

DEFINE_INTRINSIC_FUNCTION(system, "__map_put_i32_i64", void, _map_put_i32_i64, U32 mapAddress,
                          I32 key, I64 value)
{
    map_put<I32, I64>(mapAddress, key, value);
}

DEFINE_INTRINSIC_FUNCTION(system, "__map_put_i64_i32", void, _map_put_i64_i32, U32 mapAddress,
                          I64 key, I32 value)
{
    map_put<I64, I32>(mapAddress, key, value);
}

DEFINE_INTRINSIC_FUNCTION(system, "__map_put_i64_i64", void, _map_put_i64_i64, U32 mapAddress,
                          I64 key, I64 value)
{
    map_put<I64, I64>(mapAddress, key, value);
}

template<typename K, typename V> static V map_get(U32 mapAddress, K key)
{
    checkNull(mapAddress);

    HashMap<K, V>* map =
        reinterpret_cast<HashMap<K, V>*>(getMemoryBaseAddress(asclMemory) + mapAddress);

    return (*map)[key];
}

DEFINE_INTRINSIC_FUNCTION(system, "__map_get_i32_i32", I32, _map_get_i32_i32, U32 mapAddress,
                          I32 key)
{
    return map_get<I32, I32>(mapAddress, key);
}

DEFINE_INTRINSIC_FUNCTION(system, "__map_get_i32_i64", I64, _map_get_i32_i64, U32 mapAddress,
                          I32 key)
{
    return map_get<I32, I64>(mapAddress, key);
}

DEFINE_INTRINSIC_FUNCTION(system, "__map_get_i64_i32", I32, _map_get_i64_i32, U32 mapAddress,
                          I64 key)
{
    return map_get<I64, I32>(mapAddress, key);
}

DEFINE_INTRINSIC_FUNCTION(system, "__map_get_i64_i64", I64, _map_get_i64_i64, U32 mapAddress,
                          I64 key)
{
    return map_get<I64, I64>(mapAddress, key);
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
        if(memoryType.size.min < 1) {
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

	instance->asclMemory = memory;

	asclMemory = instance->asclMemory;
    wavmAssert(asclMemory);

	return instance;
}

void ASCL::initializeGlobals(Context* context,
                             const IR::Module& module,
                             ModuleInstance* moduleInstance)
{
    auto stackMax = asGlobalNullable(getInstanceExport(moduleInstance, "__STACK_MAX"));
    wavmAssert(stackMax != nullptr);

    STACK_MAX = getGlobalValue(context, stackMax).i32;
    wavmAssert(STACK_MAX > 0);

    auto stackTop = asGlobalNullable(getInstanceExport(moduleInstance, "__STACK_TOP"));
    wavmAssert(stackTop != nullptr);

    STACK_TOP = getGlobalValue(context, stackTop).i32;
    wavmAssert(STACK_TOP > 0);

    HEAP_ADDR = STACK_MAX;

    mp_set_memory_functions(mpzAlloc, mpzRealloc, mpzFree);
}

void ASCL::injectCommandArgs(ASCL::Instance* instance,
                             const std::vector<const char*>& argStrings,
                             std::vector<IR::Value>& outInvokeArgs)
{
	Memory* memory = instance->asclMemory;
	U8* asclMemoryBaseAdress = getMemoryBaseAddress(memory);

	U32* argvOffsets = (U32*)(asclMemoryBaseAdress +
                              heapAlloc32((U32)(sizeof(U32) * (argStrings.size() + 1))));
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
