#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "enum.h"
#include "src_pos.h"

int asclvm_run(const char* filename, const char* funcname, char** args);

int asclvm_test(const char* asclFile, const char* asclSource, const char* wasmFile,
                const char* wasmFunction, void (*err_fn)(ec_t, errlvl_t, src_pos_t*, ...));

#ifdef __cplusplus
}
#endif
