#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int vm_run(const char* filename, const char* funcname, char** args);

#ifdef __cplusplus
}
#endif
