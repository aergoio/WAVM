set(Sources ASCL.cpp ASCLVM.cpp)
set(PublicHeaders ${WAVM_INCLUDE_DIR}/ASCL/ASCLVM.h)

WAVM_ADD_LIB_COMPONENT(ASCLVM
    SOURCES ${Sources} ${PublicHeaders}
    PRIVATE_LIB_COMPONENTS Runtime WASTParse WASM RegExp NFA Logging Platform)
