set(Sources ASCL.cpp ASCLVM.cpp)
set(PublicHeaders ${WAVM_INCLUDE_DIR}/ASCL/ASCLVM.h)

WAVM_ADD_LIBRARY(ASCLVM ${Sources} ${PublicHeaders})

target_link_libraries(ASCLVM Runtime WASTParse WASM RegExp NFA Logging Platform dl)

file(INSTALL ${WAVM_INCLUDE_DIR}
	 DESTINATION ${WAVM_SOURCE_DIR}/../../include
	 PATTERN *.txt EXCLUDE
	 PATTERN *.h.in EXCLUDE)

file(INSTALL ${PROJECT_BINARY_DIR}/Include/WAVM/Inline/Config.h
	 DESTINATION ${WAVM_SOURCE_DIR}/../../include/WAVM/Inline)
