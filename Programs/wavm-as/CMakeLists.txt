WAVM_ADD_EXECUTABLE(wavm-as
	FOLDER Programs
	SOURCES wavm-as.cpp
	PRIVATE_LIB_COMPONENTS Logging IR WASTParse WASM Platform)
WAVM_INSTALL_TARGET(wavm-as)
