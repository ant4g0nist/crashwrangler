all: exc_handler

SDK=macosx
SDKPATH=$(shell xcodebuild -sdk $(SDK) -version Path)
CC=xcrun --sdk $(SDK) cc
CXX=xcrun --sdk $(SDK) c++
SW_VERS=$(shell sw_vers -productVersion | cut -b 1-4)
UNAME_M=$(shell uname -m)
DISAS_OBJECTS_DESKTOP=arm64_disasm.o
DISAS_OBJECTS=$(DISAS_OBJECTS_DESKTOP)

BREW_PREFIX=$(shell brew --prefix 2>/dev/null || echo /usr/local)

ifeq ($(UNAME_M), arm64)
	CFLAGS=-arch arm64 -g -lcapstone -L$(BREW_PREFIX)/lib -I$(BREW_PREFIX)/include
	EXC_HANDLER=exc_handler_silicon
else ifeq ($(SW_VERS), 10.10)
	CFLAGS=-arch x86_64 -g
	EXC_HANDLER=exc_handler_yosemite
else ifeq ($(SW_VERS), 10.11)
	CFLAGS=-arch x86_64 -g
	EXC_HANDLER=exc_handler_yosemite
else ifeq ($(SW_VERS), 10.12)
	CFLAGS=-arch x86_64 -g
	EXC_HANDLER=exc_handler_sierra
else
	$(shell echo i don't know what to compile)
	exit 0
endif

exc_handler: $(EXC_HANDLER)
	@true


TESTS = abort badsyscall crashread crashwrite crashexec divzero illegalinstruction nocrash  nullderef spin recursion stack_buffer_overflow malloc_abort fortify_source_overflow cfrelease_null uninit_heap recursive_write bad_func_call cpp_crash objc_crash invalid_address_64 read_and_write_instruction illegal_libdispatch fastMalloc variable_length_stack_buffer exploitable_jit null_objc_msgSend

TEST_DIR = tests_src

MIG_OUTPUT=mach_exc.h mach_excUser.c mach_excServer.h mach_excServer.c
MIG_OBJECTS=mach_excUser.o mach_excServer.o


$(MIG_OUTPUT): mach_exc.defs
	mig -header mach_exc.h -user mach_excUser.c -sheader mach_excServer.h -server mach_excServer.c mach_exc.defs

$(MIG_OBJECTS): $(MIG_OUTPUT)
	$(CC) $(CFLAGS) -Wall -Wextra -c mach_excUser.c
	$(CC) $(CFLAGS) -Wall -Wextra -c mach_excServer.c

# $(DISAS_OBJECTS_DESKTOP): i386_disasm.c
# 	$(CC) -c $(CFLAGS) i386_disasm.c

$(DISAS_OBJECTS_DESKTOP): arm64_disasm.c
	$(CC) -c $(CFLAGS) arm64_disasm.c

exc_handler.o: exc_handler.m exc_handler.h $(MIG_OUTPUT)
	$(CC) $(CFLAGS) -Wall -Wextra -c -F/System/Library/PrivateFrameworks exc_handler.m

CrashReport.o: CrashReport.m CoreSymbolication.h
	$(CC) $(CFLAGS) -Wall -Wextra -c -F/System/Library/PrivateFrameworks CrashReport.m

exc_handler_yosemite: CrashReport_Yosemite.o $(MIG_OBJECTS) $(DISAS_OBJECTS) exc_handler.o
	$(CC) $(CFLAGS) -F/System/Library/PrivateFrameworks  -framework CoreSymbolication -framework IOKit -framework Foundation -framework ApplicationServices -framework Symbolication -framework CoreServices -framework CrashReporterSupport -framework CoreFoundation -framework CommerceKit -o exc_handler exc_handler.o $(DISAS_OBJECTS) CrashReport_Yosemite.o $(MIG_OBJECTS)

exc_handler_sierra: CrashReport_Sierra.o $(MIG_OBJECTS) $(DISAS_OBJECTS) exc_handler.o
	$(CC) $(CFLAGS) -F/System/Library/PrivateFrameworks  -framework CoreSymbolication -framework IOKit -framework Foundation -framework ApplicationServices -framework Symbolication -framework CoreServices -framework CrashReporterSupport -framework CoreFoundation -framework CommerceKit -o exc_handler exc_handler.o $(DISAS_OBJECTS) -framework CrashReporterSupport $(MIG_OBJECTS)

exc_handler_silicon: CrashReport.o $(MIG_OBJECTS) $(DISAS_OBJECTS) exc_handler.o
	$(CC) $(CFLAGS) -F/System/Library/PrivateFrameworks -framework CoreSymbolication -framework IOKit -framework Foundation -framework CoreServices -framework CoreFoundation -o exc_handler exc_handler.o $(DISAS_OBJECTS) CrashReport.o $(MIG_OBJECTS)

TEST_FLAGS=

tests: $(TESTS)

abort: $(TEST_DIR)/abort.c
	$(CC) $(TEST_FLAGS) -o abort $(TEST_DIR)/abort.c
badsyscall: $(TEST_DIR)/badsyscall.c
	$(CC) $(TEST_FLAGS) -o badsyscall $(TEST_DIR)/badsyscall.c
crashread: $(TEST_DIR)/crashread.c
	$(CC) $(TEST_FLAGS) -o crashread $(TEST_DIR)/crashread.c
crashwrite: $(TEST_DIR)/crashwrite.c
	$(CC) $(TEST_FLAGS) -o crashwrite $(TEST_DIR)/crashwrite.c
crashexec: $(TEST_DIR)/crashexec.c
	$(CC) $(TEST_FLAGS) -o crashexec $(TEST_DIR)/crashexec.c
divzero: $(TEST_DIR)/divzero.c
	$(CC) $(TEST_FLAGS) -o divzero $(TEST_DIR)/divzero.c
illegalinstruction: $(TEST_DIR)/illegalinstruction.c
	$(CC) $(TEST_FLAGS) -o illegalinstruction $(TEST_DIR)/illegalinstruction.c
nullderef: $(TEST_DIR)/nullderef.c
	$(CC) $(TEST_FLAGS) -o nullderef $(TEST_DIR)/nullderef.c
nocrash: $(TEST_DIR)/nocrash.c
	$(CC) $(TEST_FLAGS) -o nocrash $(TEST_DIR)/nocrash.c
spin: $(TEST_DIR)/spin.c
	$(CC) $(TEST_FLAGS) -o spin $(TEST_DIR)/spin.c
recursion: $(TEST_DIR)/recursion.c
	$(CC) $(TEST_FLAGS) -o recursion $(TEST_DIR)/recursion.c
stack_buffer_overflow: $(TEST_DIR)/stack_buffer_overflow.c
	$(CC) $(TEST_FLAGS) -fstack-protector -D_FORTIFY_SOURCE=0 -o stack_buffer_overflow $(TEST_DIR)/stack_buffer_overflow.c
fortify_source_overflow: $(TEST_DIR)/stack_buffer_overflow.c
	$(CC) $(TEST_FLAGS) -D_FORTIFY_SOURCE=2 -fno-stack-protector -o fortify_source_overflow $(TEST_DIR)/stack_buffer_overflow.c
malloc_abort: $(TEST_DIR)/malloc_abort.c
	$(CC) $(TEST_FLAGS) -o malloc_abort $(TEST_DIR)/malloc_abort.c
cfrelease_null: $(TEST_DIR)/cfrelease_null.c
	$(CC) $(TEST_FLAGS)  -framework CoreFoundation -o cfrelease_null $(TEST_DIR)/cfrelease_null.c
uninit_heap: $(TEST_DIR)/uninit_heap.c
	$(CC) $(TEST_FLAGS) -o uninit_heap $(TEST_DIR)/uninit_heap.c
recursive_write: $(TEST_DIR)/recursive_write.c
	$(CC) $(TEST_FLAGS) -o recursive_write $(TEST_DIR)/recursive_write.c
bad_func_call: $(TEST_DIR)/bad_func_call.c
	$(CC) $(TEST_FLAGS) -o bad_func_call $(TEST_DIR)/bad_func_call.c
cpp_crash:  $(TEST_DIR)/cpp_crash.cpp
	$(CXX) $(TEST_FLAGS) -o cpp_crash $(TEST_DIR)/cpp_crash.cpp
objc_crash: $(TEST_DIR)/objc_crash.m
	$(CC) $(TEST_FLAGS) -o objc_crash -framework Foundation $(TEST_DIR)/objc_crash.m
invalid_address_64: $(TEST_DIR)/invalid_address_64.c
	$(CC) $(TEST_FLAGS) -o invalid_address_64 $(TEST_DIR)/invalid_address_64.c
read_and_write_instruction: $(TEST_DIR)/read_and_write_instruction.c
	$(CC) $(TEST_FLAGS) -o read_and_write_instruction $(TEST_DIR)/read_and_write_instruction.c
illegal_libdispatch:  $(TEST_DIR)/illegal_libdispatch.c
	$(CC) $(TEST_FLAGS) -o illegal_libdispatch $(TEST_DIR)/illegal_libdispatch.c
fastMalloc: $(TEST_DIR)/fastMalloc.cpp
	$(CXX) $(TEST_FLAGS) -o fastMalloc $(TEST_DIR)/fastMalloc.cpp
variable_length_stack_buffer: $(TEST_DIR)/variable_length_stack_buffer.c
	$(CC) $(TEST_FLAGS) -o variable_length_stack_buffer $(TEST_DIR)/variable_length_stack_buffer.c
exploitable_jit:  $(TEST_DIR)/exploitable_jit.c
	$(CC) $(TEST_FLAGS) -o exploitable_jit  $(TEST_DIR)/exploitable_jit.c
null_objc_msgSend: $(TEST_DIR)/null_objc_msgSend.c
	$(CC) $(TEST_FLAGS) -o null_objc_msgSend  $(TEST_DIR)/null_objc_msgSend.c

clean:
	- rm -rf exc_handler $(TESTS)  *.dSYM $(MIG_OUTPUT) $(DISAS_OBJECTS) $(MIG_OBJECTS) exc_handler.o CrashReport.o
