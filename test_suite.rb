#!/usr/bin/env ruby -w
##
# Copyright (c) 2009-2010 Apple Inc. All rights reserved.
#
# @APPLE_DTS_LICENSE_HEADER_START@
# 
# IMPORTANT:  This Apple software is supplied to you by Apple Inc.
# ("Apple") in consideration of your agreement to the following terms, and your
# use, installation, modification or redistribution of this Apple software
# constitutes acceptance of these terms.  If you do not agree with these terms,
# please do not use, install, modify or redistribute this Apple software.
# 
# In consideration of your agreement to abide by the following terms, and
# subject to these terms, Apple grants you a personal, non-exclusive license,
# under Apple's copyrights in this original Apple software (the "Apple Software"),
# to use, reproduce, modify and redistribute the Apple Software, with or without
# modifications, in source and/or binary forms; provided that if you redistribute
# the Apple Software in its entirety and without modifications, you must retain
# this notice and the following text and disclaimers in all such redistributions
# of the Apple Software.  Neither the name, trademarks, service marks or logos of
# Apple Inc. may be used to endorse or promote products derived from
# the Apple Software without specific prior written permission from Apple.  Except
# as expressly stated in this notice, no other rights or licenses, express or
# implied, are granted by Apple herein, including but not limited to any patent
# rights that may be infringed by your derivative works or by other works in
# which the Apple Software may be incorporated.
# 
# The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
# WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
# WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN
# COMBINATION WITH YOUR PRODUCTS. 
# 
# IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR
# DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF
# CONTRACT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF
# APPLE HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# @APPLE_DTS_LICENSE_HEADER_END@
##
require 'fileutils'
# Forwarding to CrashReporter is now disabled by default.
# Set CW_FORWARD_CRASH_REPORTER=1 to enable it.
ENV["CW_EXPLOITABLE_JIT"]="1"
#this script assumes that make and make tests has already been run
crashlog_dir = "./crashlogs/"

Expected = {
  #[exception type, is_exploitable]
  "abort" => ["EXC_CRASH", "no"],
  "bad_func_call" => ["EXC_BAD_ACCESS", "yes"],
  # "badsyscall" => ["EXC_CRASH", "no"],
  "cfrelease_null" => ["dontcare", "no"], #on leopard, EXC_BAD_ACCESS, on SL, EXC_BREAKPOINT
  "cpp_crash" =>  ["EXC_BAD_ACCESS", "yes"],
  "crashexec" => ["EXC_BAD_ACCESS", "yes"],
  "crashread" => ["EXC_BAD_ACCESS", "no"],
  "crashwrite" => ["EXC_BAD_ACCESS", "yes"],
  "divzero" => ["EXC_ARITHMETIC", "no"],
  "exploitable_jit" => ["EXC_BAD_ACCESS", "yes"],
  "fastMalloc" => ["EXC_BAD_ACCESS", "no"],
  "fortify_source_overflow" => ["EXC_CRASH", "yes"],
  "illegal_libdispatch" => ["EXC_BAD_INSTRUCTION", "no"],
  "illegalinstruction" => ["EXC_BAD_INSTRUCTION", "yes"],
  "invalid_address_64" => ["EXC_BAD_ACCESS", "yes"],
  "malloc_abort" => ["EXC_CRASH", "yes"],
  "nocrash" => ["nocrash", "no"],
  "nullderef" => ["EXC_BAD_ACCESS", "no"],
  "objc_crash" =>  ["EXC_BAD_ACCESS", "yes"],
  "read_and_write_instruction" => ["EXC_BAD_ACCESS", "no"],
  "recursion" => ["EXC_BAD_ACCESS", "no"],
  "recursive_write" => ["EXC_BAD_ACCESS", "no"],
  "stack_buffer_overflow" => ["EXC_CRASH", "yes"],
#  "uninit_heap" => ["EXC_BAD_ACCESS", "yes"],  crashes accessing 0xaaaaaaaa were changed to be non exploitable
  "variable_length_stack_buffer" => ["EXC_BAD_ACCESS", "yes"], 
}

#if `lipo -info uninit_heap`.index("x86_64") != nil
  #note, there's a bug on 64-bit, <rdar://problem/6763905> Crash reporter should return EXC_I386_GPFLT as exception code when appropriate
#  Expected["uninit_heap"] = ["EXC_BAD_ACCESS", "no"]
#end
if `sw_vers -productVersion`.to_f < 10.7
  Expected.delete("illegal_libdispatch")
end

if `uname -m`.strip == "arm64"
  Expected["divzero"] = ["nocrash", "no"]                       # sdiv returns 0, no trap
  Expected["fortify_source_overflow"] = ["EXC_BREAKPOINT", "no"] # brk trap, not abort
  Expected["malloc_abort"] = ["EXC_BREAKPOINT", "no"]            # brk trap, not abort
  Expected["illegal_libdispatch"] = ["EXC_BREAKPOINT", "no"]     # brk, not ud2
  Expected["variable_length_stack_buffer"] = ["EXC_BAD_ACCESS", "no"] # detection limitation
end

#line =  string like exception=EXC_BAD_ACCESS:signal=Segmentation fault:is_exploitable= no:
#instruction_disassembly=movzbl       (%eax),%eax:instruction_address=0x0000000000001ff6:
#access_type=read:access_address=0x0000000041414141

#arg = string like exception or is_exploitable
#return the value for that arg. Note this won't work for access_address because it doesn't have a : at the end
def get_val (line, arg)
  #get the index immediately after arg=

  start_index = line.index(arg) 
  if start_index == nil
    raise "Error: #{arg}= not found in file."
  end
  start_index += arg.length + 1 
  end_index = line.index(":", start_index)
  #lstrip because is_exploitable =  no always has a leading space
  return line[start_index...end_index].lstrip
end

FileUtils.remove_entry_secure(crashlog_dir) if File.exist?(crashlog_dir)
Expected.sort.each { |test, expected_results|
  file_found = true
  next if (test == "spin") 
  raise "Error: ./exc_handler does not exist" if not File.exist?("./exc_handler")
  raise "Error: test ./#{test} does not exist" if not File.exist?("./#{test}")
  cmd = "env CW_CURRENT_CASE=#{test} ./exc_handler ./#{test} &> /dev/null"
  #puts "cmd = #{cmd}"
  system(cmd)
  begin
    infile = File.new("#{crashlog_dir}/#{test}.crashlog.txt", "r")
    line = infile.readline
    infile.close
  rescue
    #if the file is not found, assume it's because the program didn't crash
    exception_type = "nocrash"
    is_exploitable = "no"
    file_found = false
  end
  if file_found
    exception_type = get_val(line, "exception")
    is_exploitable = get_val(line, "is_exploitable")
  end

  
  if (expected_results[0] == exception_type or expected_results[0] == "dontcare") and expected_results[1] == is_exploitable
    puts "#{test}: PASS."
  else
    puts "#{test}: FAIL. exception_type = #{exception_type} and is_exploitable = #{is_exploitable}"
    puts "\t expected: exception_type = #{expected_results[0]} is_exploitable = #{expected_results[1]}"
  end
}
