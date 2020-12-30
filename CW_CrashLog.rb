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

require File.dirname(File.expand_path(__FILE__)) + '/CrashLog'
require File.dirname(File.expand_path(__FILE__)) + '/CrashWrangler'

$meta_files_dir = CrashWrangler::META_FILES_DIR

#A class for handling crash logs that are output by CrashWrangler's exc_handler.
class CW_CrashLog < CrashLog

  attr_accessor :function_names, :function_offsets, :module_names, :module_offsets, :test_case_path, :log_path

  def initialize(log_path, want_extra_info)
    super(log_path, "")

    @test_case_path = ""

    if @log_string =~ /^Test case was (.+)$/
      @test_case_path = $1
    else 
      raise "Error: crash log did not contain 'Test case was [path]"
    end
    #        puts "function_names[0] = #{function_names[0]} function_names[1] = #{function_names[1]}"
  end


  #search @log_string for something like "name=val:" and return val
  def get_val(name)
    marker = name + "="
    index = @log_string.index(marker)
    if index == nil
      raise ValNotFoundError, "ERROR: #{name}= not found in file #{@log_path}", caller
    end
    index += marker.length
    end_index = @log_string.index(":", index)
    val = @log_string[index...end_index]
    return val
  end

  def exploitable?
    return false if get_val("is_exploitable").strip == "no"
    return true  
  end
  
  #convert test_case_path into a diff path assuming the conventions used by fuzz_master.rb
  def diff_path
    #Automation system runs patched files from the meta_files subdirectory.
    #convert something like
    #./evaluation_cases/test.mov/slide_fuzz/meta_files/00000112.mov
    #to ./evaluation_cases/test.mov/slide_fuzz/00000112.mov.diff
    return nil unless @test_case_path
    diff_path = @test_case_path.gsub("/#{$meta_files_dir}/", "/")
    diff_path += ".diff"
    return diff_path
  end


end