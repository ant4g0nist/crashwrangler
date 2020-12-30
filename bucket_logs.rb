#!/usr/bin/env ruby -w
##
# Copyright (c) 2010-2014 Apple Inc. All rights reserved.
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
# 
#Takes a bunch of crash logs in the Crashlog_dir directory and figures out which of these
#are duplicates
#Most people should just run this script with no arguments if the crash logs are in the "./crashlogs" directory

require 'find'
require 'optparse'
require File.dirname(File.expand_path(__FILE__)) + '/CW_CrashLog'
require File.dirname(File.expand_path(__FILE__)) + '/CrashWrangler'
#require File.dirname(File.expand_path(__FILE__)) + '/CW_Util'
require 'socket'
require 'fileutils'
require 'rubygems'

$debug_print = false


#glue together info about a unique crash point
#crashlog is one CW_CrashLog object that exemplifies this UniqueCrash.
class UniqueCrash
  attr_accessor :crashIDs, :is_exploitable, :crashlog
  def initialize(crashID, is_exploitable, crashlog) 
    @crashIDs = [crashID]
    @is_exploitable = [is_exploitable] #indicates whether the corresponding crashID(same index) is security
    @crashlog = crashlog                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
  end

  def signature
    return @crashlog.signature
  end
end

class ValNotFoundError < RuntimeError
end

class BucketLogs
  
  def initialize (crashlog_dir, offset_deviation, fuzz_log_path, recursive_scan, unique_crashes_base_dir, test_command, scan_all)
    @crashlog_dir, @offset_deviation, @fuzz_log_path, @recursive_scan, \
    @unique_crashes_base_dir, @test_command, @scan_all = \
    crashlog_dir, offset_deviation, fuzz_log_path, recursive_scan, \
    unique_crashes_base_dir, test_command, scan_all
    @crashes = []
  end
  def hidden?(path)
    return File.basename(path)[0,1] == "."
  end

  def write_log()
    require 'plist' #don't make people install the plist gem if they're not using this.

    plist = {}
    if File.exists?(@fuzz_log_path)
      plist = Plist::parse_xml(@fuzz_log_path)
    end

    uniques = []
    num_crashes = 0 
    num_exploitables = 0
    
    @crashes.each { |crash|
      uniques << {
        "sig" => crash.signature,
        "count" => crash.crashIDs.size,
        #a unique crash is exploitable if ANY of the crashes were exploitable
        "exploitable" => crash.is_exploitable.include?("yes"),
      }
      num_crashes += crash.crashIDs.size
      num_exploitables += crash.crashIDs.size if crash.is_exploitable.include?("yes")
    }

    plist['uniques'] = uniques
    plist['crashes'] = num_crashes
    plist['exploitables'] = num_exploitables
    
    plist = plist.to_plist
    file = File.open(@fuzz_log_path, "w")
    file.write(plist)
    file.close
  end

  #for each crash, copy the log to unique_crashes_base_dir/signature
  def sort_unique_crashes()
    Dir.mkdir(@unique_crashes_base_dir) unless File.directory?(@unique_crashes_base_dir)
    @crashes.each { |crash|
      crash.crashIDs.each { |log|
        sig = crash.signature
        sig = sig[0..254] if sig.size > 254
        sig_dir_path = "#{@unique_crashes_base_dir}/#{sig}"
        Dir.mkdir(sig_dir_path) unless File.directory?(sig_dir_path)
        FileUtils.cp(log, "#{@unique_crashes_base_dir}/#{sig}")
      }
    }
  end

  #return true if each element of off1 is within @offset_deviation of the corresponding element of off2
  #off1 and off2 are arrays of strings representing ints, e.g. []"0x75584", "0xffc"]
  def offsets_match?(off1, off2)
    found = true
    off1.length.times { |i|
      elem1 = off1[i].to_i(16)
      elem2 = off2[i].to_i(16)
      if not (elem1-@offset_deviation..elem1+@offset_deviation).include?(elem2)
        found = false
        break 
      end
    }

    return found
  end

  def read_logs
    if not FileTest.directory?(@crashlog_dir)
      raise "Error: #{@crashlog_dir} doesn't exist or isn't a directory."
    end
    
    log_extensions = Regexp.union([/\.crash$/, /\.crashlog\.txt$/])
    #process each file in the search path
    Find.find(@crashlog_dir) do |path|
      
      Find.prune if @recursive_scan == false and File.directory?(path) and path != @crashlog_dir
      next if File.directory?(path)
      next if hidden?(path)
      
      next unless @scan_all or path =~ log_extensions
      crashID = path
      puts "Error: #{path} size = 0" if File.size(path) == 0
      begin
        log = CW_CrashLog.new(path, false)
      rescue
        puts "Error for log at path #{path}"
        raise $!
      end
      begin
        is_expl = log.get_val("is_exploitable")
      rescue ValNotFoundError
        is_expl = "unknown"
      end
      #    exception_type = log.get_val("exception")
      #    instruction_address = log.get_val("instruction_address")

      dputs "for log #{path}"
      dputs "function_names = #{log.function_names.inspect}"
      dputs "function_offsets = #{log.function_offsets.inspect}"
      dputs "module_names = #{log.module_names.inspect}"
      dputs "module_offsets = #{log.module_offsets.inspect}"
      dputs ""
      # We consider a crash 'unique' if it crashes at a crash point that hasn't been seen before.

      #if the crash is already known, add the crashID to the list
      #otherwise add a new entry for the crash
      found = false
      @crashes.each do |crash|
        next if crash.crashlog.module_names != log.module_names

        #the names/offsets arrays are defined like this:
        #function_names[0] = the function name that crashed
        #function_names[1] = the first function name in the stack point that was not in System_modules defined below 
        # (so index 0 may have the same value as index 1)
        #if no crashing thread stack is in the crash log, they will all be set to nil
        # e.g. if it crashes in foo, function_names[0] = foo, function_names[1] = foo
        #if it crashes in abort which was called by foo, function_names[0] = abort, function_names[1] = foo
        
        #We don't just check if the function names match because it might look like
        #11  com.apple.Safari                    0x000000010812efcf 0x107fc8000 + 1470415
        #the function name 0x107fc8000 will change each time if -pie is on (on by default in 64-bit on 10.7 and later).

        #We don't just check module offset because module offsets often change between OS minor versions even when the code
        #in the function didn't change.

        #If the primary function name is 0, we don't consider the primary module offset in terms of duplicates.
        #example: 
        #0   ???                                 0x000000011672ebd8 0 + 4671597528
        #1   com.apple.some.framework         0x00007fff8707b3d6 some_function() + 1194
        #
        #If we had another log where the instruction pointer at frame 0 was different, we would 
        #still consider the two logs to be the same crash.
        
        if ( crash.crashlog.function_names == log.function_names and offsets_match?(crash.crashlog.function_offsets, log.function_offsets) ) or \
          ( offsets_match?(crash.crashlog.module_offsets,log.module_offsets) ) or \
          ( crash.crashlog.module_names[0] == "???" and offsets_match?([crash.crashlog.module_offsets[1]],[log.module_offsets[1]]) ) or \
          ( CrashLog.string_starts_with_names(crash.crashlog.function_names[0], CrashLog.Match_any_offset_functions) and crash.crashlog.function_names == log.function_names and offsets_match?([crash.crashlog.function_offsets[1]],[log.function_offsets[1]]) )
          crash.crashIDs << crashID
          crash.is_exploitable << is_expl 
          found = true
        end
      end
      if found == false 
        crash = UniqueCrash.new(crashID, is_expl, log)
        @crashes << crash
      end
    end
  end
  
  def print_crashes
    @crashes.sort! do |a, b|
      a.crashlog.function_names[0] <=> b.crashlog.function_names[0]
    end

    @crashes.each do |crash| 
      puts 
      sig = crash.signature.gsub(/\^/, " / ")
      puts "Crash at #{sig}"
      crash.crashIDs.each_index do |i| 
        crashID = crash.crashIDs[i]
        is_expl = crash.is_exploitable[i]
        puts "\texploitable=#{is_expl}: #{crashID}"
      end
    end
  end
  
  def run
    read_logs
    puts ""
    print_crashes
    write_log if @fuzz_log_path
    sort_unique_crashes if @unique_crashes_base_dir
  end
end



if $0 == __FILE__

  crashlog_dir = CrashWrangler::CRASH_LOG_DIR
  offset_deviation = 0
  fuzz_log_path = nil
  recursive_scan = true
  unique_crashes_base_dir = nil
  # re_run_with_guardmalloc = false
  test_command = nil
  scan_all = false
  options = OptionParser.new do |opts|
    opts.on("-h", "--help", "Print usage") do |o|
      puts opts
      exit(0)
    end
    opts.on("-v", "--verbose", "Print additional debugging info") do |o|
      $debug_print = true
    end
    opts.on("-l log_directory", "--logdir", "The directory containing the crash logs. " \
    "Note: if the directory contains subdirectories, it will be recursively scanned unless " \
    "the -n option is used. Default: " + crashlog_dir) do |o|
      crashlog_dir = o
    end
    opts.on("-a", "--scan-all", "If set, scan all files in the log directory. Default: scan only files with crash log file extensions.") do |o|
      scan_all = true
    end
    opts.on("-o offset", "--offset_deviation", "Maximum offset to match unique crashes on.  " \
    "E.g. -o 10 means a crash at foo+15 will match other crashes from foo+5 to foo+25. " \
    "Default: #{offset_deviation}") { |o|
      offset_deviation = o.to_i
    }
    opts.on("-u unique_crashes_dir", "--uniquecrashdir", \
    "The base directory where information about unique crashes should go. If not set, " \
    "don't log any info") do |o|
      unique_crashes_base_dir = o
    end
    opts.on("-c test_command", "--command", "The command to run to test each case in " \
    "unique_crashes_dir. e.g. ./run_qt.sh.  Only used if -g is used." ) { |o|
      test_command = o
    }
    opts.on("-f fuzz_log", "--fuzzlog", "The path to a log to write info about unique " \
    "crashes. If unset, no log will be written.") { |o|
      fuzz_log_path = o
    }
    opts.on("-n", "--no-recursive-scan", "If set, don't scan the directory recursively.") { |o|
      recursive_scan = false
    }
    opts.on("-r run_dir", "--rundir", "If set, use run_dir as the base directory to " \
    "derive unique_crashes_dir and log_directory and ignore the -u and -l options") { |o|
      run_dir = o
      crashlog_dir = "#{run_dir}/#{CrashWrangler::CRASH_LOG_DIR}"
      unique_crashes_base_dir = "#{run_dir}/#{CrashWrangler::UNIQUE_CRASHES_DIR}"
    }
  end
  options.parse!(ARGV)

  bl = BucketLogs.new(crashlog_dir, offset_deviation, fuzz_log_path, recursive_scan, unique_crashes_base_dir, test_command, scan_all)
  bl.run
end