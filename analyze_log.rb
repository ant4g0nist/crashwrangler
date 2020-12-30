#!/usr/bin/env ruby -w
##
# Copyright (c) 2009 Apple Inc. All rights reserved.
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


require 'optparse'
require File.dirname(File.expand_path(__FILE__)) + '/CrashLog'
require File.dirname(File.expand_path(__FILE__)) + '/CW_CrashLog'
require 'find'
require 'fileutils'

def hidden?(path)
  return File.basename(path)[0,1] == "."
end

$exploitable_reads = false
$exploitable_jit = false

disassembly = nil
log_file = ""
log_dir = nil

options = OptionParser.new do |opts|
  opts.on("-h", "--help", "Print usage") do |h|
    puts opts
    exit(0)
  end
  opts.on("-v", "--verbose", "Print additional debugging info") do |o|
    $debug_print = true
  end
  opts.on("-d disassembly", "--disassembly", "Disassembly of the crashing instruction") do |o|
    disassembly = o
  end
  opts.on("-r", "--exploitable-reads", "If set, non-null read access violations are considered exploitable") do |o|
    $exploitable_reads = true
  end
  opts.on("-l log_directory", "--logdir", "If set, analyze all the logs in the directory") do |o|
    log_dir = o
  end
end
options.banner = "Usage: #{$0} [options] log_file\nlog_file = path to a log file to analyze"
options.parse!(ARGV)

$exploitable_reads = true if ENV['CW_EXPLOITABLE_READS']
$exploitable_jit   = true if ENV['CW_EXPLOITABLE_JIT']

if log_dir
  
  if File.exist?("marshaled_logs")
    f = File.new("marshaled_logs", "r")
    puts "starting marshal load"
    logs = Marshal.load(f)
    puts "marshal load complete"
    num_logs = 0
    num_exploitables = 0
    num_not_exploitables = 0
    num_unknown_exploitables = 0
    
    uniques = 0
    unique_exploitables = 0
    unique_not_exploitables = 0
    unique_unknown_exploitables = 0
#    this_was_exploitable = false
    
    logs = logs.sort { |a, b|
      a[1].size <=> b[1].size #sort by number of crashes per signature
      #a[1][0][0] <=> b[1][0][0]  #sort by exploitablility
    }
    
    logs.delete_if { |log|
      log[1][0][0] != CrashLog.YES
    }
    logs.delete_if { |log|
      look_for = [
        /objc_msgSend/,
        /WTF::(try)?(f|F)ast(M|C|Re)alloc/,
        /WTF::fastFree|CFRelease|CFRetain/,
        /malloc|realloc|calloc|free|szone_error/,
        /operator delete/,
        /WTF::TCMalloc_Central_FreeList/,
        ]
      found = false
      look_for.each { |func|
        found = true if log[0] =~ func
      }    
      found
    }
    
    logs.each { |signature, crashes|
      if signature =~ /strcpy/ 
        crashes.each { |crash|
          puts "path for strcpy was #{crash[1]}"
        }
      end
    }
    
    logs.each { |signature, crashes|
      
      log_path = ""
      exploitable = nil
      crashes.each { |crash|
        exploitable = crash[0]        
        if exploitable == CrashLog.YES
          num_exploitables +=1
        elsif exploitable == CrashLog.NO
          num_not_exploitables +=1
        elsif exploitable == CrashLog.UNKNOWN
          num_unknown_exploitables +=1
        else
          raise "Error: unknown exploitable #{exploitable}"
        end         
    
        num_logs += 1
        #Assumption: all crashes for a given signature have the same exploitability.
      }
      log_path = crashes[0][1]
      puts "exploitable = #{exploitable}, signature = #{signature}, count = #{crashes.size}"
      puts "\t representative log = #{log_path}"
      
      uniques +=1

      if exploitable == CrashLog.YES
        unique_exploitables +=1
      elsif exploitable == CrashLog.NO
        unique_not_exploitables +=1
      elsif exploitable == CrashLog.UNKNOWN
        unique_unknown_exploitables +=1
      end
      
    }
    puts "crashes =  #{num_logs}. Exploitables = #{num_exploitables}. Not Exploitables = #{num_not_exploitables}.  Unknown exploitability count = #{num_unknown_exploitables}"
    puts "uniques = #{uniques}. unique exploitables = #{unique_exploitables}. unique not exploitable = #{unique_not_exploitables}.  Unique unknown exploitables = #{unique_unknown_exploitables}"
    
    exit
  end
  
  
  logs = {}
  bad_logs_dir = "bad_logs"
  raise "Error: bad directory #{log_dir}" if not File.directory?(log_dir)
  Find.find(log_dir) { |path|
    i = 0
    puts "For log #{path}"
    next if hidden?(path)
    next if File.directory?(path)
    begin
      log = CrashLog.new(path, nil)
    rescue
      puts $!
      puts $!.backtrace
      Dir.mkdir(bad_logs_dir) unless File.directory?(bad_logs_dir)
      if $!.to_s =~ /Malformed log ([^,]+), couldn't get process name/ or \
        $!.to_s =~ /Error: log file (.+) did not include a proper Thread d\+ Crashed: line./
        puts "bad file is #{$1}"
        File.move($1, bad_logs_dir)
      end
      next
    end
    puts "\tlog.signature was #{log.signature}"
    puts "\texploitable was #{log.is_exploitable_s}"
    
    puts "exploitable = #{log.is_exploitable_s} #{log.is_exploitable_s.class}"
    
    log.log_string = nil #save some space since the log string is no longer needed.
    log.crashed_thread_stack = nil
    
    #each logs entry uses key = signature, value = an array of 2-element arrays.
    
    if not logs[log.signature]
      logs[log.signature] = [[log.is_exploitable_s, log.log_path]]
    else
      logs[log.signature] << [log.is_exploitable_s, log.log_path]
    end
    
    if i % 50 == 0
      marshaled_logs = Marshal.dump(logs)
      f = File.new("marshaled_logs", "w")
      f.write(marshaled_logs)
      f.close
    end
    i += 1
    
  }
  marshaled_logs = Marshal.dump(logs)
  f = File.new("marshaled_logs", "w")
  f.write(marshaled_logs)
  f.close
  exit
end

if ARGV.length != 1
  puts opts
  exit(0)
end
log_file = ARGV[0]
raise "Error: Log file #{log_file} does not exist" if not FileTest.exists?(log_file)
raise "Error: Log file #{log_file} not readable" if not FileTest.readable?(log_file)

str = File.new(log_file, "r").read
if str =~ /instruction_disassembly=([^:]+):/
  disassembly= $1
end
crashlog = CrashLog.new(log_file, disassembly)
dputs crashlog.inspect
crashlog.describe
exploitable = crashlog.exploitable
if exploitable == CrashLog.YES
  exit(0)
elsif exploitable == CrashLog.NO
  exit(1)
else
  exit(2)
end
