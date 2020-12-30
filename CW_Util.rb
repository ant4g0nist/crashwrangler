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

require File.dirname(File.expand_path(__FILE__)) + '/FuzzPatch'
require File.dirname(File.expand_path(__FILE__)) + '/CW_CrashLog'
require 'fileutils'
require 'rubygems'
require 'net/http'
#require 'plist'

class CW_Util

  # Some shells will return -1 as 255, -2 as 254, etc.  Convert back to negative.
  def self.signed_byte(ret_val)
    ret_val = [ret_val].pack("c").unpack("c")[0]
    return ret_val
  end
  #given the path to a crash log, look up the test case.  If it doesn't exist, find the diff file that created it
  #and try to use FuzzPatch to re-create it.
  #if crashlog is not nil, it's expected to be a CW_CrashLog and crashlog_path is ignored.
  #return crashlog
  def self.patch_from_log(crashlog_path, crashlog = nil)
    if crashlog == nil
      crashlog = CW_CrashLog.new(crashlog_path, true)
    end
    test_case_path = crashlog.test_case_path
    diff_path = crashlog.diff_path

    if File.exists?(diff_path)
      puts "Attempting patch. diff path = #{diff_path}, test_case_path = #{test_case_path}"
      fuzz_patch = FuzzPatch.new(diff_path, true, $meta_files_dir)
      fuzz_patch.apply_patch
    end

    if not File.exists?(test_case_path) 
      raise "Error: couldn't find test case #{test_case_path} or diff #{crashlog.diff_path} for crash log #{crashlog_path}"
    end
    return crashlog
  end


  #For each entry in unique_crashes_dir, re-run one of the test cases with libgmalloc.
  #If it crashes with a different signature(which is more or equally exploitable), move the 
  #crash directory to the new signature prefixed with gmalloc
  #If the gmalloc directory exists already, move the logs from the crash directory to it, 
  #then delete the empty directory.
  #If the crash with libgmalloc is less exploitable, then do nothing.
  #PRE: unique_crashes_dir should have been filled out by BucketLogs.sort_unique_crashes
  def self.re_run_with_gmalloc(unique_crashes_dir, run_cmd)
    puts "Re-running crashing cases with libgmalloc(3)"
    Dir.entries(unique_crashes_dir).each { |crash_dir|
      next if crash_dir == "." or crash_dir == ".."
      orig_crashlog_dir = unique_crashes_dir + "/" + crash_dir
      raise "Error: #{orig_crashlog_dir} is not a directory" unless File.directory?(orig_crashlog_dir)

      log_paths = Dir.entries(orig_crashlog_dir)
      raise "Error: #{orig_crashlog_dir}/#{crash_dir} was empty" if log_paths.size <= 2
      first_log_path = log_paths[2]
      diffs = false
      crashlog = CW_CrashLog.new("#{orig_crashlog_dir}/#{first_log_path}", true)
      if File.exists?(crashlog.diff_path)
        diffs = true
        crashlog = patch_from_log("#{orig_crashlog_dir}/#{first_log_path}")
      end
      run_one_case_with_gmalloc(unique_crashes_dir, run_cmd, orig_crashlog_dir, first_log_path, crashlog,diffs)
      
      #Too complicated to do for now.  TODO?
      #Make sure all the logs don't get moved after the first case runs.
      #if crashlog.heap_corruption?
        #if the crash log indicates heap corruption then we need to re-run every log
        #since it's quite possible they all have different root causes.
      #  remaining_log_paths = log_paths[3..-1]
      #  if remaining_log_paths != []
      #    remaining_log_paths.each { |log_path|
      #      crashlog = patch_from_log("#{orig_crashlog_dir}/#{log_path}")
      #      run_one_case_with_gmalloc(unique_crashes_dir, run_cmd, orig_crashlog_dir, log_path, crashlog)            
      #    }
      #  end
      #end 
    }
    puts "Finished re-running unique cases with libgmalloc"
  end 
  
  def self.run_one_case_with_gmalloc(unique_crashes_dir, run_cmd, orig_crashlog_dir, log_path, crashlog, diffs) 
    old_test_case_path = crashlog.test_case_path.clone
    new_crashlog_path = "#{orig_crashlog_dir}/gmalloc_#{log_path}"
    new_test_case_path = File.dirname(old_test_case_path) + "/gmalloc_" + File.basename(old_test_case_path)
    if diffs
      FileUtils.mv(old_test_case_path, new_test_case_path) 
    else
      FileUtils.cp(old_test_case_path, new_test_case_path)
    end
    crashlog.test_case_path = new_test_case_path

    timeout = 60 #give it longer to run when using gmalloc.
    cmd = "env CW_NO_CRASH_REPORTER=1 CW_USE_GMAL=1 CW_TIMEOUT=#{timeout} " \
    "CW_LOG_PATH=\"#{new_crashlog_path}\" CW_TEST_CASE_PATH=\"#{old_test_case_path}\""\
    " #{run_cmd} \"#{new_test_case_path}\""
    puts "About to run #{cmd}"
    system(cmd)
    ret = $?.exitstatus     
    ret = signed_byte(ret) if ret
    if ret == nil or ret == -2 or ret == 0
      puts "Command was interrupted, because it hung when using gmalloc or didn't crash."
      File.unlink(new_test_case_path)
      return
    end
    if ret < 0
      #not necessarily a fatal error?
      raise "Error: #{cmd} had an error: #{ret}."
    end

    exploitable = false
    crashed = false      
    exploitable = true if ret > 100
    crashed = true if ret > 0

    #Delete the temporary file created for running this case 
    File.unlink(new_test_case_path) 
    puts "unlinking #{new_test_case_path}"

    return if not crashed
    #Do nothing if the gmalloc crash was less exploitable than the original crash
    return if not exploitable and crashlog.exploitable?

    #      puts "new crashlog path = #{new_crashlog_path}"
    new_crashlog = CW_CrashLog.new(new_crashlog_path, true)

    #skip if the crashlog didn't change or this log was already moved.
    return if File.basename(orig_crashlog_dir) == new_crashlog.signature

    new_dir = unique_crashes_dir + "/" + new_crashlog.signature
    if new_dir == orig_crashlog_dir
      raise "new and old dirs were the same.  old sig = #{crashlog.signature} new sig = #{new_crashlog.signature}"
    end
    if File.directory?(new_dir)
      puts "Moving #{orig_crashlog_dir}/* to #{new_dir}"
      Dir.entries(orig_crashlog_dir).each { |log|
        next if log == "." or log == ".."
        #move each crashlog into new_dir, then delete old dir
        FileUtils.mv("#{orig_crashlog_dir}/#{log}", new_dir)
      }
      Dir.rmdir("#{orig_crashlog_dir}")
    else 
      puts "Moving #{orig_crashlog_dir} to #{new_dir}"
      FileUtils.mv(orig_crashlog_dir, new_dir)
    end
    
    #too complicated to do now, TODO
    #since the signature is different, go to the plist and overwrite the old signature
    #we should also update exploitable if it went from no to yes
    #TODO: only overwriting one plist, shouldn't I overwrite all of them?
    # plist_path = File.dirname(crashlog.test_case_path) + "/" + CrashWrangler::FUZZ_LOG
    #     plist = Plist::parse_xml(plist_path)
    #     plist['uniques'].each { |unique|
    #       if unique['sig'] == crashlog.signature
    #         unique['sig'] = new_crashlog.signature
    #         if new_crashlog.exploitable? and not unique['exploitable']
    #           unique['exploitable'] = true
    #           plist['exploitables'] += 1
    #         end
    #         break
    #       end
    #     }
    #     plist = plist.to_plist
    # #    puts "writing #{plist} to #{plist_path}"
    #     
    #     file = File.open(plist_path, "w")
    #     file.write(plist)
    #     file.close
  end
  
  
  #send the log to the log muncher via a HTTP PUT
  #return 0 for success, nonzero for failure
  def self.put_plist(path)
    begin
      data = File.new(path, "r").read
    
      h = Net::HTTP.new('securitysaver.apple.com',3000)
      r = h.put('/fuzz_log_muncher', data, {"Content-Type" => "application/x-www-form-urlencoded"})
      puts "#{r.body}"
      if r.body !~ /ERROR/
        return 0
      elsif r.body =~ /Mysql::ConCountError: Too many connections/
        return self.put_plist(path)
      else
        puts "Above error was for #{path}"
        return 1
      end
    rescue Timeout::Error, Timeout::ExitException
      puts "ERROR for #{path}: #{$!}\n#{$!.backtrace}"
      return 1
    rescue
      raise $!
    end
  end
end
