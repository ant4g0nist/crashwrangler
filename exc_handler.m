/*
 * Copyright (c) 2009-2016 Apple Inc. All rights reserved.
 *
 * @APPLE_DTS_LICENSE_HEADER_START@
 * 
 * IMPORTANT:  This Apple software is supplied to you by Apple Inc.
 * ("Apple") in consideration of your agreement to the following terms, and your
 * use, installation, modification or redistribution of this Apple software
 * constitutes acceptance of these terms.  If you do not agree with these terms,
 * please do not use, install, modify or redistribute this Apple software.
 * 
 * In consideration of your agreement to abide by the following terms, and
 * subject to these terms, Apple grants you a personal, non-exclusive license,
 * under Apple's copyrights in this original Apple software (the "Apple Software"),
 * to use, reproduce, modify and redistribute the Apple Software, with or without
 * modifications, in source and/or binary forms; provided that if you redistribute
 * the Apple Software in its entirety and without modifications, you must retain
 * this notice and the following text and disclaimers in all such redistributions
 * of the Apple Software.  Neither the name, trademarks, service marks or logos of
 * Apple Inc. may be used to endorse or promote products derived from
 * the Apple Software without specific prior written permission from Apple.  Except
 * as expressly stated in this notice, no other rights or licenses, express or
 * implied, are granted by Apple herein, including but not limited to any patent
 * rights that may be infringed by your derivative works or by other works in
 * which the Apple Software may be incorporated.
 * 
 * The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
 * WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN
 * COMBINATION WITH YOUR PRODUCTS. 
 * 
 * IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR
 * DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF
 * CONTRACT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF
 * APPLE HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * @APPLE_DTS_LICENSE_HEADER_END@
 */

#import <AvailabilityMacros.h>  //for OS version check; should be first

#import <sys/resource.h>
#import <sys/wait.h>
#import <unistd.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <servers/bootstrap.h>
#import <Foundation/Foundation.h>
#import <launch.h>
#import <mach/task_info.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <pthread.h>
#import <signal.h>
#import <sys/signal.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <dirent.h>
#import <err.h>
#import <fcntl.h>

#if defined (__i386__) || defined (__x86_64__)
#include <mach/i386/thread_status.h>
#elif defined (__arm__) || defined (__arm64__)
#include <mach/arm/thread_status.h>
#endif

#import "exc_handler.h"
#import "mach_exc.h"
#import "mach_excServer.h"
extern char **environ;

static void kill_child() {
    kill(g_child_pid, SIGKILL);
}
static void myhandler1() {
    //child exited with a signal.
    my_printf("Terminated by noncrashing signal.\n");
    exit(RET_OTHER_SIG);
}

static void myhandler2() {
    my_printf("child exited normally\n");
    exit(RET_NO_CRASH);
}

//When the child exits, send a SIGUSR2 so the handler doesn't block forever waiting for an exception.  
void *waiter() {
    int status, signal_num;
    wait(&status);
    
    if (WIFSIGNALED(status)) {
        signal_num = WTERMSIG(status);
        //This is intended only for abnormal terminations such as SIGTERM, SIGINT, SIGKILL that aren't 
        //caught by the exception handler.  If the signal is one that would be caught by the exception
        //handler, do nothing
        if (signal_num < 4 || signal_num == 9 || signal_num > 12) {
            my_printf("child exited due to signal: %s\n", strsignal(signal_num));
            kill(getpid(), SIGUSR1);
        }
        return 0;
    }
    kill(getpid(), SIGUSR2); //exited normally
    return 0;
}



//If the string ends with an endline, null it out
static void chomp (char * str) {
    char * lastchar = str + strlen(str)-1;
    if (*lastchar == '\n' || *lastchar == '\r') {
        *lastchar = 0;
    }
}

//Intel disassembly may include colons after the segment selector, which breaks machine readability 
//of the CrashWrangler output header, which uses colons as a separator.
static void delete_colons(char *disassembly) {
    size_t i = 0;
    for (i=0; i < strlen(disassembly); i++) {
        if (disassembly[i] == ':') {
            disassembly[i] = ' ';
        }
    }
}

//Use this instead of exit.  Only needs to be called in 
//catch_mach_exception_raise_state_identity and its children.
static void my_exit(int code) {
    delete_lock();
    exit(code);
}

static mach_port_t launchd_checkin(char *service_name)
{
    mach_port_t port = MACH_PORT_NULL;
    launch_data_t msg = NULL, reply = NULL, datum = NULL;
    
    if (NULL == (msg = launch_data_new_string(LAUNCH_KEY_CHECKIN)))
    { my_printf("Could not create checkin message for launchd: %s\n", strerror(errno)); goto fin; }
    if (NULL == (reply = launch_msg(msg)))
    { my_printf("Could not message launchd: %s\n", strerror(errno)); goto fin; }
    if (LAUNCH_DATA_ERRNO == launch_data_get_type(reply))
    {
        if (launch_data_get_errno(reply) == EACCES) { 
            launch_data_free(msg); launch_data_free(reply); return(MACH_PORT_NULL); 
        }
        my_printf("Launchd checkin failed: %s.\n", strerror(launch_data_get_errno(reply))); goto fin;
    }
    if (NULL == (datum = launch_data_dict_lookup(reply, LAUNCH_JOBKEY_MACHSERVICES)) 
        || LAUNCH_DATA_DICTIONARY != launch_data_get_type(datum)) {
        my_printf("Launchd reply does not contain %s dictionary.\n", LAUNCH_JOBKEY_MACHSERVICES); goto fin; 
    }
    if (NULL == (datum = launch_data_dict_lookup(datum, service_name)) 
        || LAUNCH_DATA_MACHPORT != launch_data_get_type(datum)) { 
        my_printf("Launchd reply does not contain %s Mach port.\n", service_name); goto fin; 
    }
    if (MACH_PORT_NULL == (port = launch_data_get_machport(datum))) {
        my_printf("Launchd gave me a null Mach port.\n"); goto fin;
    }
    
fin:
    if (NULL != msg)   launch_data_free(msg);
    if (NULL != reply) launch_data_free(reply);
    return port;
}

static void check_for_debugsymbols() {
    NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];    
    CFStringRef DBGAppID                 = CFSTR("com.apple.DebugSymbols");
    CFStringRef DBGPrefKey_ShellCommands = CFSTR("DBGShellCommands");
    CFTypeRef shell                      = CFPreferencesCopyAppValue (DBGPrefKey_ShellCommands,   DBGAppID);
    
    
    if (shell) {
        fprintf(stderr, "Error: CrashWrangler does not work properly if DBGShellCommands is set in "
                "~/Library/Preferences/com.apple.DebugSymbols.plist\n");
        my_exit(RET_ERROR);
    }
    [pool drain];
}


/* 
 If there are any environment variables prefixed with CWE_, delete the prefix
 and set the environment variable in the child only.
 
 e.g. CWE_DYLD_INSERT_LIBRARIES=foo.dylib
 -> DYLD_INSERT_LIBRARIES=foo.dylib will be set in the child but not in the exc_handler process.
 */
static void copy_cwe_variables() {
    char ** envp = environ;
    char * prefix = "CWE_";
    size_t prefix_len = strlen(prefix);
	char *equals, *env_name;
    while (*envp != NULL) {
        if (strncmp(*envp, prefix, prefix_len) == 0) {
			equals = strchr(*envp, '=');
			if (! equals) {
				fprintf(stderr, "Error: bad environment variable %s", *envp);
				exit(RET_ERROR);
			}
			env_name = strdup(*envp);
			if (! env_name) {
				perror("strndup");
				exit(RET_ERROR);
			}
			env_name[ (size_t)(equals-*envp) ] = 0;
			if (putenv(*envp + prefix_len) != 0) {
				perror("putenv");
				exit(RET_ERROR);
			}
			unsetenv(env_name);
			free(env_name);
			envp = environ;  //we have to restart since environ may have been relocated to grow.
        } else {
			envp++;
		}
    }
    
}

int main(int argc, char **argv) {
    kern_return_t ret;
    char * pid_filename = NULL;
    pthread_t wait_thread; 
    pid_t attach_pid = 0;
    mach_port_t self = mach_task_self(), exc = MACH_PORT_NULL;
    mach_port_t server_port;
    char * current_case = getenv("CW_CURRENT_CASE");
    if (current_case) {
#define CR_INFO_SIZE 2048
        char * cr_info = malloc(CR_INFO_SIZE); //must be a malloced buffer; CrashReporter will free it.
        //if exc_handler crashes, we want to know what case caused it.
        snprintf(cr_info,CR_INFO_SIZE, "Running on case %s", current_case);
        CRSetCrashLogMessage(cr_info);
    }
    sigset_t set;
    sigemptyset(&set);
    pthread_sigmask(SIG_SETMASK, &set ,NULL); //unset signal mask so that the signal handlers work properly even if parent is doing something weird.
    
    // /usr/include/mach/exception_types.h
    exception_mask_t mask = EXC_MASK_CRASH;
    
    task_get_bootstrap_port(self, &g_orig_bootstrap_port);
    lock_filename = getenv("CW_LOCK_FILE");
    if (! lock_filename) {
        lock_filename = DEFAULT_LOCK_FILE;
    }
    check_for_debugsymbols();
    char * attach_pid_str = getenv("CW_ATTACH_PID");
    if (attach_pid_str) {
        attach_pid = atoi(attach_pid_str);             
    }
    char * launchd_service_name = getenv("CW_REGISTER_LAUNCHD_NAME");

    if (getenv("CW_QUIET")) {
        g_quiet = YES;
    }
    if (attach_pid) {
        my_printf("Attaching to pid %d\n", attach_pid);
    } else if (launchd_service_name) {
        my_printf("Registering with name %s\n", launchd_service_name);
    } else if (argc <=1) {
        fprintf(stderr, "Usage: %s [command to run and arguments]\n", argv[0]);
        fprintf(stderr, "Example: %s echo hello world\n", argv[0]);
        exit(RET_ERROR);
    }
    log_dir = getenv("CW_LOG_DIR");
    if (! log_dir) {
        log_dir = DEFAULT_LOG_DIR;
    }
    log_path = getenv("CW_LOG_PATH");
    if (getenv("CW_NO_LOG")) {
        log_path = "/dev/null";
    }
    g_forward_to_CrashReporter = YES;
    if (getenv("CW_NO_CRASH_REPORTER")) {
        g_forward_to_CrashReporter = NO;
    }
    if (getenv("CW_EXPLOITABLE_READS")) {
        g_exploitable_reads = YES;
    }
    if (getenv("CW_EXPLOITABLE_JIT")) {
        g_exploitable_jit = YES;
    }
    if (getenv("CW_IGNORE_FRAME_POINTER")) {
        g_ignore_frame_pointer = YES;
    }

    signal(SIGUSR1, (void (*)(int))myhandler1);
    signal(SIGUSR2, (void (*)(int))myhandler2);
	
    if (launchd_service_name)
        exc = launchd_checkin(launchd_service_name);
    if (exc == MACH_PORT_NULL) {
        if (launchd_service_name) {
            //If we're here, we know it's because launchd_checkin failed
            my_printf("Registering stand-alone service\n");
            ret = bootstrap_check_in(g_orig_bootstrap_port, launchd_service_name, &exc);
            EXIT_ON_MACH_ERROR("bootstrap_check_in", ret);
        } else {
            ret = mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &exc);
            EXIT_ON_MACH_ERROR("mach_port_allocate", ret);
        }        
    }
	ret = mach_port_insert_right(self, exc, exc, MACH_MSG_TYPE_MAKE_SEND);
	EXIT_ON_MACH_ERROR("mach_port_insert_right", ret);  
    g_exception_port = exc;
	
	ret = mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &server_port); 	 
	EXIT_ON_MACH_ERROR("mach_port_allocate 2", ret); 	 
	ret = mach_port_insert_right(self, server_port, server_port, MACH_MSG_TYPE_MAKE_SEND); 	 
	EXIT_ON_MACH_ERROR("mach_port_insert_right 2", ret); 	 
	
    if (attach_pid) {
        //set the exception port in the target task rather than in the real self
        ret = task_for_pid(self, attach_pid, &self);
        EXIT_ON_MACH_ERROR("task_for_pid: are you running as root or setgid procmod? ", ret);
        ret = task_set_exception_ports(self, 
                                       mask,
                                       exc,
                                       EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, 
                                       MACHINE_THREAD_STATE);
        EXIT_ON_MACH_ERROR("task_set_exception_ports", ret);
        
        if (argc <= 1) {
            //We're only attaching, and not launching a child.
            ret = mach_msg_server_once(mach_exc_server, 4096, exc, MACH_MSG_OPTION_NONE);
            EXIT_ON_MACH_ERROR("mach_msg_server_once", ret);
            exit(0);
        }
    }
    
    if (launchd_service_name && argc < 2) {
        ret = mach_msg_server_once(mach_exc_server, 4096, exc, MACH_MSG_OPTION_NONE);
        EXIT_ON_MACH_ERROR("mach_msg_server_once", ret);
        exit(0);
    }

    if (! getenv("CW_NO_KILL_CHILD")) {
        atexit(kill_child);
    }
	
	//set bootstrap port to server port so it'll be inherited by the child.
	//the child will then ask the server for the real bootstrap port and the exception port
	//the purpose of all this is that I don't want to catch exceptions in the parent.
	task_set_bootstrap_port(mach_task_self(), server_port);
	
    g_child_pid = fork();
    if (g_child_pid) {
        //Parent
        FILE * pidfile;        
        if (g_child_pid == -1) {
            perror("fork");
            exit(RET_ERROR);
        }
		//reset to real bootstrap port 	 
		task_set_bootstrap_port(mach_task_self(), g_orig_bootstrap_port);
		
        pid_filename = getenv("CW_PID_FILE");
        if (pid_filename) {
            //write the pid to the file
            pidfile = fopen(pid_filename, "w");
            if (pidfile == NULL) {
                perror("Creating CW_PID_FILE");
                exit(RET_ERROR);
            }
            fprintf(pidfile, "%u", g_child_pid);
            fclose(pidfile);
        }
 
        //start another thread here which waits on the child and sends a signal
        //when it exits.   This is so we're not blocked 
        //forever waiting for an exception, in the case that it exits normally.
        ret = pthread_create(&wait_thread, NULL, waiter,0);
        if (ret) {
            perror("pthread_create");
            exit(RET_ERROR);
        }
        ret = pthread_detach(wait_thread);
        if (ret) {
            perror("pthread_detach");
        }
		
		//receive the request for exception port/bootstrap 	 
		ret = mach_msg_server_once(mach_exc_server, 4096, server_port , MACH_MSG_OPTION_NONE); 	 
		EXIT_ON_MACH_ERROR("mach_msg_server_once transfer_ports", ret);
        //run the exception handler server
        ret = mach_msg_server_once(mach_exc_server, 4096, exc, MACH_MSG_OPTION_NONE);
        EXIT_ON_MACH_ERROR("mach_msg_server_once exc server", ret);
        
        ret = g_is_exploitable ? g_crashsignal + 100 : g_crashsignal;
        return ret;
    } else {
		//get real bootstrap and exception port from the parent
		transfer_ports(bootstrap_port, &g_exception_port, &g_orig_bootstrap_port);

		exc = g_exception_port;
		task_set_bootstrap_port(mach_task_self(), g_orig_bootstrap_port);
		
        //reset default signal handlers in the child
        signal(SIGUSR1, SIG_DFL);
        signal(SIGUSR2, SIG_DFL);
		
        ret = task_set_exception_ports(mach_task_self(), 
                                       mask,
                                       exc,
                                       EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, 
                                       MACHINE_THREAD_STATE);
        EXIT_ON_MACH_ERROR("task_set_exception_ports", ret);  
		
        if (getenv("CW_USE_GMAL") != NULL) {
            setenv("MALLOC_FILL_SPACE", "1", 1);
            setenv("DYLD_INSERT_LIBRARIES", "/usr/lib/libgmalloc.dylib", 1);
        }
        copy_cwe_variables();
        //exec the arguments to this program
        ret = execvp(argv[1], &argv[1]);
        //if running a program in the CWD, make sure to put ./ in front of it.
        my_printf("Attempt to execvp %s failed.\n", argv[1]);
        return RET_ERROR;
    }
    return RET_ERROR;
}

void delete_lock() {
    int ret = unlink(lock_filename);  
    
    if (ret < 0 && errno != ENOENT) {
        my_printf("lock file = %s\n", lock_filename); 
        perror ("unlink lock file");
    }
}

kern_return_t catch_transfer_ports (__attribute__((unused)) mach_port_t server, 
									mach_port_t *exception_port, 
									mach_port_t *orig_bootstrap_port) {
	*exception_port = g_exception_port;
	*orig_bootstrap_port = g_orig_bootstrap_port;
    return KERN_SUCCESS;
}


kern_return_t catch_mach_exception_raise_state_identity(__attribute__((unused)) exception_port_t exception_port, 
                                                        thread_port_t thread,
                                                        task_port_t task, exception_type_t exception, 
                                                        mach_exception_data_t code,
                                                        mach_msg_type_number_t code_count, 
                                                        int *flavor, thread_state_t in_state,
                                                        mach_msg_type_number_t in_state_count, 
                                                        thread_state_t out_state, 
                                                        mach_msg_type_number_t * out_state_count) {
    kern_return_t ret; 
    mach_msg_type_number_t data_count = PAGE_SIZE;         
    char *d_ptr = NULL;
    char *disassembly = NULL;
    const char * access_type = "";
    exception_port_t cr_exception_port;
    //create a lock file lock_filename so that the automation doesn't try to kill the 
    //child while we're still doing handling, including writing the crashlog, which 
    //seems to take forever on Leopard.        
    ret = open(lock_filename, O_CREAT | O_NOFOLLOW, 0644);
    if (ret < 0) {
        perror("Creating lock file");
        return KERN_FAILURE;
    }
    close(ret);
    
    uint64_t pc=0;
    cpu_type_t cputype = 0;
    
    //Extract the real exception and code.  EXC_CRASH multiplexes different kinds of exceptions. rdar://4708201
    exception_type_t real_exception = 0;
    //There always seem to be exactly 2 codes.  
    //If this changes in the future, will have to increase the size of this.
    mach_exception_data_type_t real_code[2];
    mach_exception_data_type_t access_address;
    if (code_count > 2) {
        fprintf(stderr, "Error: code_count > 2. Increase size of real_codes\n");
        my_exit(RET_ERROR);
    }
    memcpy(real_code, code, sizeof(real_code));
    unsigned int signal = 0;
    
#if defined (__i386__) || defined (__x86_64__)
    
    if (x86_THREAD_STATE32 == ((MY_THREAD_STATE *)in_state)->tsh.flavor) {
        pc = ((MY_THREAD_STATE *)in_state)->MY_X86_32_PC;
        cputype = CPU_TYPE_I386;
    } else {
        pc = ((MY_THREAD_STATE *)in_state)->MY_X86_64_PC;
        cputype = CPU_TYPE_X86_64;
    }
// #elif defined (__arm__) || defined (__arm64__)
#elif defined (__arm64__)
    arm_unified_thread_state_t *uts = (arm_unified_thread_state_t*)in_state;
    //NOTE: This will not work for a 64-bit exc_handler analyzing a 32-bit process or vice versa.
    //For my purposes, I don't care.
    // if (uts->ash.flavor == ARM_THREAD_STATE32) {
    //     in_state = (thread_state_t)&uts->ts_32;
    //     cputype = CPU_TYPE_ARM;
    //     pc = ((MY_THREAD_STATE *)in_state)->MY_ARM_PC;
    // } else {
        in_state = (thread_state_t)&uts->ts_64;
        cputype = CPU_TYPE_ARM64;
        pc = ((MY_THREAD_STATE *)in_state)->__pc;
    // }
    /*
    //To determine if the thread is running in Thumb mode, check the CPSR for the T flag.
    if (my_in_state->MY_ARM_CPSR & PSR_TF) {
        cputype = CPU_TYPE_THUMB;
    } else {
        cputype = CPU_TYPE_ARM;
    }
     */
#else
#error Unknown architecture
#endif
    
    /*
    int ctr = 0;
    size_t * struct_ptr = (size_t*)my_in_state;
    
    for (ctr = 0;ctr < sizeof(*my_in_state) / sizeof(size_t); ctr++) {
        printf("state[%d] = %p\n", ctr, struct_ptr[ctr]);
    }

     unsigned int i;
     for (i=0; i< code_count; i++) {
        my_printf("code[0x%x] = 0x%016qx\n", i, code[i]);
    } */
    
    //Use EXC_CRASH for everything. rdar://4708201
    /* "The current plan is to put the signal in the top 8 bits of code[0], the exception type in
        the next 4 bits, and send along the low 20 bits of the original code[0]. code[1] will be 
        unmodified, as it's often an address. This also lets Crash Reporter distinguish cases where 
        a mach exception wasn't the original cause of death, such as abort()."
    */
    if (exception != EXC_CRASH) {
        fprintf(stderr, "Error: got non-EXC_CRASH exception\n");
        my_exit(RET_ERROR);
    }
    
    //derive what type of crash it really was.
    real_exception = ((code[0] >> 20) & 0x0F);
    signal = ((code[0] >> 24) & 0xFF);
    real_code[0] = (code[0] & ~(0x00000000FFF00000));
    real_code[1]= code[1];
    access_address = real_code[1];
    
    if (real_exception == 0) {
        real_exception = EXC_CRASH;  //this is for things like abort()
    }
    g_crashsignal = signal;
//    my_printf("signal is 0x%x %s\n", signal, strsignal(signal));
//    my_printf("real_exception is 0x%x %s\n", real_exception, strexception(real_exception));
    
    //Assumption: the only reason I wouldn't be able to disassemble is if I was 
    //executing a bad address.
    if ((uint64_t)access_address == pc) {
        //note: even executing null should be considered a exploitable issue,
        APPEND_TO_LOGMSG_HR_WITH_FORMAT("Trying to execute a bad address, this is a potentially exploitable issue\n");
        g_is_exploitable = YES;
        disassembly = "";
        access_type = "exec";
    } else {
        //disassemble the instruction that caused the crash
        
        //<rdar://problem/7876658> using vm_read to read from the comm page fails.
        //need to use at least PAGE_SIZE as the third argument to vm_read
        //AND we also need to make sure we don't read past the end of the page because it might be unmapped
        //AND we need to make sure we can disassemble code near a page boundary.  
        
        mach_vm_address_t pc_page = pc & ~(PAGE_MASK);
        size_t pc_page_offset = pc & PAGE_MASK;
        size_t space_remaining = PAGE_SIZE - pc_page_offset;
        size_t amount_to_read = PAGE_SIZE;
        
        if (space_remaining < MAX_INSTRUCTION_STRLEN) {
            amount_to_read = PAGE_SIZE * 2;
        }       
        
        ret = vm_read(task, (mach_vm_address_t) pc_page, amount_to_read, 
                           (void*)&d_ptr, &data_count);
        if (ret != KERN_SUCCESS) {
            //first try: assume that we failed because we tried to read 2 pages and the
            //second page was unmapped.
            
            ret = vm_read(task, (mach_vm_address_t) pc_page, PAGE_SIZE,
                               (void*)&d_ptr, &data_count);
            if (ret != KERN_SUCCESS) {
                //aborting here because it's very important to catch when this happens, it means missing crashes.
                delete_lock(); 
                //see /usr/include/mach/kern_return.h for error codes
                printf("ERROR: mach_vm_read (disassembling) at 0x%016qx: %d\n", pc, ret);
                abort();
                //        EXIT_ON_MACH_ERROR("mach_vm_read (disassembling)", ret);

            }
        }
        disassembly = MY_DISAS(d_ptr + pc_page_offset, MAX_INSTRUCTION_STRLEN, cputype);
        printf("disassembly: %s\n", disassembly);
        delete_colons(disassembly);
        chomp(disassembly);
        //vm_read returns a dynamically allocated buffer which needs to be freed.
        //This caused a crash on iOS so it probably isn't true any more.
        //mach_vm_deallocate(mach_task_self(),(vm_address_t)d_ptr, data_count);     
    }
    
    if (real_exception == EXC_BAD_ACCESS) {
        if (strcmp(access_type, "exec")) {
             //it was either a read or a write
            access_type = get_access_type(disassembly, in_state, access_address);
            if (strcmp(access_type, "read") == 0) {
                g_is_exploitable = g_exploitable_reads; 
                
                uint32_t addr = (uint32_t) access_address; 
                uint32_t max_offset = 1024;
                //Note: This doesn't work for a 64-bit pointer 0xaaaaaaaaaaaaaaaa. 
                //If the crashing address would be invalid in the 64-bit ABI, we get EXC_I386_GPFLT 
                //for the exception code and no address code.
                //See <rdar://problem/6763905> 
                if (addr > 0x55555555 - max_offset && addr < 0x55555555 + max_offset) {
                    //It's probably exploitable in the MallocScribble case, but not necessarily in the libgmalloc case.
                    //Don't mark it exploitable, since libgmalloc is used much more than MallocScribble these days.
                    APPEND_TO_LOGMSG_HR_WITH_FORMAT("The access address indicates the use of freed memory if MallocScribble "
                                                    "was used, or uninitialized memory if libgmalloc and MALLOC_FILL_SPACE was used.\n");
                }
                if (addr > 0xaaaaaaaa - max_offset && addr < 0xaaaaaaaa + max_offset) {
                    //reading an uninitialized pointer isn't necessarily exploitable but it's interesting to note.
                    APPEND_TO_LOGMSG_HR_WITH_FORMAT("The access address indicates that uninitialized memory " 
                                                    "was being used if MallocScribble was used.\n");
                }
            } else if (strcmp(access_type, "recursion") == 0) {
                g_is_exploitable = NO;
            } else {
                //exploitable if access type is write or unknown or exec
                g_is_exploitable = YES;
            }
#if defined(__x86_64__)
            if (real_code[0] == EXC_I386_GPFLT) {
                //When the address would be invalid in the 64-bit ABI, we get a EXC_I386_GPFLT and 
                //the access address shows up as 0.  That shouldn't count as a null deref.
                //(0x0000800000000000 to 0xFFFF800000000000 is not addressable, 
                //0xFFFF800000000000 and up is reserved for future kernel use)
                APPEND_TO_LOGMSG_HR_WITH_FORMAT("The exception code indicates that the access address was invalid in the"
                                                " 64-bit ABI (it was > 0x0000800000000000).\n");
            }
#endif
			//Consider it a null dere
            if ( (size_t)access_address < PAGE_SIZE * 8
#if defined (__x86_64__)
                && real_code[0] != EXC_I386_GPFLT
#endif
            ){
                APPEND_TO_LOGMSG_HR_WITH_FORMAT("Null dereference, probably not exploitable\n");
                g_is_exploitable = NO;  //even writing to null is not exploitable.
            } else {
                //exploitability will be determined later by is_stack_suspicious() and get_access_type
                APPEND_TO_LOGMSG_HR_WITH_FORMAT("Crash accessing invalid address.  Consider running it again with " \
                                                "libgmalloc(3) to see if the log changes.\n");
            }    
        }
    } else if (real_exception == EXC_BAD_INSTRUCTION) {
        APPEND_TO_LOGMSG_HR_WITH_FORMAT("Illegal instruction at 0x%016qx, probably not an exploitable issue since this exception is usually the result of a deliberate halt.\n", pc);
        g_is_exploitable = NO;
        //disassembly = "";
    } else if (real_exception == EXC_ARITHMETIC) {
        APPEND_TO_LOGMSG_HR_WITH_FORMAT("Arithmetic exception at 0x%016qx, probably not exploitable.\n", pc);
        g_is_exploitable = NO;
    } else if (real_exception == EXC_SOFTWARE) {
        //this never seems to fire. I think it's been superseded by EXC_CRASH
        APPEND_TO_LOGMSG_HR_WITH_FORMAT("Software exception.\n");
        g_is_exploitable = NO;
    } else if (real_exception == EXC_BREAKPOINT) {
        g_is_exploitable = NO;
    } else if (real_exception == EXC_CRASH) {   
        g_is_exploitable = NO;
        //disassembly = "";
        //NOTE: if this is an abort due to -fstack-protector, MallocCorruptionAbort, etc, 
        //the log will later be patched so g_is_exploitable=YES.
    } else {
        APPEND_TO_LOGMSG_HR_WITH_FORMAT("Unknown exception number %d\n", real_exception);
        g_is_exploitable = YES; //This should never happen.
    }
    if (real_exception != EXC_BAD_ACCESS) {
        real_code[1] = 0; 
    }
    
    
    if (!g_ignore_frame_pointer && real_exception == EXC_BAD_ACCESS && bp_inconsistent_with_sp(in_state)) {
        //If the base pointer is far away from the stack pointer the most likely cause is that
        //a variable length stack buffer was passed a very large size, or the sp was otherwise
        //corrupted.
        g_is_exploitable = YES;
        APPEND_TO_LOGMSG_HR_WITH_FORMAT("Presumed exploitable based on the discrepancy between the "
                                        "stack pointer and base pointer registers. If -fomit-frame-pointer "
                                        "was used to build the code, set the CW_IGNORE_FRAME_POINTER env "
                                        "variable.\n");
    }
    
    //See README.txt for the format description.
    snprintf(logmsg, sizeof(logmsg), 
             "exception=%s:signal=%d:is_exploitable=%s:instruction_disassembly=%s:"
             "instruction_address=0x%016qx:access_type=%s:access_address=0x%016qx:\n",
             strexception(real_exception),
             signal,
             g_is_exploitable ? "yes" : " no",
             disassembly,
             pc, 
             access_type,
             access_address);
    
    write_crashlog(task, thread, exception, code, code_count, flavor, in_state, 
                   in_state_count, real_exception);
    if (g_forward_to_CrashReporter) {
        //Forward the crash to local CrashReporter. 
        //Won't work if the process is running as root.  See rdar://6833167.
        //Note: it won't actually submit the report to Apple unless you click OK or have
        //auto-submit turned on.
        ret= bootstrap_look_up(bootstrap_port, "com.apple.ReportCrash", &cr_exception_port);
        EXIT_ON_MACH_ERROR("bootstrap_look_up", ret);
        ret = mach_exception_raise_state_identity( cr_exception_port, 
                                                  thread,
                                                  task,  exception, 
                                                  code,
                                                  code_count, 
                                                  flavor,  in_state,
                                                  in_state_count, 
                                                  out_state, 
                                                  out_state_count);
        if (ret == KERN_FAILURE) {
            my_printf("Failed to forward exception to CrashReporter.\n");
        } else if (ret){
            EXIT_ON_MACH_ERROR("mach_exception_raise_state_identity", ret);
        }
    } 
    *out_state_count = in_state_count;
    memcpy(out_state,in_state,in_state_count);
    delete_lock();

    ret = mach_port_deallocate (mach_task_self(), task);
    EXIT_ON_MACH_ERROR("mach_port_deallocate task", ret);
    ret = mach_port_deallocate (mach_task_self(), thread);
    EXIT_ON_MACH_ERROR("mach_port_deallocate thread", ret);
    ret = g_is_exploitable ? g_crashsignal + 100 : g_crashsignal;
#if defined (__arm__) || defined (__arm64__)
    my_exit(ret);  //Workaround for rdar://19036151
#endif
    return KERN_SUCCESS; //KERN_SUCCESS indicates that this should not be forwarded to other handlers
}

BOOL func_is_release_retain(NSString * func) {
    return [func isEqualToString:@" _CFRelease "] || [func isEqualToString:@" CFRelease "] || [func isEqualToString:@" _CFRetain "] || [func isEqualToString:@" CFRetain "];
}

//determine if a log is exploitable by processing the stack trace, (not by disassembly)
//NOTE: this expects that the format of CrashReporter logs doesn't change.
//returns NO_CHANGE, CHANGE_TO_EXPLOITABLE, or CHANGE_TO_NOT_EXPLOITABLE
uint32_t is_stack_suspicious(NSString * desc, mach_exception_data_type_t access_address, 
                             exception_type_t exception_type) {
    unsigned int i;
    
    if (exception_type == EXC_BREAKPOINT) {
        return NO_CHANGE;
    }
    
    //If any of these functions are in the stack trace, it's likely that the crash is exploitable.
    //It uses a substring match, so we put spaces around the names to prevent false positives.
    //the CSMem ones are used a lot by QuickTime.
    //objc_msgSend has no space at the end because there are other similar named functions 
    //like objc_msgSend_vtable14
    NSString * suspicious_functions[] = {
        @" __stack_chk_fail ", @" szone_error ", @" CFRelease ", @" CFRetain ", @" _CFRelease ", @" _CFRetain", 
        @" malloc ", @" calloc ", @" realloc ",  @" objc_msgSend",
        @" szone_free ", @" free_small ", @" tiny_free_list_add_ptr ", @" tiny_free_list_remove_ptr ",
        @" small_free_list_add_ptr ", @" small_free_list_remove_ptr ", @" large_entries_free_no_lock ", 
        @" large_free_no_lock ", @" szone_batch_free ", @" szone_destroy ", @" free ", 
        @" CSMemDisposeHandle ",  @" CSMemDisposePtr ",
        @" _CFStringAppendFormatAndArgumentsAux ", @" WTF::fastFree ", @" WTF::fastMalloc ",
        @" WTF::FastCalloc ", @" WTF::FastRealloc ", @"  WTF::tryFastCalloc ", @" WTF::tryFastMalloc ",  
        @" WTF::tryFastRealloc ", @" WTF::TCMalloc_Central_FreeList ", @" GMfree ", @" GMmalloc_zone_free ",
        @" GMrealloc ", @" GMmalloc_zone_realloc ", @" WTFCrashWithSecurityImplication ", @" __chk_fail_overflow ",
    };
    // @"_CFStringCreateWithFormatAndArgumentsAux"  Theoretically adding this would be a good idea to catch format strings, but in practice you end up getting a bunch of non-exploitable null derefs.
    
    //If these functions are in the backtrace of the crashing thread, immediately return not exploitable.
    NSString * non_exploitable_functions[] = {
        @"ABORTING_DUE_TO_OUT_OF_MEMORY",
    };
    
    /* crash log looks like:
     Thread 0 Crashed:
     0   libSystem.B.dylib                 0xffff9240 __bigcopy + 256
     ...
     19  com.apple.QuickLookDaemon         0x00002334 0x1000 + 4916
     
     Thread 1:
     ...
     Thread 0 crashed with i386 Thread State 32:
     
     So crashed thread backtrace starts with "Thread %d Crashed:" and ends with either
     "Thread %d:" or "Thread %d crashed with "
     
     In 10.7, sometimes looks like
     Thread 8 Crashed:  Safari: HistoryTextCache PDF text extraction

     */
    
    NSString * start_str = @" Crashed:";
    NSString * end_str = @"\nThread ";
    NSRange startRange = [desc rangeOfString:start_str];
    if (startRange.location == NSNotFound) {
        return NO_CHANGE;
    }
    
    //The crashed thread's stack trace is whatever is between start_str and the next end_str
    
    //from the end of the start_str to the end of the description
    NSRange crashed_thread = NSMakeRange(startRange.location + startRange.length, 
                                            [desc length] - (startRange.location + startRange.length));
    //index of first end_str AFTER the start_str
    NSUInteger first_endstr = [desc rangeOfString:end_str 
                                                     options:0 
                                                       range:crashed_thread].location;
    
    if (first_endstr != NSNotFound) {
        //from the end of the start_str to the first end_str
        crashed_thread.length = first_endstr - crashed_thread.location;
    } else {
        //end_str does not appear in the log after the start_str
        //this would only happen if something was really messed up
        fprintf(stderr, "Error: this crash log appears to be malformed\n");
        delete_lock();
        abort();
    }
    
    NSString * thread_log = [desc substringWithRange:crashed_thread];
    my_printf("\nCrashed thread log = \n%s\n", [thread_log UTF8String]);
    if (g_exploitable_jit) {
        //use index 1 because the first character is an endline
        NSString * first_line = [[thread_log componentsSeparatedByString:@"\n"] objectAtIndex:1];
        //looking for something like:
        //0   ???                           	0x00005994128e5940 0 + 98492501350720
        //if we were executing an invalid address, this would already be marked exploitable, but sometimes 
        //we crash in a JIT area of memory where the pages are executable but there happens to be some valid 
        //code there that causes a null deref or other crash that normally wouldn't be considered exploitable.
        if ([first_line rangeOfString:@"0   ???"].location == 0) {
            APPEND_TO_LOGMSG_HR_WITH_FORMAT("This crash is suspected to be exploitable because the crashing "
                                            "instruction is outside of a known function, i.e. in dynamically "
                                            "generated code\n");
            return CHANGE_TO_EXPLOITABLE;
        }

    }
    //<rdar://problem/7930393> _dispatch_hardware_crash should use something other than __builtin_trap
    if (([thread_log rangeOfString:@"\n0   libdispatch.dylib"].location != NSNotFound ||
         [thread_log rangeOfString:@"\n0   libxpc.dylib"].location != NSNotFound)) {
        return CHANGE_TO_NOT_EXPLOITABLE;
    }
    
    //recursion check should come before the suspicious function check, because 
    //recursion often causes crash in e.g. malloc when growing the stack, which should be considered not exploitable.
    
    //Assume a long enough crashing thread is due to recursion
    const char * cstr = [thread_log UTF8String];
    unsigned int endline_count = 0;
    while (*cstr++) {
        if (*cstr == '\n' || *cstr == '\r') {
            endline_count++;
        }
    }
    
#define MINIMUM_RECURSION_LENGTH 300
    if (endline_count > MINIMUM_RECURSION_LENGTH) {
        APPEND_TO_LOGMSG_HR_WITH_FORMAT("The crash is suspected to be due to unbounded recursion since" 
                                        " there were %d stack frames.\n", endline_count);
        return CHANGE_TO_NOT_EXPLOITABLE;
    }
    
    for (i=0; i < sizeof(non_exploitable_functions) / sizeof(non_exploitable_functions[0]); i++) {
        NSUInteger locationOfNonExploitableFunc = [thread_log rangeOfString:non_exploitable_functions[i]].location;
        if (locationOfNonExploitableFunc != NSNotFound) {
            return CHANGE_TO_NOT_EXPLOITABLE;
        }
    }
    //search the stack frame for the name of each suspicious function.
    for (i=0; i < sizeof(suspicious_functions) / sizeof(suspicious_functions[0]); i++) {
        NSUInteger locationOfSuspiciousFunc = [thread_log rangeOfString:suspicious_functions[i]].location;
        if (locationOfSuspiciousFunc != NSNotFound) {
            if ( (exception_type == EXC_BREAKPOINT || exception_type == EXC_BAD_INSTRUCTION) &&
                func_is_release_retain(suspicious_functions[i]) ) {
                //CFRelease(NULL) is not exploitable
                //NOTE: in 10.6 and later, CFRelease(NULL) makes a EXC_BREAKPOINT crash
                //CFRelease.  In 10.13 it causes a EXC_BAD_INSTRUCTION (SIGILL)
                return CHANGE_TO_NOT_EXPLOITABLE;
            } else if ( func_is_release_retain(suspicious_functions[i])  &&
                       [thread_log rangeOfString:@"CGContextDelegateFinalize" 
                                         options:0
                                           range:NSMakeRange(0, locationOfSuspiciousFunc)
                        ].location != NSNotFound) {
                //when CGContextDelegateFinalize is called via CFRelease, it calls a lot of code which may
                //or may not indicate that a bad pointer was released
                return NO_CHANGE;
            } else if ( func_is_release_retain(suspicious_functions[i]) && (size_t)access_address < PAGE_SIZE) {
                //Crashing with a null deref under CFRelease/Retain happens sometimes in rare cases but should not be considered exploitable
                continue;
            } else if ([suspicious_functions[i] isEqualToString:@" objc_msgSend"] && (size_t)access_address < PAGE_SIZE) {
                //crashing in a null deref in objc_msgSend is theoretically exploitable since messaging nil is a no-op and
                //it probably indicates memory corruption.  But in practice these are mostly non-reproducible. No change, keep
                //searching for more suspicious functions.
                continue;
            } else {
                APPEND_TO_LOGMSG_HR_WITH_FORMAT("The crash is suspected to be an exploitable issue due to the " 
                                                "suspicious function in the stack trace of the crashing thread: \'%s\' \n", 
                                                [suspicious_functions[i] UTF8String]);
                return CHANGE_TO_EXPLOITABLE;
            }
        }
    }

    if (access_address == 0xbbadbeef) {
        //WebCore's WTFCrash() function may write a null byte to 0xbbadbeef, but it's for asserting
        //a non exploitable crash.
        //This should be after the suspicious function check since WTFCrashWithSecurityImplication
        //now calls WTFCrash sometimes.
        return CHANGE_TO_NOT_EXPLOITABLE;
    }
    return NO_CHANGE;
}



//given a disassembly, figure out what access type it is.  (read|write|recursion|unknown|exec).
//pre: disassembly should be a null terminated string
const char * get_access_type(const char *disassembly, __attribute__((unused)) thread_state_t in_state, __attribute__((unused)) mach_exception_data_type_t access_address) {
    const char * type = "unknown";
#if defined (__i386__) || defined (__x86_64__)
    //write instructions have parens around the right operand
    //read instructions have parens around the left operand
    //example: movzbl  (%eax), %eax    or movb      $0x00,(%eax)
    //or mov (eax, ebx), ecx   or mov eax, (ebx, ecx)
    //or mov (eax,ebx,4), ecx or mov eax, (ebx, ecx, 4)
    //reads always have the right parenthesis before the last comma
    //writes always have the right parenthesis after the last comma
    
    char *last_comma = strrchr(disassembly, ',');
    char *right_paren = strrchr(disassembly, ')');
    char *asterisk = strchr(disassembly, '*');
    char *dollar = strchr(disassembly, '$'); 
    char *percent = strchr(disassembly, '%'); 
    if (strchr(disassembly, ')') != right_paren) {
        //There's more than one right paren, therefore it's an instruction like
        //rep/movsl     (%esi),(%edi)
        type = type_for_two_memory(disassembly, in_state, access_address);
    } else if (strstr(disassembly, "call")) {
        //If the instruction looks like call   0x1fe6 <foo> then it's due to the stack pointer
        //being out of bounds due to recursion or evil-sized variable size stack buffer
        //If it looks like call  *0x8(%eax) or call *%eax, or call (%eax) then it's exploitable
        if (! right_paren && ! asterisk) { //optimize for common case
            type = "recursion";
        } else if (stack_access_crash(in_state, access_address)) {
            type = "recursion";  
        } else {
            type = "exec";
        }
    } else if (strstr(disassembly, "cmp") || strstr(disassembly, "test") || strstr(disassembly, "fld")) {
        //These instructions are always reads, even when the right operand is the one being dereferenced.
        type = "read";  
    } else if (strstr(disassembly, "fst")) {
        type = "write";  //floating point store
    } else if (strstr(disassembly, "mov") && ! right_paren && ! dollar && percent && last_comma) {
        //if there is no parenthesis and no dollar sign then it is something like mov    0x41414141,%eax
        //which is deferencing the constant first argument.
        if (percent > last_comma) {
            type = "read";
        } else {
            type = "write";
        }
    } else if (last_comma && right_paren) {
        //it has 2 operands and an explicit dereference
        if (right_paren < last_comma) {
            type = "read";
        } else {
            type = "write";
        }
    } else if (strstr(disassembly, "jmp")) {
        type = "exec";
    } else if (strstr(disassembly, "push")) {
        //push (%eax) might mean crashing reading eax, or crashing writing to (%esp)
        //push eax crashing would always mean crashing writing to (%esp)
        if (right_paren) {
            type = "read"; //probably, anyways. 
        } else {
            type = "recursion";            
        }
    } else if (strstr(disassembly, "inc") || strstr(disassembly, "dec")) {
        //increment or decrement instructions.  Example: inc (%eax)
        //inc %eax would never crash, so we must be writing to memory.
        type = "write";
    } else if (strstr(disassembly, "stos")) {
        type = "write";
    } else if (strstr(disassembly, "lods")) {
        type = "read";
    } else {
        type = "unknown";
    }
    //TODO: other instructions which take one operand and might cause a crash?    

#elif defined(__arm__) || defined (__arm64__)
    //write instructions start with "st"
    //read instructions start with "ld"
    if (strncmp(disassembly, "st", 2) == 0) {
        type = "write";
    } else if (strncmp(disassembly, "ld", 2) == 0) {
        type = "read";
    } else if (strncmp(disassembly, "push",4) == 0) {
        type = "recursion";
    } else {
        type = "unknown";
    }
    
#else 
#error Unknown architecture

#endif
    return type;
}


//Note: this is only called from the i386/x86_64 code
uint64_t value_for_first_register(const char *disassembly, thread_state_t in_state) {
    char * first_left_paren = strchr(disassembly, '(');
    char * first_reg = first_left_paren + 2; //jump over % and 'e' or 'r'   
    
    if (*first_reg == 'r' || *first_reg == 'e') {
        first_reg++;
    }
    return value_for_register(first_reg, (MY_THREAD_STATE*)in_state);
    
}

//return whether or not the base pointer is far away from the stack pointer.
int bp_inconsistent_with_sp(thread_state_t in_state) {
#define MAX_DISTANCE (PAGE_SIZE * 10)
    uint64_t bp_val = value_for_register("bp", (MY_THREAD_STATE*)in_state);

    uint64_t sp_val = value_for_register("sp", (MY_THREAD_STATE*)in_state);
    //No check if bp_val > sp_val since bp_val - sp_val may have underflowed.
    if (bp_val - sp_val > MAX_DISTANCE) {
        return YES;
    }
    return NO;
    
}


//Determine if a crash is due to accessing near the stack pointer
int stack_access_crash(thread_state_t in_state, mach_exception_data_type_t access_address) {
    
    uint64_t sp_val = value_for_register("sp", (MY_THREAD_STATE*)in_state);
    //with a recursion crash, the access address might look like 0x00007fff5f3ffff8
    //when rsp is 0x7fff5f400000
    if ((sp_val - access_address) <= PAGE_SIZE) {
        return YES;
    }
    
    return NO;
}

//get the access type for an instruction like rep/movsl     (%esi),(%edi)
//that does 2 memory accesses at once.
const char * type_for_two_memory(const char *disassembly, thread_state_t in_state, mach_exception_data_type_t access_address) {
    uint64_t first_reg_val = value_for_first_register(disassembly, in_state);
    if (first_reg_val == (uint64_t)access_address) {
        return "read";
    } else {
        return "write";
    }
}

//reg should be a 2 character string like ax, di, dx, not necessarily null terminated.
uint64_t value_for_register(__attribute__((unused)) char *reg, __attribute__((unused)) MY_THREAD_STATE *in_state) {
    //For now ignore the possibility that r8-r15 on 64-bit were involved.  
    //In practice it's always rsi and rdi anyways.
    
#if defined (__i386__) || defined (__x86_64__) 
    
    uint64_t ax, bx, cx, dx, di, si, sp, bp;
    
    if (x86_THREAD_STATE32 == in_state->tsh.flavor) { 
        ax = in_state->MY_X86_32_AX;
        bx = in_state->MY_X86_32_BX;
        cx = in_state->MY_X86_32_CX;
        dx = in_state->MY_X86_32_DX;
        di = in_state->MY_X86_32_DI;
        si = in_state->MY_X86_32_SI;
        sp = in_state->MY_X86_32_SP;
        bp = in_state->MY_X86_32_BP;
    } else {
        ax = in_state->MY_X86_64_AX;
        bx = in_state->MY_X86_64_BX;
        cx = in_state->MY_X86_64_CX;
        dx = in_state->MY_X86_64_DX;
        di = in_state->MY_X86_64_DI;
        si = in_state->MY_X86_64_SI;
        sp = in_state->MY_X86_64_SP;
        bp = in_state->MY_X86_64_BP;
    }

    if (strncmp(reg, "ax", 2) == 0) {        
        return ax;
    } else if (strncmp(reg, "bx", 2) == 0) {
        return bx;
    } else if (strncmp(reg, "cx", 2) == 0) {
        return cx;
    } else if (strncmp(reg, "dx", 2) == 0) {
        return dx;
    } else if (strncmp(reg, "di", 2) == 0) {
        return di;
    } else if (strncmp(reg, "si", 2) == 0) {
        return si;
    } else if (strncmp(reg, "sp", 2) == 0) {
        return sp;
    } else if (strncmp(reg, "bp", 2) == 0) {
        return bp;
    } else {
        printf("ERROR: unexpected register %s\n", reg);
        abort();
    }
#elif defined(__arm__) || defined (__arm64__)
    if (strncmp(reg, "cp", 2) == 0) {
        return in_state->__cpsr;
    } else if (strncmp(reg, "sp", 2) == 0) {
        return in_state->__sp;
    } else if (strncmp(reg, "bp", 2) == 0) {
        return in_state->__fp;
    } else {
        printf("ERROR: unexpected register %s\n", reg);
        abort();
    }
#else
#error Invalid architecture
#endif
}

void write_crashlog(task_t task, thread_t thread, exception_type_t exception, 
                   mach_exception_data_t code, mach_msg_type_number_t code_count, 
                   int *flavor, thread_state_t in_state, 
                   mach_msg_type_number_t in_state_count, exception_type_t real_exception_type) {
    unsigned int i; int fd;
    char log_name[PATH_MAX];
    memset(log_name, 0, sizeof(log_name));
    char * current_case =0;
    char * test_case_path;
    char cur_case_store[PATH_MAX];
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];     
    CrashReport *_crashReport = nil;

    _crashReport = [[CrashReport alloc] initWithTask:task
                                        exceptionType: exception
                                        exceptionCode: code
                                        exceptionCodeCount: code_count
                                        thread: thread
                                        threadStateFlavor: *flavor
                                        threadState: (thread_state_t)in_state
                                        threadStateCount: in_state_count];
    char *log_info;
    NSString *crashDescription = [_crashReport description];
    char *descr= (char*)[crashDescription UTF8String]; 
        
    mach_exception_data_type_t access_address = code[1];
    uint32_t res = is_stack_suspicious(crashDescription, access_address, real_exception_type);
    
    //The current spec if that by default, the machine readable and human readable headers are both added.
    //if this env var is set, only the machine readable header is added.
    if (!getenv("CW_MACHINE_READABLE")) {
        strlcat(logmsg, logmsg_human_readable, sizeof(logmsg));
    } 
    if (res == CHANGE_TO_EXPLOITABLE) {
        g_is_exploitable = YES;
        char * is_expl = strstr(logmsg, "is_exploitable=");
        if (is_expl) {
            memcpy(is_expl + strlen("is_exploitable="), "yes", 3);
        }
    } else if (res == CHANGE_TO_NOT_EXPLOITABLE) {
        g_is_exploitable = NO;
        char * is_expl = strstr(logmsg, "is_exploitable=");
        if (is_expl) {
            memcpy(is_expl + strlen("is_exploitable="), " no", 3);
        }
    }
    

    
    char * log_extension = ".crashlog.txt";
    int basename_index = 0;
    
    //if CW_CASE_FILE is set, then we read the current case from that file
    //otherwise, get it from the env variable CW_CURRENT_CASE, which is preferred.
    char * case_file = getenv("CW_CASE_FILE");
    if (case_file) {
        int fd = open(case_file, O_RDONLY);
        if (fd <0) {
            perror("opening CW_CASE_FILE");
            my_exit(RET_ERROR);
        }
        int nread = read(fd, cur_case_store, sizeof(cur_case_store)-1);
        if (nread < 0){
            perror("reading CW_CASE_FILE");
            my_exit(RET_ERROR);
        }
        current_case = cur_case_store;
        current_case[nread] = 0;
        chomp(current_case); //cut off trailing endline
    } else {
        current_case = getenv("CW_CURRENT_CASE");
        if (! current_case && ! log_path) {
            fprintf(stderr, "ERROR: You must set the environment variable CW_CURRENT_CASE, "
                    "CW_CASE_FILE, or CW_LOG_PATH\n");
            my_exit(RET_ERROR);
        }
    }
    
    test_case_path = getenv("CW_TEST_CASE_PATH");
    if (! test_case_path) {
        test_case_path = current_case;
    }
    
    //if CW_LOG_PATH was not defined, then derive it from CW_CASE_FILE or CW_CURRENT_CASE
    if ( ! log_path) {
        strlcpy(log_name, log_dir, sizeof(log_name));
        if (log_name[strlen(log_name)-1] != '/') {
            strlcat(log_name, "/", sizeof(log_name)); 
        } 
        basename_index = strlen(log_name);
        strlcat(log_name, current_case, sizeof(log_name));
    
        //escape out / or . characters
        for (i=basename_index;i < strlen(log_name); i++) {
            if (log_name[i] == '/' || log_name[i] == '.') {
                log_name[i] = '_';
            }
        }
        strlcat(log_name, log_extension, sizeof(log_name));
        log_path = log_name;
        //if the directory doesn't exist, create it.
        if (! opendir(log_dir)) {        
            if (mkdir(log_dir, 0755)) {
                fprintf(stderr, "Error trying to create directory %s\n", log_dir);
                my_exit(RET_ERROR);
            }
        }
    } 
    my_printf("log name is: %s\n---\n", log_path);

    fd = open(log_path, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (fd < 0 ){
        perror("open crashlog file");
        my_exit(RET_ERROR);
    }
    my_printf("%s", logmsg);

    snprintf(logmsg + strlen(logmsg), sizeof(logmsg) - strlen(logmsg), "Test case was %s\n", test_case_path);
    log_info = getenv("CW_LOG_INFO");
    if (log_info) {
        snprintf(logmsg + strlen(logmsg), sizeof(logmsg) - strlen(logmsg), "LOG_INFO: %s\n", log_info);
    }
    strlcat(logmsg, "\n\n\n", sizeof(logmsg));
    
    if (write (fd, logmsg, strlen(logmsg)) < 0) {
        perror("write crashlog file 1");
        my_exit(RET_ERROR);
    }
    if (write (fd, descr, strlen(descr)) < 0) {
        perror("write crashlog file");
        my_exit(RET_ERROR);
    }
    close(fd);
    [_crashReport release];
    [pool drain];
}

const char * strexception(exception_type_t exception) {
    const char *exceptionTypeDescription;
    switch(exception) {
        case EXC_BAD_ACCESS:
            exceptionTypeDescription = "EXC_BAD_ACCESS";
            break;
        case EXC_BAD_INSTRUCTION:
            exceptionTypeDescription = "EXC_BAD_INSTRUCTION";
            break;
        case EXC_ARITHMETIC:
            exceptionTypeDescription = "EXC_ARITHMETIC";
            break;
        case EXC_EMULATION:
            exceptionTypeDescription = "EXC_EMULATION";
            break;
        case EXC_SOFTWARE:
            exceptionTypeDescription = "EXC_SOFTWARE";
            break;
        case EXC_BREAKPOINT: 
            exceptionTypeDescription = "EXC_BREAKPOINT";
            break;
        case EXC_SYSCALL:
            exceptionTypeDescription = "EXC_SYSCALL";
            break;
        case EXC_MACH_SYSCALL:
            exceptionTypeDescription = "EXC_MACH_SYSCALL";
            break;
        case EXC_RPC_ALERT:
            exceptionTypeDescription = "EXC_RPC_ALERT";
            break;
        case EXC_CRASH:
            exceptionTypeDescription = "EXC_CRASH";
            break;
        default:
            exceptionTypeDescription = "EXCEPTION TYPE UNKNOWN";
            break;
    }
    return exceptionTypeDescription;
}

