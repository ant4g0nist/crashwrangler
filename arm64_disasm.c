#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <mach-o/arm64/reloc.h>
#include <capstone/capstone.h>

//holds the disassembled output.
char exc_handler_arm64_disas[1024];

#define printf(format, args...) \
snprintf(exc_handler_arm64_disas + strlen(exc_handler_arm64_disas), \
sizeof(exc_handler_arm64_disas) - strlen(exc_handler_arm64_disas), format, ## args)

char *arm_disassemble64( char * sect, unsigned long left, cpu_type_t cputype)
{
	csh handle;
	cs_insn *insn;
	exc_handler_arm64_disas[0]=0;

	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
	{
		return exc_handler_arm64_disas;    
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON
	size_t count = cs_disasm(handle, sect, 1024, 0, 0, &insn);
	for(int i=0; i< count; i++)
	{
		cs_detail *detail = insn[i].detail;
		printf("%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
		break;
	}
	
	cs_close(&handle);
	return exc_handler_arm64_disas;
}