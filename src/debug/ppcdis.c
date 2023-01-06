/*
 *	HT Editor
 *	ppcdis.cc
 *
 *	Copyright (C) 1999-2002 Sebastian Biallas (sb@biallas.net)
 *	Copyright 1994 Free Software Foundation, Inc.
 *	Written by Ian Lance Taylor, Cygnus Support
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <string.h> //<cstring>
#if 1 // Nick
#include <fcntl.h>
#include <unistd.h>
#endif

#include "tools/endianess.h"
#include "tools/snprintf.h"
#include "ppcdis.h"
#include "ppcopc.h"

char insnstr[256];
ppcdis_insn insn;
int mode;

void/*PPCDisassembler::*/PPCDisassembler(int aMode)
{
	mode = aMode;
}

dis_insn */*PPCDisassembler::*/decode(const byte *code, int maxlen, CPU_ADDR addr)
{
	const struct powerpc_opcode *opcode;
	const struct powerpc_opcode *opcode_end;
	uint32 op;
	int dialect = -1;

	insn.data = createHostInt(code, 4, big_endian);
	
	if (maxlen<4) {
		insn.valid = false;
		insn.size = maxlen;
		return &insn;
	}

	insn.size = 4;

	/* Get the major opcode of the instruction.  */
	op = PPC_OP(insn.data);

	/* Find the first match in the opcode table.  We could speed this up
	   a bit by doing a binary search on the major opcode.  */
	opcode_end = powerpc_opcodes + powerpc_num_opcodes;
	
	for (opcode = powerpc_opcodes; opcode < opcode_end; opcode++) {
		uint32 table_op;
		const byte *opindex;
		const struct powerpc_operand *operand;
		bool invalid;

		table_op = PPC_OP (opcode->opcode);

		if ((insn.data & opcode->mask) != opcode->opcode || (opcode->flags & dialect) == 0) {
			continue;
		}

		/* Make two passes over the operands.  First see if any of them
		   have extraction functions, and, if they do, make sure the
		   instruction is valid.  */
		invalid = false;
		for (opindex = opcode->operands; *opindex != 0; opindex++) {
			operand = powerpc_operands + *opindex;
			if (operand->extract) (*operand->extract)(insn.data, &invalid);
		}
		if (invalid) continue;

		/* The instruction is valid.  */
		insn.name = opcode->name;

		/* Now extract and print the operands.  */
		int opidx = 0;
		for (opindex = opcode->operands; *opindex != 0; opindex++) {
			sint32 value;

			operand = powerpc_operands + *opindex;

			/* Operands that are marked FAKE are simply ignored.  We
			   already made sure that the extract function considered
			   the instruction to be valid.  */
			if ((operand->flags & PPC_OPERAND_FAKE) != 0) continue;

			insn.op[opidx].op = operand;
			insn.op[opidx].flags = operand->flags;
			/* Extract the value from the instruction.  */
			if (operand->extract) {
				value = (*operand->extract)(insn.data, NULL);
			} else {
				value = (insn.data >> operand->shift) & ((1 << operand->bits) - 1);
				if ((operand->flags & PPC_OPERAND_SIGNED) != 0 && (value & (1 << (operand->bits - 1))) != 0) {
					value -= 1 << operand->bits;
				}
			}

			/* If the operand is optional, and the value is zero, don't
			   print anything.  */
			if ((operand->flags & PPC_OPERAND_OPTIONAL) != 0 && (operand->flags & PPC_OPERAND_NEXT) == 0 && value == 0) {
				insn.op[opidx++].imm = 0;
				continue;
			}

			if (operand->flags & PPC_OPERAND_GPR_0) {
				if (value) {
					insn.op[opidx].flags |= PPC_OPERAND_GPR;
					insn.op[opidx++].reg = value;
				} else {
					insn.op[opidx].flags = 0;
					insn.op[opidx].imm = value;
				}
			} else if (operand->flags & PPC_OPERAND_GPR) {
				insn.op[opidx++].reg = value;
			} else if (operand->flags & PPC_OPERAND_FPR) {
				insn.op[opidx++].freg = value;
			} else if (operand->flags & PPC_OPERAND_VR) {
				insn.op[opidx++].vreg = value;
			} else if (operand->flags & PPC_OPERAND_RELATIVE) {
				if (mode == PPC_MODE_32) {
					insn.op[opidx++].rel.mem = addr.addr32.offset + value;
				} else {
					insn.op[opidx++].rel.mem = addr.flat64.addr + value;
				}
			} else if ((operand->flags & PPC_OPERAND_ABSOLUTE) != 0) {
				insn.op[opidx++].abs.mem = value;
			} else if ((operand->flags & PPC_OPERAND_CR) == 0 || (dialect & PPC_OPCODE_PPC) == 0) {
				insn.op[opidx++].imm = (sint64)value;
			} else {
				insn.op[opidx++].creg = value;			}

		}
		insn.ops = opidx;

		/* We have found and printed an instruction; return.  */
		insn.valid = true;
		return &insn;
	}

	insn.valid = false;
	return &insn;
}

dis_insn */*PPCDisassembler::*/duplicateInsn(dis_insn *disasm_insn)
{
	ppcdis_insn *insn = /*ppc_*/malloc(sizeof (ppcdis_insn));
	if (insn == NULL) {
		perror("malloc()");
		exit(EXIT_FAILURE);
	}
	*insn = *(ppcdis_insn *)disasm_insn;
	return insn;
}

void /*PPCDisassembler::*/getOpcodeMetrics(int *min_length, int *max_length, int *min_look_ahead, int *avg_look_ahead, int *addr_align)
{
	*min_length = *max_length = *min_look_ahead = *avg_look_ahead = *addr_align = 4;
}

byte /*PPCDisassembler::*/getSize(dis_insn *disasm_insn)
{
	return ((ppcdis_insn*)disasm_insn)->size;
}

const char */*PPCDisassembler::*/getName(void)
{
	return "PPC/Disassembler";
}

const char */*PPCDisassembler::*/str(dis_insn *disasm_insn, int style)
{
	return strf(disasm_insn, style, "");
}

const char */*PPCDisassembler::*/strf(dis_insn *disasm_insn, int style, const char *format)
{
	if (style & DIS_STYLE_HIGHLIGHT) enable_highlighting();
	
	const char *cs_default = get_cs(e_cs_default);
	const char *cs_number = get_cs(e_cs_number);
	const char *cs_symbol = get_cs(e_cs_symbol);

	ppcdis_insn *ppc_insn = (ppcdis_insn *) disasm_insn;
	if (!ppc_insn->valid) {
		switch (ppc_insn->size) {
			case 1:
				strcpy(insnstr, "db         ?");
				break;
			case 2:
				strcpy(insnstr, "dw         ?");
				break;
			case 3:
				strcpy(insnstr, "db         ? * 3");
				break;
			case 4:
				sprintf(insnstr, "dd         %s0x%08x", cs_number, ppc_insn->data);
				break;
			default: { /* braces for empty assert */
				strcpy(insnstr, "?");
//				assert(0);
			}
		}
	} else {
		char *is = insnstr+sprintf(insnstr, "%-10s", ppc_insn->name);
		int dialect=-1;

		bool need_comma = false;
		bool need_paren = false;
		for (int opidx = 0; opidx < ppc_insn->ops; opidx++) {
			int flags = ppc_insn->op[opidx].flags;
/*			if ((flags & PPC_OPERAND_OPTIONAL) != 0 && (flags & PPC_OPERAND_NEXT) == 0 && ppc_insn->op[opidx].imm == 0) {
				continue;
			}*/
			if (need_comma) {
				is += sprintf(is, "%s, ", cs_symbol);
				need_comma = false;
			}
			if (flags & PPC_OPERAND_GPR) {
				is += sprintf(is, "%sr%d", cs_default, ppc_insn->op[opidx].reg);
			} else if ((flags & PPC_OPERAND_FPR) != 0) {
				is += sprintf(is, "%sf%d", cs_default, ppc_insn->op[opidx].freg);
			} else if ((flags & PPC_OPERAND_VR) != 0) {
				is += sprintf(is, "%svr%d", cs_default, ppc_insn->op[opidx].vreg);
			} else if ((flags & PPC_OPERAND_RELATIVE) != 0) {
				CPU_ADDR caddr;
				if (mode == PPC_MODE_32) {
					caddr.addr32.offset = (uint32)ppc_insn->op[opidx].mem.disp;
				} else {
					caddr.flat64.addr = ppc_insn->op[opidx].mem.disp;
				}
				int slen;
				char *s = (addr_sym_func) ? addr_sym_func(caddr, &slen, addr_sym_func_context) : 0;
				if (s) {
					is += sprintf(is, "%s", cs_default);
					memcpy(is, s, slen);
					is[slen] = 0;
					is += slen;
				} else {
					is += ht_snprintf(is, 100, "%s0x%qx", cs_number, ppc_insn->op[opidx].rel.mem);
				}
			} else if ((flags & PPC_OPERAND_ABSOLUTE) != 0) {
				is += ht_snprintf(is, 100, "%s0x%qx", cs_number, ppc_insn->op[opidx].abs.mem);
			} else if ((flags & PPC_OPERAND_CR) == 0 || (dialect & PPC_OPCODE_PPC) == 0) {
				is += ht_snprintf(is, 100, "%s%qd", cs_number, ppc_insn->op[opidx].imm);
			} else if (ppc_insn->op[opidx].op->bits == 3) {
				is += sprintf(is, "%scr%d", cs_default, ppc_insn->op[opidx].creg);
			} else {
				static const char *cbnames[4] = { "lt", "gt", "eq", "so" };
				int cr;
				int cc;
				cr = ppc_insn->op[opidx].creg >> 2;
				if (cr != 0) is += sprintf(is, "%s4%s*%scr%d", cs_number, cs_symbol, cs_default, cr);
				cc = ppc_insn->op[opidx].creg & 3;
				if (cc != 0) {
					if (cr != 0) is += sprintf(is, "%s+", cs_symbol);
					is += sprintf(is, "%s%s", cs_default, cbnames[cc]);
				}
			}
		
			if (need_paren) {
				is += sprintf(is, "%s)", cs_symbol);
				need_paren = false;
			}

			if ((flags & PPC_OPERAND_PARENS) == 0) {
				need_comma = true;
			} else {
				is += sprintf(is, "%s(", cs_symbol);
				need_paren = true;
			}
		}
	}
	disable_highlighting();
	return insnstr;     
}

bool /*PPCDisassembler::*/validInsn(dis_insn *disasm_insn)
{
	return ((ppcdis_insn*)disasm_insn)->valid;
}

#if 1 // Nick
static uint8_t mem[0x1000000]; // 16M

static const char *operand_types[] = {
	"UNUSED",	// #define UNUSED 0
	"BA",		// #define BA UNUSED + 1
	"BAT",		// #define BAT BA + 1
	"BB",		// #define BB BAT + 1
	"BBA",		// #define BBA BB + 1
	"BD",		// #define BD BBA + 1
	"BDA",		// #define BDA BD + 1
	"BDM",		// #define BDM BDA + 1
	"BDMA",		// #define BDMA BDM + 1
	"BDP",		// #define BDP BDMA + 1
	"BDPA",		// #define BDPA BDP + 1
	"BF",		// #define BF BDPA + 1
	"OBF",		// #define OBF BF + 1
	"BFA",		// #define BFA OBF + 1
	"BI",		// #define BI BFA + 1
	"BO",		// #define BO BI + 1
	"BOE",		// #define BOE BO + 1
	"BT",		// #define BT BOE + 1
	"CR",		// #define CR BT + 1
	"CRB",		// #define CRB CR + 1
	"CRFD",		// #define CRFD CRB + 1
	"CRFS",		// #define CRFS CRFD + 1
	"CT",		// #define CT CRFS + 1
	"D",		// #define D CT + 1
	"DS",		// #define DS D + 1
	"FLM",		// #define FLM DS + 1
	"FRA",		// #define FRA FLM + 1
	"FRB",		// #define FRB FRA + 1
	"FRC",		// #define FRC FRB + 1
	"FRS",		// #define FRS FRC + 1
	"FXM",		// #define FXM FRS + 1
	"L",		// #define L FXM + 1
	"LI",		// #define LI L + 1
	"LIA",		// #define LIA LI + 1
	"LS",		// #define LS LIA + 1
	"MB",		// #define MB LS + 1
	"ME",		// #define ME MB + 1
	"MBE",		// #define MBE ME + 1
	"UNUSED",
	"MB6",		// #define MB6 MBE + 2
	"MSLWI",	// #define MSLWI MB6 + 1
	"MSRWI",	// #define MSRWI MSLWI + 1
	"MO",		// #define MO MSRWI + 1
	"NB",		// #define NB MO + 1
	"NSI",		// #define NSI NB + 1
	"RA",		// #define RA NSI + 1
	"RA0",		// #define RA0 RA + 1
	"RAL",		// #define RAL RA0 + 1
	"RAM",		// #define RAM RAL + 1
	"RAS",		// #define RAS RAM + 1
	"RB",		// #define RB RAS + 1
	"RBS",		// #define RBS RB + 1
	"RS",		// #define RS RBS + 1
	"SH",		// #define SH RS + 1
	"SH6",		// #define SH6 SH + 1
	"SI",		// #define SI SH6 + 1
	"SISIGNOPT",	// #define SISIGNOPT SI + 1
	"SPR",		// #define SPR SISIGNOPT + 1
	"SPRBAT",	// #define SPRBAT SPR + 1
	"SPRG",		// #define SPRG SPRBAT + 1
	"SR",		// #define SR SPRG + 1
	"STRM",		// #define STRM SR + 1
	"SV",		// #define SV STRM + 1
	"TBR",		// #define TBR SV + 1
	"TO",		// #define TO TBR + 1
	"U",		// #define U TO + 1
	"UI",		// #define UI U + 1
	"VA",		// #define VA UI + 1
	"VB",		// #define VB VA + 1
	"VAB",		// #define VAB VB + 1
	"VC",		// #define VC VAB + 1
	"VD",		// #define VD VC + 1
	"VD128",	// #define VD128 VD + 1
	"VA128",	// #define VA128 VD128 + 1
	"VB128",	// #define VB128 VA128 + 1
	"VC128",	// #define VC128 VB128 + 1
	"VPERM128",	// #define VPERM128 VC128 + 1
	"VD3D0",	// #define VD3D0 VPERM128 + 1
	"VD3D1",	// #define VD3D1 VD3D0 + 1
	"VD3D2",	// #define VD3D2 VD3D1 + 1
	"SIMM",		// #define SIMM VD3D2 + 1
	"UIMM",		// #define UIMM SIMM + 1
	"SHB",		// #define SHB UIMM + 1
	"WS",		// #define WS SHB + 1
	"MTMSRD_L",	// #define MTMSRD_L WS + 1
};

int main(int argc, char **argv) {
	Disassembler();
	PPCDisassembler(PPC_MODE_32);
	if (argc >= 2) {
		// command-line argument is .bin file to disassemble
		int fd = open(argv[1], O_RDONLY);
		if (fd == -1) {
			perror(argv[1]);
			exit(EXIT_FAILURE);
		}

		ssize_t result = read(fd, mem, 0x1000000); // maximum of 16M
		if (result == (ssize_t)-1) {
			perror("read()");
			exit(EXIT_FAILURE);
		}
		int size = (int)result & ~3;

		close(fd);

		for (int pc = 0; pc < size; pc += 4) {
			dis_insn *p = decode(mem + pc, 4, (CPU_ADDR){.addr32 = {.offset = pc}});
			printf("%08x %08x\t%s\n", pc, ((ppcdis_insn *)p)->data, str(p, 0));
		} 
	}
	else {
		// with no command-line argument, print opcode table
		// note that it is not correct for some instructions like bdnz+
		// as there are further opcode restrictions based on *invalid
		for (int i = 0; i < powerpc_num_opcodes; ++i) {
			printf("opcodes %s ", powerpc_opcodes[i].name);
			for (int j = 0; j < 8; ++j) {
				int operand_type = powerpc_opcodes[i].operands[j];
				if (operand_type == 0) {
					if (j == 0)
						printf("_");
					break;
				}
				printf("%s%s", j ? "," : "", operand_types[operand_type]);
			}
			printf(" %08x %08x\n", (int)powerpc_opcodes[i].opcode, (int)powerpc_opcodes[i].mask);
			for (int j = -1; j < 0x20; ++j) {
				uint32 opcode = powerpc_opcodes[i].opcode;
				if (j >= 0) {
					if (powerpc_opcodes[i].mask & ((uint32)1 << j))
						continue;
					opcode |= (uint32)1 << j;
				}

				uint8_t data[4];
				createForeignInt(data, opcode, 4, big_endian);
				dis_insn *p = decode(data, 4, (CPU_ADDR){.addr32 = {.offset = 0}});
				printf("%08x\t%s\n", ((ppcdis_insn *)p)->data, str(p, 0));
			}
			printf("\n");
		}
	}

	return 0;
}
#endif
