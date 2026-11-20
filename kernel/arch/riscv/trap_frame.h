#ifndef SPELLBOUND_TRAP_FRAME_H
#define SPELLBOUND_TRAP_FRAME_H

#define TRAP_PC_OFFSET 128
#define TRAP_STATUS_OFFSET 132
#define TRAP_FRAME_SIZE 144

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>

struct trap_frame {
    uint32_t x[32]; /* indexed by architectural register number */
    uint32_t pc;
    uint32_t status;
    uint32_t padding[2];
};

_Static_assert(offsetof(struct trap_frame, pc) == TRAP_PC_OFFSET, "trap PC offset");
_Static_assert(offsetof(struct trap_frame, status) == TRAP_STATUS_OFFSET, "trap status offset");
_Static_assert(sizeof(struct trap_frame) == TRAP_FRAME_SIZE, "trap frame size");
#endif

#endif
