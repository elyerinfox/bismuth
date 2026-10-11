/* QEMU 'virt' loads the ELF at its physical addresses; RAM starts at 0x40000000, and the
   Linux-style load offset is 0x80000. We place _start first. */
ENTRY(_start)

SECTIONS
{
    . = 0x40080000;
    __image_start = .;

    .text : ALIGN(4096) {
        __text_start = .;
        KEEP(*(.text.boot))
        . = ALIGN(2048);
        KEEP(*(.text.vectors))
        *(.text .text.*)
        . = ALIGN(4096);
        __text_end = .;
    }

    .rodata : ALIGN(4096) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        . = ALIGN(4096);
        __rodata_end = .;
    }

    .data : ALIGN(4096) {
        *(.data .data.*)
    }

    .bss (NOLOAD) : ALIGN(8) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(8);
        __bss_end = .;
    }

    /* 256 KiB boot/kernel stack, 16-aligned top. */
    . = ALIGN(16);
    . = . + 0x40000;
    . = ALIGN(16);
    __stack_top = .;

    . = ALIGN(4096);
    __image_end = .;

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
