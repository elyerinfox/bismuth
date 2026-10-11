/* The Raspberry Pi firmware (and QEMU raspi4b) loads the 64-bit kernel at 0x80000 and enters
   at EL2; RAM starts at 0x0. _start is placed first. */
ENTRY(_start)

SECTIONS
{
    . = 0x80080000;
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

    . = ALIGN(16);
    . = . + 0x40000;
    . = ALIGN(16);
    __stack_top = .;

    . = ALIGN(4096);
    __image_end = .;

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
