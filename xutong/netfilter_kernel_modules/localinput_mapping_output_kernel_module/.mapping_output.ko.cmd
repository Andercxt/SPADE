cmd_/home/xutong/mapping_output_kernel_module/mapping_output.ko := ld -r -m elf_x86_64 -z max-page-size=0x200000 -T ./scripts/module-common.lds --build-id  -o /home/xutong/mapping_output_kernel_module/mapping_output.ko /home/xutong/mapping_output_kernel_module/mapping_output.o /home/xutong/mapping_output_kernel_module/mapping_output.mod.o ;  true
