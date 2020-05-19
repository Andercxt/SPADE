#!/bin/bash

cd localinput_mapping_input_kernel_module
make clean
make
insmod localinput_mapping_input.ko
cd ../localinput_mapping_output_kernel_module
make clean
make
insmod localinput_mapping_output.ko
cd ../localoutput_mapping_input_kernel_module
make clean
make
insmod localoutput_mapping_input.ko
cd ../localoutput_mapping_output_kernel_module
make clean
make
insmod localoutput_mapping_output.ko
cd ../postrouting_mapping_input_kernel_module
make clean
make
insmod postrouting_mapping_input.ko
cd ../postrouting_mapping_output_kernel_module
make clean
make
insmod postrouting_mapping_output.ko
cd ../prerouting_mapping_input_kernel_module
make clean
make
insmod prerouting_mapping_input.ko
cd ../prerouting_mapping_output_kernel_module
make clean
make
insmod prerouting_mapping_output.ko
echo "done with reinstalling netfilter-related kernel module!"
