#!/bin/bash

rmmod localinput_mapping_input
rmmod localinput_mapping_output
rmmod localoutput_mapping_input
rmmod localoutput_mapping_output
rmmod postrouting_mapping_input
rmmod postrouting_mapping_output
rmmod prerouting_mapping_input
rmmod prerouting_mapping_output
echo "done with removing netfilter-related kernel module!"
