#!/bin/bash

set -ex

# Run the test
rm -f smoke.serial
set +e

FW_PATH=binaries/opensbi-riscv64-generic-fw_dynamic.bin
QEMU=./binaries/qemu-system-riscv64
XEN=./binaries/xen

CONFIG_FILE="dom0.conf"
PLATFORM_NAME=dom0-qemu-virt
PLATFORM_PCPU_NUM=1
PLATFORM_RAM_SIZE=2g
PLATFORM_XEN_BOOTARGS="com1=poll sched=null"
DOM0_KERNEL_ADDR=0x808ef000
DOM0_KERNEL_PATH=./binaries/Image.gz
DOM0_RAMDISK_ADDR=0x90400000
DOM0_RAMDISK_PATH=./binaries/initrd.img
DOM0_BOOTARGS="rw root=/dev/ram console=hvc0 keep_bootcon bootmem_debug debug"

echo "PLATFORM_NAME=\"${PLATFORM_NAME}\"
PLATFORM_CPU_NUM=\"${PLATFORM_PCPU_NUM}\"
PLATFORM_RAM_SIZE=\"${PLATFORM_RAM_SIZE}\"
PLATFORM_XEN_BOOTARGS=\"${PLATFORM_XEN_BOOTARGS}\"
PLATFORM_INTERRUPT_CONTROLLER=\"plic\"
PLATFORM_DOM0LESS=false

DOM0_KERNEL_ADDR=\"${DOM0_KERNEL_ADDR}\"
DOM0_KERNEL_PATH=\"${DOM0_KERNEL_PATH}\"
DOM0_RAMDISK_ADDR=\"${DOM0_RAMDISK_ADDR}\"
DOM0_RAMDISK_PATH=\"${DOM0_RAMDISK_PATH}\"
DOM0_BOOTARGS=\"${DOM0_BOOTARGS}\"" > "${CONFIG_FILE}"

# Arrays to store parsed data
declare -A PLATFORM_DATA
declare -A DOMU_DATA
declare -A DOM0_DATA

get_kernel_node() {
    local kernel_la="${1}"
    local kernel_path="${2}"
    local bootargs="${3}"

    local kernel_size=""

    if [ -f "$kernel_path" ]; then
        kernel_size=$(stat -c %s "$kernel_path")
        kernel_size_hex=$(printf "0x%x" "$kernel_size")
    else
        echo "Error: kernel path [$kernel_path] is wrong"
        exit 1
    fi

    local kernel_module_block="
        module@$kernel_la {
            compatible = \"multiboot,kernel\", \"multiboot,module\";
            reg = <$kernel_la $kernel_size_hex>;
            bootargs = \"$bootargs\";
        };
    "
    echo "$kernel_module_block"
}

get_ramdisk_node() {
    local ramdisk_la="${1}"
    local ramdisk_path="${2}"

    local ramdisk_size=""

    if [ -f "$ramdisk_path" ]; then
        ramdisk_size=$(stat -c %s "$ramdisk_path")
        ramdisk_size_hex=$(printf "0x%x" "$ramdisk_size")
    else
        echo "Error: ramdisk path [$ramdisk_path] is wrong"
        exit 1
    fi

    local ramdisk_module_node="
        module@$ramdisk_la {
            compatible = \"multiboot,ramdisk\", \"multiboot,module\";
            reg = <$ramdisk_la $ramdisk_size_hex>;
        };
    "
    echo "$ramdisk_module_node"
}

get_dom0_val() {
    local key=$1

    echo "${DOM0_DATA[$key]}"
}

get_domu_val() {
    local dom_id=$1
    local key=$2

    echo "${DOMU_DATA[$dom_id,$key]}"
}

get_platform_val() {
    local key=$1

    echo "${PLATFORM_DATA[$key]}"
}

generate_domu()
{
    local dom_id=$1

    local is_vsbi_uart=$(get_domu_val "$dom_id" "VSBI_UART")
    local cpus=$(get_domu_val "$dom_id" "CPUS_NUM")
    local kernel_la=$(get_domu_val "$dom_id" "KERNEL_ADDR")
    local kernel_path=$(get_domu_val "$dom_id" "KERNEL_PATH")
    local kernel_bootargs=$(get_domu_val "$dom_id" "BOOTARGS")
    local ramdisk_la=$(get_domu_val "$dom_id" "RAMDISK_ADDR")
    local ramdisk_path=$(get_domu_val "$dom_id" "RAMDISK_PATH")
    local vsbi_uart_val=""

    if [ "$is_vsbi_uart" == "true" ]; then
        vsbi_uart_val="vsbi_uart;"
    fi

    if [ -z "$kernel_la" ] || [ -z "$kernel_path" ]; then
        echo "Please specify both kernel load address and path"
        exit 1
    fi

    local kernel_module_node=$(get_kernel_node  "$kernel_la" \
                                                "$kernel_path" \
                                                "$kernel_bootargs")

    if [ -z "$ramdisk_la" ] || [ -z "$ramdisk_path" ]; then
        echo "Please specify both ramdisk load address and path"
        exit 1
    fi

    local ramdisk_module_node=$(get_ramdisk_node "$ramdisk_la" "$ramdisk_path")

    local guest_node=$(cat <<EOF
    ${dom_id} {
        #address-cells = <1>;
        #size-cells = <1>;
        compatible = "xen,domain";
        memory = <0 0x40000>;
        cpus = <${cpus}>;
        ${vsbi_uart_val}

        ${kernel_module_node}

        ${ramdisk_module_node}
    };
EOF
)

    echo "$guest_node"
}

remove_unsupported_nodes() {
    local dts_name="$1.dts"

    # Virtio and PCI isn't supported now
    awk '/virtio[^;]*{|pci[^;]*{/ {f=1} f && /};/ {f=0; next} !f' ${dts_name} > ${dts_name}_ && mv ${dts_name}_ ${dts_name}
}

generate_base_dts() {
    local platform_name=$(get_platform_val NAME)
    local platform_cpu_num=$(get_platform_val CPU_NUM)
    local platform_ram_size=$(get_platform_val RAM_SIZE)
    local platform_interrupt_controller=$(get_platform_val INTERRUPT_CONTROLLER)
    local dts_name="./binaries/qemu"
    local xen_boot_args=$(get_platform_val XEN_BOOTARGS)

    case $platform_name in
        qemu-virt)
            ${QEMU} -M virt -smp $platform_cpu_num -nographic \
                    -bios ${FW_PATH} \
                    -append "${xen_boot_args}" -kernel ${XEN} \
                    -m $platform_ram_size -machine dumpdtb=$dts_name.dtb
            dtc -I dtb ${dts_name}.dtb > "${dts_name}.dts"
            remove_unsupported_nodes ${dts_name}
            rm $dts_name.dtb
            ;;
        dom0-qemu-virt)
            local kernel_path=$(get_dom0_val KERNEL_PATH)
            local kernel_addr=$(get_dom0_val KERNEL_ADDR)
            local ramdisk_path=$(get_dom0_val RAMDISK_PATH)
            local ramdisk_addr=$(get_dom0_val RAMDISK_ADDR)
            local boot_args=$(get_dom0_val BOOTARGS)

            "${QEMU}" -M virt -smp "${platform_cpu_num}" -nographic \
                      -bios ${FW_PATH} \
                      -m "${platform_ram_size}" \
                      -device "guest-loader,kernel=${kernel_path},addr=${kernel_addr},bootargs=${boot_args}" \
                      -device "guest-loader,initrd=${ramdisk_path},addr=${ramdisk_addr}" \
                      -append "${xen_boot_args}" -kernel ${XEN} \
                      -machine dumpdtb=${dts_name}.dtb
            dtc -I dtb ${dts_name}.dtb > "${dts_name}.dts"
            remove_unsupported_nodes ${dts_name}
            rm $dts_name.dtb
            ;;
        *)
            echo "Add dtb generation command for $platform_name"
            exit 1
            ;;
    esac

    echo "$dts_name.dts"
}

generate_dtb() {
    local is_dom0less=$(get_platform_val DOM0LESS)

    dts_name=$(generate_base_dts)

    if [ "$is_dom0less" == "true" ]; then
        local domu_node

        # in case of dom0less Xen expects to have 'xen,xen-bootargs'
        # instead of bootargs
        sed -i 's/\bbootargs\b/xen,xen-bootargs/g' ${dts_name}
        
        local guest_amount=$(get_platform_val GUEST_DOM_NUM)
        for ((i=1; i<=${guest_amount}; i++)); do
            domu_node+=$(generate_domu "DOMU${i}")
            domu_node+="\n"
        done

        # Capture the modified content in a variable
        modified_chosen_node=$(awk -v chosen_node="$domu_node" '/chosen {/,/};/ {if (/};/) print "\t\t" chosen_node "\n\t};"; else print $0}' "$dts_name")

        # remove the last }; in the file, it will be added with ${modified_chosen_node}
        sed -i '$s/};//' "$dts_name"

        # remove current chosen node
        sed -i '/chosen {/,/};/d' "$dts_name"

        # write updated chosen node to dts
        echo -e "${modified_chosen_node}\n};" >> "$dts_name"
    # else
    #     dom0_node=$(generate_dom0)

    #     new_chosen_node_content+=$dom0_node
    fi

    # generate dtb
    dtb_name=./binaries/$(get_platform_val NAME).dtb

    dtc -O dtb -o $dtb_name $dts_name 
}

check_and_set_platform_data_default() {
    local key_to_check="$1"
    local default_value="$2"

    if [[ ! -v "PLATFORM_DATA[$key_to_check]" ]]; then
        # Key does not exist, set the default value
        PLATFORM_DATA[$key_to_check]="$default_value"
    fi
}

# Function to process PLATFORM data
process_platform_data() {
    echo "Processing PLATFORM data:"

    check_and_set_platform_data_default "NAME" "qemu-virt"
    check_and_set_platform_data_default "RAM_SIZE" "4g"
    check_and_set_platform_data_default "CPU_NUM" "1"
    check_and_set_platform_data_default "XEN_BOOTARGS" ""
    check_and_set_platform_data_default "INTERRUPT_CONTROLLER" "plic"
    check_and_set_platform_data_default "GUEST_DOM_NUM" "plic"
    check_and_set_platform_data_default "DOM0LESS" "true"

    for key in "${!PLATFORM_DATA[@]}"; do
        value="${PLATFORM_DATA[$key]}"
        echo "$key: $value"
        # Add your actions here
    done

    echo "PLATFORM data processing complete."
}

check_and_set_domu_data_default() {
    local domu_num=$1
    local key_to_check="$2"
    local default_value="$3"

    if [[ ! -v "DOMU_DATA[$domu_num,$key_to_check]" ]]; then
        # Key does not exist, set the default value
        DOMU_DATA[$domu_num,$key_to_check]="$default_value"
        echo "@@@@ $key_to_check"
    fi
}

check_and_failure_domu_data() {
    local domu_num=$1
    local key_to_check="$2"

    if [[ ! -v "DOMU_DATA[$domu_num,$key_to_check]" ]]; then
        echo "${domu_num} [${key_to_check}] should be set!"
        exit 1
    fi
}

check_and_set_dom0_data_default() {
    local key_to_check="$1"
    local default_value="$2"

    if [[ ! -v "DOM0_DATA[$key_to_check]" ]]; then
        # Key does not exist, set the default value
        DOM0_DATA[$key_to_check]="$default_value"
    fi
}

check_and_failure_dom0_data() {
    local key_to_check="$1"

    if [[ ! -v "DOM0_DATA[$key_to_check]" ]]; then
        echo "$key_to_check should be set!"
        exit 1
    fi
}

process_dom0_data() {
        check_and_failure_dom0_data KERNEL_ADDR
        check_and_failure_dom0_data KERNEL_PATH
        check_and_failure_dom0_data RAMDISK_ADDR
        check_and_failure_dom0_data RAMDISK_PATH
        check_and_set_dom0_data_default BOOTARGS ""
}

# Function to process DOMU data
process_domu_data() {
    local platform_guest_dom_num=PLATFORM_DATA["GUEST_DOM_NUM"]

    for ((i=1; i<=$platform_guest_dom_num; i++)); do
        check_and_set_domu_data_default "DOMU$i" VSBI_UART false
        check_and_set_domu_data_default "DOMU$i" CPUS_NUM 1
        check_and_set_domu_data_default "DOMU$i" BOOTARGS ""

        check_and_failure_domu_data "DOMU$i" KERNEL_ADDR
        check_and_failure_domu_data "DOMU$i" KERNEL_PATH
        check_and_failure_domu_data "DOMU$i" RAMDISK_ADDR
        check_and_failure_domu_data "DOMU$i" RAMDISK_PATH
    done

    # Iterate over the associative array
    for key in "${!DOMU_DATA[@]}"; do
        value="${DOMU_DATA[$key]}"
        echo "Key: $key, Value: $value"
    done
}

# Function to parse the configuration file
parse_config_file() {
    # Read the configuration file line by line
    while IFS= read -r line; do
        # Ignore comments and empty lines
        if [[ $line =~ ^\s*# || -z $line ]]; then
            continue
        fi

        # Split the line into key and value
        key=$(echo "$line" | cut -d '=' -f 1)
        value=$(echo "$line" | cut -d '=' -f 2-)

        # Trim leading and trailing whitespace from the key and value
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)

        prefix="${key%%_*}"
        rest="${key#*_}"

        echo "@@@ $rest"

        case "$key" in
            PLATFORM*)
                PLATFORM_DATA["$rest"]=$value
                ;;
            DOMU*)
                DOMU_DATA["$prefix","$rest"]=$value
                ;;
            DOM0*)
                echo "${rest}=${value}"
                DOM0_DATA["$rest"]=$value
                ;;
            # Add more cases for other sections as needed
        esac
    done < "$CONFIG_FILE"

    # Perform actions for each section
    process_platform_data
    
    local is_dom0less=$(get_platform_val DOM0LESS)

    if [ "${is_dom0less}" == "true" ]; then
        process_domu_data
    else
        process_dom0_data
    fi
}

parse_config_file
generate_dtb

timeout -k 1 40 \
${QEMU} -M virt \
        -bios ${FW_PATH} \
        -smp ${PLATFORM_PCPU_NUM} \
        -nographic \
        -m ${PLATFORM_RAM_SIZE} \
        -kernel ${XEN} \
        -device "loader,file=${DOM0_KERNEL_PATH},addr=${DOM0_KERNEL_ADDR}" \
        -device "loader,file=${DOM0_RAMDISK_PATH},addr=${DOM0_RAMDISK_ADDR}" \
        -dtb ./binaries/${PLATFORM_NAME}.dtb \
        |& tee smoke.serial

rm ${CONFIG_FILE}

set -e
(grep -q "Hello RISC-V World!" smoke.serial) || exit 1
exit 0
