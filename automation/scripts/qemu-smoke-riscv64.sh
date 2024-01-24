#!/bin/bash

set -ex

# Run the test
rm -f smoke.serial
set +e

BUILDDIR=./binaries
FW_PATH=${BUILDDIR}/opensbi-riscv64-generic-fw_dynamic.bin
QEMU=${BUILDDIR}/qemu-system-riscv64
XEN=${BUILDDIR}/xen

TEST_CASE=$1

# Arrays to store parsed data
declare -A PLATFORM_DATA
declare -A DOMU_DATA
declare -A DOM0_DATA

# guest_domain_num=0

get_kernel_node() {
    local kernel_la="${1}"
    local kernel_path="${2}"
    local bootargs="${3}"

    local kernel_size=""

    if [ -f "$kernel_path" ]; then
        kernel_size=$(stat -c %s "$kernel_path")
        kernel_size_hex=$(printf "0x%x" "$kernel_size")
        # echo "File size of $kernel_path: $kernel_size bytes"
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
        # echo "File size of $ramdisk_path: $ramdisk_size bytes"
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

generate_qemu_pfdt_flags()
{
    local platform_guest_dom_num=PLATFORM_DATA["GUEST_DOM_NUM"]
    local qemu_pfdt_flags=""

    for ((i=1; i<=$platform_guest_dom_num; i++)); do
    local pfdt_path=$(get_domu_val "DOMU$i" "PFDT_PATH")
    local pfdt_addr=$(get_domu_val "DOMU$i" "PFDT_ADDR")

    # echo "[$pfdt_path] [$pfdt_addr]"

    if [ "$pfdt_addr" != "0x0" ]; then
        pfdt_path="${pfdt_path%?}b"
        qemu_pfdt_flags+="-device loader,file=$pfdt_path,addr=$pfdt_addr "
    fi
     done

    echo "$qemu_pfdt_flags"
}

generate_pfdt_node()
{
    local dom_id=$1

    local pfdt_dtb_addr=$(get_domu_val "$dom_id" "PFDT_ADDR")
    local pfdt_dts_path=$(get_domu_val "$dom_id" "PFDT_PATH")

    if [ -f "$pfdt_dts_path" ]; then
        local pfdt_dtb_path=${pfdt_dts_path%?}b
        local pfdt_dtb_name=$(basename "$pfdt_dtb_path")

        dtc -O dtb -o ${BUILDDIR}/$pfdt_dtb_name $pfdt_dts_path

        pfdt_dtb_size=$(stat -c %s "${BUILDDIR}/$pfdt_dtb_name")
        pfdt_dtb_size_hex=$(printf "0x%x" "$pfdt_dtb_size")
    else
        echo ""
        return 0
    fi

    local pfdt_node="
        module@$pfdt_dtb_addr {
            compatible = \"multiboot,device-tree\", \"multiboot,module\";
            reg = <$pfdt_dtb_addr $pfdt_dtb_size_hex>;
        };
        "

    echo "$pfdt_node"
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

    local pfdt_node=$(generate_pfdt_node "$dom_id")

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

        ${pfdt_node}
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
    local dts_name="qemu"
    local xen_boot_args=$(get_platform_val XEN_BOOTARGS)

    local ic_flags=""
    case $platform_interrupt_controller in
        aplic-imsic)
            ic_flags=",aclint=off,aia=aplic-imsic,aia-guests=7 -cpu rv64,smstateen=on"
            ;;
    esac

    case $platform_name in
        dom0less-qemu-virt)
            ${QEMU} -M virt$ic_flags -smp $platform_cpu_num -nographic \
                    -bios ${FW_PATH} \
                    -append "${xen_boot_args}" -kernel ${XEN} \
                    -m $platform_ram_size -machine dumpdtb=${BUILDDIR}/$dts_name.dtb
            dtc -I dtb ${BUILDDIR}/${dts_name}.dtb > "${BUILDDIR}/${dts_name}.dts"
            remove_unsupported_nodes ${BUILDDIR}/${dts_name}
            rm ${BUILDDIR}/$dts_name.dtb
            ;;
        dom0-qemu-virt)
            local kernel_path=$(get_dom0_val KERNEL_PATH)
            local kernel_addr=$(get_dom0_val KERNEL_ADDR)
            local ramdisk_path=$(get_dom0_val RAMDISK_PATH)
            local ramdisk_addr=$(get_dom0_val RAMDISK_ADDR)
            local boot_args=$(get_dom0_val BOOTARGS)

            "${QEMU}" -M virt$ic_flags -smp "${platform_cpu_num}" -nographic \
                      -bios ${FW_PATH} \
                      -m "${platform_ram_size}" \
                      -device "guest-loader,kernel=${kernel_path},addr=${kernel_addr},bootargs=${boot_args}" \
                      -device "guest-loader,initrd=${ramdisk_path},addr=${ramdisk_addr}" \
                      -append "${xen_boot_args}" -kernel ${XEN} \
                      -machine dumpdtb=${BUILDDIR}/${dts_name}.dtb
            dtc -I dtb ${BUILDDIR}/${dts_name}.dtb > "${BUILDDIR}/${dts_name}.dts"
            remove_unsupported_nodes ${BUILDDIR}/${dts_name}
            rm ${BUILDDIR}/$dts_name.dtb
            ;;
        *)
            echo "Add dtb generation command for $platform_name"
            exit 1
            ;;
    esac

    echo "${BUILDDIR}/$dts_name.dts"
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
    dtb_name="$(get_platform_val NAME)".dtb

    dtc -O dtb -o ${BUILDDIR}/${dtb_name} $dts_name
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
    # echo $platform_guest_dom_num

    # platform_guest_dom_num=$((platform_guest_dom_num))

    echo "process_domu_data"

    for ((i=1; i<=$platform_guest_dom_num; i++)); do
        check_and_set_domu_data_default "DOMU$i" VSBI_UART false
        check_and_set_domu_data_default "DOMU$i" CPUS_NUM 1
        check_and_set_domu_data_default "DOMU$i" BOOTARGS ""
        check_and_set_domu_data_default "DOMU$i" PFDT_PATH ""
        check_and_set_domu_data_default "DOMU$i" PFDT_ADDR 0x0

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

case "${TEST_CASE}" in
    "dom0-test" | "dom0-smp-test")
        if [ "$TEST_CASE" = "dom0-smp-test" ]; then
            PLATFORM_PCPU_NUM=4
        elif [ "$TEST_CASE" = "dom0-test" ]; then
            PLATFORM_PCPU_NUM=1
        fi

        CONFIG_FILE="dom0.conf"
        PLATFORM_NAME=dom0-qemu-virt
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
        ;;
    "dom0less-4smp-1vcpu-test")
        PLATFORM_PCPU_NUM=4

        CONFIG_FILE="dom0less.conf"
        PLATFORM_NAME=dom0less-qemu-virt
        PLATFORM_RAM_SIZE=2g
        DOMU1_KERNEL_ADDR=0x808ef000
        DOMU1_KERNEL_PATH=./binaries/Image.gz
        DOMU1_RAMDISK_ADDR=0x90400000
        DOMU1_RAMDISK_PATH=./binaries/initrd.img
        DOMU2_KERNEL_ADDR=0xa0000000
        DOMU2_KERNEL_PATH=./binaries/Image.gz
        DOMU2_RAMDISK_ADDR=0xb0000000
        DOMU2_RAMDISK_PATH=./binaries/initrd.img

        echo "PLATFORM_NAME=\"${PLATFORM_NAME}\"
        PLATFORM_CPU_NUM=\"${PLATFORM_PCPU_NUM}\"
        PLATFORM_RAM_SIZE=\"${PLATFORM_RAM_SIZE}\"
        PLATFORM_XEN_BOOTARGS=com1=poll sched=null
        PLATFORM_INTERRUPT_CONTROLLER=plic
        PLATFORM_GUEST_DOM_NUM=2
        PLATFORM_DOM0LESS=true

        DOMU1_KERNEL_ADDR=\"${DOMU1_KERNEL_ADDR}\"
        DOMU1_KERNEL_PATH=\"${DOMU1_KERNEL_PATH}\"
        DOMU1_VSBI_UART=true
        DOMU1_RAMDISK_ADDR=\"${DOMU1_RAMDISK_ADDR}\"
        DOMU1_RAMDISK_PATH=\"${DOMU1_RAMDISK_PATH}\"
        DOMU1_CPUS_NUM=1
        DOMU1_BOOTARGS=\"console=hvc0\"

        DOMU2_KERNEL_ADDR=\"${DOMU2_KERNEL_ADDR}\"
        DOMU2_KERNEL_PATH=\"${DOMU2_KERNEL_PATH}\"
        DOMU2_VSBI_UART=true
        DOMU2_RAMDISK_ADDR=\"${DOMU2_RAMDISK_ADDR}\"
        DOMU1_RAMDISK_PATH=\"${DOMU2_RAMDISK_PATH}\"
        DOMU2_RAMDISK_PATH=./binaries/initrd.img
        DOMU2_CPUS_NUM=1
        DOMU2_BOOTARGS=\"console=hvc0\"" > "${CONFIG_FILE}"
        ;;
    *)
        echo "Invalid option: $value"
        # Handle invalid options
        exit 1
        ;;
esac

cat "${CONFIG_FILE}"

parse_config_file
generate_dtb

pfdt_qemu_flags=$(generate_qemu_pfdt_flags)
echo "FLAGS: $pfdt_qemu_flags"

case "${TEST_CASE}" in
    "dom0-test" | "dom0-smp-test")
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

        set -e
        (grep -q "Hello RISC-V World!" smoke.serial) || exit 1
        ;;
    "dom0less-4smp-1vcpu-test")
        timeout -k 1 40 \
        ${QEMU} -M virt \
                -bios ${FW_PATH} \
                -smp ${PLATFORM_PCPU_NUM} \
                -nographic \
                -m ${PLATFORM_RAM_SIZE} \
                -kernel ${XEN} \
                -device "loader,file=${DOMU1_KERNEL_PATH},addr=${DOMU1_KERNEL_ADDR}" \
                -device "loader,file=${DOMU1_RAMDISK_PATH},addr=${DOMU1_RAMDISK_ADDR}" \
                -device "loader,file=${DOMU2_KERNEL_PATH},addr=${DOMU2_KERNEL_ADDR}" \
                -device "loader,file=${DOMU2_RAMDISK_PATH},addr=${DOMU2_RAMDISK_ADDR}" \
                -dtb ./binaries/${PLATFORM_NAME}.dtb \
                |& tee smoke.serial
        set -e
        [[ $(grep -c "Hello RISC-V World!" smoke.serial) -eq 2 ]] || exit 1
        ;;
    *)
        echo "Invalid option: ${TEST_CASE}"
        exit 1
        ;;
esac

rm ${CONFIG_FILE}

exit 0
