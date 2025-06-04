#!/bin/bash

# PintOS Environment Setup Automation Script
# This script automates the setup process for PintOS from sections B to E
# Author: Generated for Operating System Project 1

# Uncomment the line below for debugging
# set -x

# Exit on any error (comment out for debugging)
# set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to detect PintOS base path
detect_pintos_path() {
    print_status "Detecting PintOS base path..."

    # Common locations to check for PintOS
    POSSIBLE_PATHS=(
        "$HOME/pintos"
        "$HOME/PintOS"
        "$HOME/Downloads/pintos"
        "$(pwd)/pintos"
    )

    # Add find result if it exists
    FIND_RESULT=$(find $HOME -maxdepth 3 -name "pintos" -type d 2>/dev/null | head -1)
    if [[ -n "$FIND_RESULT" ]]; then
        POSSIBLE_PATHS+=("$FIND_RESULT")
    fi

    print_status "Checking possible locations..."
    for path in "${POSSIBLE_PATHS[@]}"; do
        print_status "Checking: $path"
        if [[ -n "$path" && -d "$path" && -d "$path/src" ]]; then
            PINTOS_BASE_PATH="$path"
            print_success "Found PintOS at: $PINTOS_BASE_PATH"
            return 0
        fi
    done

    # If not found, prompt user
    print_warning "PintOS directory not found automatically."
    echo "Please enter the full path to your PintOS directory:"
    read -r user_path

    if [[ -d "$user_path" && -d "$user_path/src" ]]; then
        PINTOS_BASE_PATH="$user_path"
        print_success "Using user-specified path: $PINTOS_BASE_PATH"
    else
        print_error "Invalid PintOS path. Please ensure the directory exists and contains 'src' subdirectory."
        print_error "You entered: $user_path"
        return 1
    fi
}

# Section B: Environment Settings (PATH setting)
setup_path_environment() {
    print_status "Setting up PATH environment..."

    # Check if PATH is already set
    if grep -q "$PINTOS_BASE_PATH/src/utils" "$HOME/.bashrc"; then
        print_warning "PATH already contains PintOS utils directory"
    else
        # Add PATH to .bashrc
        echo "" >> "$HOME/.bashrc"
        echo "# PintOS PATH setting - Added by setup script" >> "$HOME/.bashrc"
        echo "export PATH=\"\$PATH:$PINTOS_BASE_PATH/src/utils\"" >> "$HOME/.bashrc"
        print_success "Added PintOS utils to PATH in .bashrc"
    fi

    # Source .bashrc to apply changes
    export PATH="$PATH:$PINTOS_BASE_PATH/src/utils"
    print_success "PATH environment updated for current session"
}

# Section C: Environment Settings (PintOS setting)
setup_pintos_paths() {
    print_status "Configuring PintOS file paths..."

    # Update pintos file - line 259
    PINTOS_FILE="$PINTOS_BASE_PATH/src/utils/pintos"
    if [[ -f "$PINTOS_FILE" ]]; then
        # Find and replace kernel.bin path around line 259
        sed -i "s|/[^/]*/[^/]*/pintos/src/[^/]*/build/kernel.bin|$PINTOS_BASE_PATH/src/threads/build/kernel.bin|g" "$PINTOS_FILE"
        print_success "Updated kernel.bin path in pintos file"
    else
        print_error "pintos file not found at $PINTOS_FILE"
        exit 1
    fi

    # Update Pintos.pm file - line 362
    PINTOS_PM_FILE="$PINTOS_BASE_PATH/src/utils/Pintos.pm"
    if [[ -f "$PINTOS_PM_FILE" ]]; then
        # Find and replace loader.bin path around line 362
        sed -i "s|/[^/]*/[^/]*/pintos/src/[^/]*/build/loader.bin|$PINTOS_BASE_PATH/src/threads/build/loader.bin|g" "$PINTOS_PM_FILE"
        print_success "Updated loader.bin path in Pintos.pm file"
    else
        print_error "Pintos.pm file not found at $PINTOS_PM_FILE"
        exit 1
    fi
}

setup_pintos_userprog_paths(){
    print_status "Configuring PintOS file pahts..."

    PINTOS_FILE="$PINTOS_BASE_PATH/src/utils/pintos"
     if [[ -f "$PINTOS_FILE" ]]; then
         # Find and replace kernel.bin path around line 259
         sed -i "s|/[^/]*/[^/]*/pintos/src/[^/]*/build/kernel.bin|$PINTOS_BASE_PATH/src/userprog/build/kernel.bin|g" "$PINTOS_FILE"
         print_success "Updated kernel.bin path in pintos file"
     else
         print_error "pintos file not found at $PINTOS_FILE"
         exit 1
     fi

     # Update Pintos.pm file - line 362
     PINTOS_PM_FILE="$PINTOS_BASE_PATH/src/utils/Pintos.pm"
     if [[ -f "$PINTOS_PM_FILE" ]]; then
         # Find and replace loader.bin path around line 362
         sed -i "s|/[^/]*/[^/]*/pintos/src/[^/]*/build/loader.bin|$PINTOS_BASE_PATH/src/userprog/build/loader.bin|g" "$PINTOS_PM_FILE"
         print_success "Updated loader.bin path in Pintos.pm file"
     else
         print_error "Pintos.pm file not found at $PINTOS_PM_FILE"
         exit 1
     fi
}

# Section D: Environment Settings (PintOS emulator setting for qemu)
setup_qemu_environment() {
    print_status "Configuring QEMU emulator settings..."

    # Update pintos-gdb file
    PINTOS_GDB_FILE="$PINTOS_BASE_PATH/src/utils/pintos-gdb"
    if [[ -f "$PINTOS_GDB_FILE" ]]; then
        # Update GDBMACROS path
        sed -i "s|GDBMACROS=.*|GDBMACROS=$PINTOS_BASE_PATH/src/misc/gdb-macros|g" "$PINTOS_GDB_FILE"
        print_success "Updated GDBMACROS path in pintos-gdb"
    else
        print_error "pintos-gdb file not found at $PINTOS_GDB_FILE"
        exit 1
    fi

    # Compile utils
    print_status "Compiling utils..."
    cd "$PINTOS_BASE_PATH/src/utils"
    if make; then
        print_success "Utils compilation completed"
    else
        print_warning "Utils compilation had issues, continuing..."
    fi

    # Update utils Makefile (LDFLAGS to LDLIBS)
    UTILS_MAKEFILE="$PINTOS_BASE_PATH/src/utils/Makefile"
    if [[ -f "$UTILS_MAKEFILE" ]]; then
        sed -i 's/LDFLAGS = -lm/LDLIBS = -lm/g' "$UTILS_MAKEFILE"
        print_success "Updated LDFLAGS to LDLIBS in utils Makefile"
    fi

    # Update Make.vars in threads directory (--bochs to --qemu)
    MAKE_VARS_FILE="$PINTOS_BASE_PATH/src/threads/Make.vars"
    if [[ -f "$MAKE_VARS_FILE" ]]; then
        sed -i 's/--bochs/--qemu/g' "$MAKE_VARS_FILE"
        print_success "Updated simulator from bochs to qemu in Make.vars"
    else
        print_error "Make.vars file not found at $MAKE_VARS_FILE"
        exit 1
    fi

    # Update pintos file for qemu settings
    PINTOS_FILE="$PINTOS_BASE_PATH/src/utils/pintos"
    # Line 103: Change $sim = "bochs" to $sim = "qemu"
    sed -i 's/\$sim = "bochs"/\$sim = "qemu"/g' "$PINTOS_FILE"
    # Line 623: Change qemu to qemu-system-i386
    sed -i "s/my (@cmd) = ('qemu')/my (@cmd) = ('qemu-system-i386')/g" "$PINTOS_FILE"
    print_success "Updated QEMU settings in pintos file"
}

build_pintos_threads(){
    # Build pintos for the project
    print_status "Building PintOS threads kernel..."
    cd "$PINTOS_BASE_PATH/src/threads"

    # Clean and make
    if make clean && make; then
        print_success "PintOS threads kernel build completed successfully"
    else
        print_error "PintOS threads build failed"
        exit 1
    fi
}

build_pintos_userprog(){
    # Build pintos for the project
    print_status "Building PintOS userprog kernel..."
    cd "$PINTOS_BASE_PATH/src/userprog"

    # Clean and make
    if make clean && make; then
        print_success "PintOS userprog kernel build completed successfully"
    else
        print_error "PintOS userprog build failed"
        exit 1
    fi
}

test_pintos_HW1() {
    print_status "Testing PintOS thread installation..."

    cd "$PINTOS_BASE_PATH/src/thread"

    print_status "Running alarm-multiple test..."
    if timeout 30 pintos -q run alarm-multiple; then
        print_success "PintOS test completed successfully"
    else
        print_warning "Test may have timed out or failed, but this is normal for initial setup"
    fi
}

# Section E: Test pintos
test_pintos_HW3() {
    print_status "Testing PintOS userprog installation..."

    cd "$PINTOS_BASE_PATH/src/userprog"

    print_status "Running args-multiple test..."
    if timeout 30 make check; then
        print_success "PintOS test completed successfully"
    else
        print_warning "Test may have timed out or failed, but this is normal for initial setup"
    fi
}

# Main execution
main() {
    echo "=================================================="
    echo "PintOS Environment Setup Automation Script"
    echo "=================================================="

    # Check if running on Ubuntu/Linux
    if [[ ! -f /etc/os-release ]]; then
        print_error "This script is designed for Linux systems"
        return 1
    fi

    # Detect PintOS path
    if ! detect_pintos_path; then
        print_error "Failed to detect PintOS path. Exiting."
        return 1
    fi
    
    echo "select HW1 or HW3: "
    read -p "Choice(1/3): " hw_choice

    if [[ "$hw_choice" != "HW1" && "$hw_choice" != "HW3" ]]; then
        echo "Wrong inputs. Please put valid input '1' or '3'."
        exit 1
    fi

    # Execute setup sections
    echo ""
    echo "Starting automated setup process..."
    echo ""

    if ! setup_path_environment; then
        print_error "Failed to setup PATH environment"
        return 1
    fi
    echo ""

    if ! setup_pintos_paths; then
        print_error "Failed to setup PintOS threads paths"
        return 1
    fi
    echo ""

    if ! setup_qemu_environment; then
        print_error "Failed to setup QEMU environment"
        return 1
    fi
    echo ""

    if ! build_pintos_threads; then
        print_error "Failed to build threads"
        return 1
    fi
    echo ""
    
    if [[ "$hw_choice" == "1" ]]; then
        if ! test_pintos_HW1; then
            print_error "Failed to test PintOS threads tests"
            return 1
            fi
    fi

    if [[ "$hw_choice" == "3" ]]; then
        if ! setup_pintos_userprog_paths; then
            print_error "Failed to setup PintOS userprog paths"
            return 1
        fi
        echo ""

        if ! build_pintos_userprog; then
            print_error "Failed to build userprog"
            return 1
        fi
        echo ""

        if ! test_pintos_HW3; then
            print_warning "Test failed, but setup may still be functional"
        fi
        echo ""
    fi
    print_success "PintOS setup completed!"
    echo ""
    echo "=================================================="
    echo "Setup Summary:"
    echo "- PintOS Base Path: $PINTOS_BASE_PATH"
    echo "- PATH updated in ~/.bashrc"
    echo "- All configuration files updated"
    echo "- QEMU emulator configured"
    echo "- Initial test completed"
    echo "=================================================="
    echo ""
    echo "Next steps:"
    echo "1. Restart your terminal or run: source ~/.bashrc"
    echo "2. Navigate to: cd $PINTOS_BASE_PATH/src/userprog"
    echo "3. Run tests with: pintos -q run "
    echo ""
    echo "Happy coding with PintOS!"

    cd $PINTOS_BASE_PATH

    return 0
}

# Run main function
main "$@"
