#include "syscall_manager.h"
#include <iostream>
#include <Windows.h>
#include <winternl.h>

int main() {
    try {
        syscall_manager::instance().initialize();

        // Example of indirect syscall (MessageBoxA)
        using MessageBoxA_t = int (WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
        auto MessageBoxA = syscall_manager::instance().get_indirect_syscall<MessageBoxA_t>("user32.dll", "MessageBoxA");

        if (MessageBoxA) {
            (*MessageBoxA)(NULL, "Hello, World! (Indirect)", "Syscall Manager", MB_OK);
        }
        else {
            std::cerr << "Failed to get MessageBoxA syscall" << std::endl;
        }

        // Example of direct syscall (NtQuerySystemInformation)
        auto NtQuerySystemInformation = syscall_manager::instance().get_direct_syscall<NTSTATUS, SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG>("ntdll.dll", "NtQuerySystemInformation");

        if (NtQuerySystemInformation) {
            SYSTEM_BASIC_INFORMATION sbi;
            ULONG returnLength = 0;

            std::cout << "Syscall number for NtQuerySystemInformation: 0x"
                << std::hex << std::setw(4) << std::setfill('0')
                << syscall_manager::instance().get_last_syscall_number() << std::endl;

            NTSTATUS status = (*NtQuerySystemInformation)(SystemBasicInformation, &sbi, sizeof(sbi), &returnLength);

            std::cout << "NtQuerySystemInformation called. Status: 0x"
                << std::hex << std::setw(8) << std::setfill('0') << status << std::endl;

            if (status == 0) { 
                std::cout << "Number of processors (Direct syscall): " << std::to_string(sbi.NumberOfProcessors) << std::endl;
            }
            else {
                std::cerr << "Failed to query system information, NTSTATUS: 0x"
                    << std::hex << std::setw(8) << std::setfill('0') << status << std::endl;
            }
        }
        else {
            std::cerr << "Failed to get NtQuerySystemInformation syscall" << std::endl;
        }

        system("pause");
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}