# syscall_manager
A lightweight, high-performance C++ library for managing both indirect and direct Windows syscalls.

## Features
- Support for both indirect and direct syscalls
- Dynamic syscall number retrieval
- Obfuscation and encryption of syscall addresses
- Randomized module loading
- Thread-safe design

## Requirements
- Windows 10 or later (tested on Windows 10 22H2 build 19045)
- Visual Studio 2019 or later with C++20 support
- MASM (Microsoft Macro Assembler)

## Installation
1. Clone the repository
2. Open the solution in Visual Studio
3. Make sure to enable 'masm' under Build Customizations and use C++ 20
4. Build the project 

## Usage
```
#include "syscall_manager.h"

int main() {
 syscall_manager::instance().initialize();

 // Example of indirect syscall
 auto MessageBoxA = syscall_manager::instance().get_indirect_syscall<MessageBoxA_t>("user32.dll", "MessageBoxA");
 if (MessageBoxA) {
     (*MessageBoxA)(NULL, "Hello, World!", "Indirect Syscall", MB_OK);
 }

 // Example of direct syscall
 auto NtQuerySystemInformation = syscall_manager::instance().get_direct_syscall<NTSTATUS, SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG>("ntdll.dll", "NtQuerySystemInformation");
 if (NtQuerySystemInformation) {
     // Use NtQuerySystemInformation...
 }

 return 0;
}
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

## Disclaimer
This project is for educational purposes only. Ensure you have appropriate permissions before using this in any production environment. The authors are not responsible for any misuse or damage caused by this software.
