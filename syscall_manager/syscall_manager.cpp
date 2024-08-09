#include "syscall_manager.h"
#include <stdexcept>
#include <algorithm>
#include <thread>
#include <bitset>
#include <intrin.h>

#undef max

syscall_manager::syscall_manager()
    : rng_(std::random_device{}()),
    delay_dist_(1, 100), // Delay between 1 and 100 milliseconds
    encryption_key_dist_(0, std::numeric_limits<uint64_t>::max()),
    encryption_key_(encryption_key_dist_(rng_))
{
}

syscall_manager::~syscall_manager() {
    for (const auto& [_, module] : loaded_modules_) {
        FreeLibrary(module);
    }
}

syscall_manager& syscall_manager::instance() {
    static syscall_manager instance;
    return instance;
}

void syscall_manager::initialize() {
    randomize_module_load_order();
}

void syscall_manager::load_module(const std::string& module_name) {
    HMODULE module = LoadLibraryA(module_name.c_str());
    if (module) {
        loaded_modules_[module_name] = module;
    }
    else {
        throw std::runtime_error("[syscall_manager] failed to load module: " + module_name);
    }
}

void* syscall_manager::get_syscall_address(const std::string& module, const std::string& function_name) {
    if (auto it = loaded_modules_.find(module); it != loaded_modules_.end()) {
        FARPROC addr = GetProcAddress(it->second, function_name.c_str());
        if (addr) {
            return reinterpret_cast<void*>(addr);
        }
    }
    return nullptr;
}

void* syscall_manager::obfuscate_syscall(void* original_addr) {
    // Obfuscation using bitset
    std::bitset<sizeof(uintptr_t) * 8> bits(reinterpret_cast<uintptr_t>(original_addr));
    bits.flip(); // Invert all bits
    return reinterpret_cast<void*>(bits.to_ullong());
}

void syscall_manager::delay_execution() {
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_dist_(rng_)));
}

void* syscall_manager::encrypt_pointer(void* ptr) {
    uintptr_t value = reinterpret_cast<uintptr_t>(ptr);
    return reinterpret_cast<void*>(value ^ encryption_key_);
}

void* syscall_manager::decrypt_pointer(void* encrypted_ptr) {
    uintptr_t value = reinterpret_cast<uintptr_t>(encrypted_ptr);
    return reinterpret_cast<void*>(value ^ encryption_key_);
}

void syscall_manager::randomize_module_load_order() {
    std::vector<std::string> modules = { "ntdll.dll", "kernel32.dll", "user32.dll", "win32u.dll" };
    std::shuffle(modules.begin(), modules.end(), rng_);
    for (const auto& module : modules) {
        load_module(module);
    }
}

void syscall_manager::dynamic_obfuscation() {
    encryption_key_ = encryption_key_dist_(rng_);
}

DWORD syscall_manager::get_syscall_number(const std::string& module, const std::string& function_name) {
    std::string key = module + "::" + function_name;

    {
        std::shared_lock lock(syscall_mutex_);
        if (auto it = syscall_numbers_.find(key); it != syscall_numbers_.end()) {
            return it->second;
        }
    }

    HMODULE hModule = GetModuleHandleA(module.c_str());
    if (!hModule) {
        return 0;
    }

    FARPROC proc = GetProcAddress(hModule, function_name.c_str());
    if (!proc) {
        return 0;
    }

    BYTE* func = reinterpret_cast<BYTE*>(proc);

    // Search for the syscall instruction
    for (int i = 0; i < 50; ++i) {
        if (func[i] == 0x0F && func[i + 1] == 0x05) {  // syscall instruction
            // Search backwards for the mov eax instruction
            for (int j = i - 1; j >= 0; --j) {
                if (func[j] == 0xB8) {  // mov eax, imm32
                    DWORD syscall_number = *reinterpret_cast<DWORD*>(&func[j + 1]);
                    {
                        std::unique_lock lock(syscall_mutex_);
                        syscall_numbers_[key] = syscall_number;
                    }
                    return syscall_number;
                }
            }
            break;
        }
    }

    return 0;
}
