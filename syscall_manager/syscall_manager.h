#ifndef SYSCALL_MANAGER_H
#define SYSCALL_MANAGER_H

#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <functional>
#include <random>
#include <chrono>
#include <span>
#include <Windows.h>
#include <shared_mutex>
#include <optional>
#include <bitset>
#include <iostream>

extern "C" void setup_syscall_number(DWORD syscall_number);
extern "C" void* execute_syscall();

class syscall_manager {
public:
    static syscall_manager& instance();

    syscall_manager(const syscall_manager&) = delete;
    syscall_manager& operator=(const syscall_manager&) = delete;

    template<typename Func>
    std::optional<Func> get_indirect_syscall(const std::string& module, const std::string& function_name);

    template<typename Ret, typename... Args>
    std::optional<Ret(*)(Args...)> get_direct_syscall(const std::string& module, const std::string& function_name);

    DWORD get_last_syscall_number() const { return last_syscall_number_; }

    void initialize();

private:
    syscall_manager();
    ~syscall_manager();

    void load_module(const std::string& module_name);
    void* get_syscall_address(const std::string& module, const std::string& function_name);

    void* obfuscate_syscall(void* original_addr);
    void delay_execution();
    void* encrypt_pointer(void* ptr);
    void* decrypt_pointer(void* encrypted_ptr);
    void randomize_module_load_order();
    void dynamic_obfuscation();

    DWORD get_syscall_number(const std::string& module, const std::string& function_name);
    DWORD last_syscall_number_ = 0;

    template<typename Ret, typename... Args>
    static Ret direct_syscall_trampoline(DWORD syscall_number, Args... args);

    std::unordered_map<std::string, HMODULE> loaded_modules_;
    std::unordered_map<std::string, void*> syscall_cache_;
    std::unordered_map<std::string, DWORD> syscall_numbers_;
    std::mt19937 rng_;
    std::uniform_int_distribution<> delay_dist_;
    std::uniform_int_distribution<uint64_t> encryption_key_dist_;
    uint64_t encryption_key_;
    std::shared_mutex syscall_mutex_;
};

template<typename Func>
std::optional<Func> syscall_manager::get_indirect_syscall(const std::string& module, const std::string& function_name) {
    std::string key = module + "::" + function_name;

    {
        std::shared_lock lock(syscall_mutex_);
        if (auto it = syscall_cache_.find(key); it != syscall_cache_.end()) {
            delay_execution();
            return reinterpret_cast<Func>(decrypt_pointer(it->second));
        }
    }

    void* addr = get_syscall_address(module, function_name);
    if (addr) {
        {
            std::unique_lock lock(syscall_mutex_);
            syscall_cache_[key] = encrypt_pointer(addr);
        }
        delay_execution();
        return reinterpret_cast<Func>(addr);
    }

    return std::nullopt;
}

template<typename Ret, typename... Args>
std::optional<Ret(*)(Args...)> syscall_manager::get_direct_syscall(const std::string& module, const std::string& function_name) {
    DWORD syscall_number = get_syscall_number(module, function_name);
    if (syscall_number == 0) {
        return std::nullopt;
    }

    last_syscall_number_ = syscall_number;

    static DWORD captured_syscall_number = syscall_number;
    static Ret(*function_pointer)(Args...) = [](Args... args) -> Ret {
        return direct_syscall_trampoline<Ret, Args...>(captured_syscall_number, args...);
        };

    return function_pointer;
}

template<typename Ret, typename... Args>
Ret syscall_manager::direct_syscall_trampoline(DWORD syscall_number, Args... args) {
    setup_syscall_number(syscall_number);
    return reinterpret_cast<Ret(__stdcall*)(Args...)>(execute_syscall)(args...);
}

#endif