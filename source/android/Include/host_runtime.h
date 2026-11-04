#pragma once

#include <cstdint>
#include <string>

namespace darksiders2::host {

enum class RuntimeState {
    kUninitialized,
    kRunning,
    kShutdown
};

class HostRuntime {
public:
    HostRuntime() = default;
    ~HostRuntime() = default;

    bool Initialize(int argc, char* argv[]);
    void RunMainLoop();
    void Shutdown();

private:
    RuntimeState m_state{RuntimeState::kUninitialized};
};

} // namespace darksiders2::host