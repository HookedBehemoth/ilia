#pragma once

#include<switch.h>

#include<functional>
#include<vector>

class HandleWaiter {
public:
    HandleWaiter() {
        u32 dependencies[] = {
            PscPmModuleId_Fs
        };
        pscmGetPmModule(&m_module, PscPmModuleId(7200), dependencies, std::size(dependencies), true);
    }
    ~HandleWaiter() {
        pscPmModuleClose(&m_module);
    }
    HandleWaiter(HandleWaiter&) = delete;
    HandleWaiter operator=(HandleWaiter&) = delete;

    using Callback = std::function<void()>;

    void Add(Handle hdl, Callback cb) {
        m_impl.emplace_back(hdl, cb);
    }

    bool Wait(u64 timeout) {
        u32 object_count = m_impl.size();
        if (object_count == 0) {
            svcSleepThread(timeout);
            return true;
        }

        /* Yes, this is bad. */
        Waiter objects[1+object_count];
        u32 i=0;
        objects[i++] = waiterForEvent(&m_module.event);
        for (auto &[hdl, cb]: m_impl)
            objects[i++] = waiterForHandle(hdl);

        bool exit=false;

        s32 idx;
        if (R_SUCCEEDED(waitObjects(&idx, objects, object_count + 1, timeout))) {
            if (idx == 0) {
                PscPmState state;
                u32 flags;
                pscPmModuleGetRequest(&m_module, &state, &flags);
                switch (state) {
                    case PscPmState_ReadyShutdown:
                        exit = true;
                        break;
                    default:
                        break;
                }
                pscPmModuleAcknowledge(&m_module, state);
            } else {
                auto &[hdl, cb] = m_impl[idx-1];
                cb();
            }
        }
        
        return exit;
    }

private:
    std::vector<std::pair<Handle, Callback>> m_impl;
    PscPmModule m_module;
};
