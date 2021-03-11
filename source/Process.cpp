#include "Process.hpp"

#include<elf.h>
#include<stdio.h>

#include<map>

#include<cxxabi.h>

#include "assert.hpp"
#include "err.hpp"

#include "Ilia.hpp"
#include "DebugTypes.hpp"
#include "InterfaceSniffer.hpp"

namespace ilia {

struct ModHeader {
	uint32_t magic, dynamic_off, bss_start_off, bss_end_off;
	uint32_t unwind_start_off, unwind_end_off, module_object_off;
};

Process::Process(
	Ilia &ilia,
	uint64_t pid) :
	ilia(ilia), pid(pid) {
	ResultCode::AssertOk(svcDebugActiveProcess(&debug, pid));
	ilia.event_waiter.Add(debug, [this] { HandleEvents(); });
}

Process::Thread::Thread(Process &process, uint64_t id, uint64_t tls, uint64_t entrypoint) :
	process(process),
	thread_id(id),
	tls(tls),
	entrypoint(entrypoint) {
}

ThreadContext &Process::Thread::GetContext() {
	if(!is_context_valid) {
		ResultCode::AssertOk(
			svcGetDebugThreadContext(&context, process.debug, thread_id, RegisterGroup_All));
		is_context_valid = true;
	}
	is_context_dirty = true;
	return context;
}

void Process::Thread::CommitContext() {
	if(is_context_dirty) {
		ResultCode::AssertOk(
			svcSetDebugThreadContext(process.debug, thread_id, &context, RegisterGroup_CpuAll));
		is_context_dirty = false;
	}
}

void Process::Thread::InvalidateContext() {
	is_context_valid = false;
}

bool Process::Thread::operator<(const Thread &rhs) const {
	return thread_id < rhs.thread_id;
}

Process::NSO::NSO(Process &process, uint64_t base, uint64_t size) :
	process(process),
	base(base),
	size(size) {
}

Process::STable::STable(Process &process, std::string interface_name, uint64_t addr) :
	process(process),
	interface_name(interface_name),
	addr(addr) {
}

Process::Trap::Trap(Process &process, std::function<void(Thread&)> cb) :
	trap_addr(process.RegisterTrap(*this)),
	process(process),
	cb(cb) {
}

Process::Trap::~Trap() {
	process.UnregisterTrap(*this);
}

void Process::Trap::Hit(Thread &t) {
	cb(t);
}

std::unique_ptr<InterfaceSniffer> Process::Sniff(const char *name) {
   if(!has_scanned) {
      ScanSTables();
   }
	auto i = s_tables.find(std::string(name));
	if(i == s_tables.end()) {
		throw ResultError(ILIA_ERR_NO_SUCH_S_TABLE);
	}

	return std::make_unique<InterfaceSniffer>(ilia, i->second);
}

std::unique_ptr<InterfaceSniffer> Process::Sniff(std::string name, uint64_t offset) {
   if(!has_scanned) {
      ScanSTables();
   }
   auto i = s_tables.emplace(name, STable(*this, name, likely_aslr_base + offset)).first;
   return std::make_unique<InterfaceSniffer>(ilia, i->second);
}

void Process::HandleEvents() {
	nx::DebugEvent event = {};
	Result rc=0;

	while(R_SUCCEEDED(rc = svcGetDebugEvent(&event, debug))) {
		switch(event.event_type) {
		case nx::DebugEvent::EventType::AttachProcess: {
			if(has_attached) {
				throw ResultError(ILIA_ERR_INVALID_PROCESS_STATE);
			}
			fprintf(stderr, "attached process '%s'\n", event.attach_process.process_name);
			has_attached = true;
			break; }
		case nx::DebugEvent::EventType::AttachThread: {
			if(!has_attached) {
				throw ResultError(ILIA_ERR_INVALID_PROCESS_STATE);
			}
			auto i = threads.find(event.attach_thread.thread_id);
			if(i != threads.end()) {
				throw ResultError(ILIA_ERR_INVALID_THREAD_STATE);
			}
			threads.emplace(
				event.attach_thread.thread_id, Thread(
					*this,
					event.attach_thread.thread_id,
					event.attach_thread.tls_pointer,
					event.attach_thread.entrypoint));
			fprintf(stderr, "attached thread 0x%lx\n", event.attach_thread.thread_id);
			break; }
		case nx::DebugEvent::EventType::ExitProcess: {
			fprintf(stderr, "ERROR: exited process?\n");
			break; }
		case nx::DebugEvent::EventType::ExitThread: {
			threads.erase(event.thread_id);
			fprintf(stderr, "exited thread 0x%lx\n", event.thread_id);
			break; }
		case nx::DebugEvent::EventType::Exception: {
			switch(event.exception.exception_type) {
			case nx::DebugEvent::ExceptionType::InstructionAbort: {
				uint64_t far = event.exception.fault_register;
				auto i = threads.find(event.thread_id);
				if(i == threads.end()) {
					fprintf(stderr, "ERROR: no such thread 0x%lx\n", event.thread_id);
					break;
				}
				size_t index = LookupTrap(far);
				if(traps[index] == nullptr) {
					fprintf(stderr, "ERROR: no such trap 0x%lx\n", index);
				} else {
					traps[index]->Hit(i->second);
				}
				break; }
			case nx::DebugEvent::ExceptionType::DebuggerAttached: {
				fprintf(stderr, "got debugger attachment exception\n");
				break; }
			default:
				fprintf(stderr, "ERROR: unhandled exception: %d\n", static_cast<uint32_t>(event.exception.exception_type));
				return;
			}
			break; }
		default:
			fprintf(stderr, "ERROR: unknown debug event?\n");
			return;
		}
	}
	
	if(R_VALUE(rc) != KERNELRESULT(OutOfDebugEvents)) {
		throw ResultError(rc);
	}

	for(auto &i : threads) {
		i.second.CommitContext();
		i.second.InvalidateContext();
	}

	if (hosversionAtLeast(3,0,0)) {
		ResultCode::AssertOk(
			svcContinueDebugEvent(debug, 7, nullptr, 0));
	} else {
		ResultCode::AssertOk(
			svcLegacyContinueDebugEvent(debug, 7, 0));
	}
}

uint64_t Process::RegisterTrap(Trap &t) {
	if(!trap_free_list.empty()) {
		size_t index = trap_free_list.front();
		trap_free_list.pop_front();
		traps[index] = &t;
		return TrapAddress(index);
	} else {
		uint64_t addr = TrapAddress(traps.size());
		traps.push_back(&t);
		return addr;
	}
}

void Process::UnregisterTrap(Trap &t) {
	size_t index = LookupTrap(t.trap_addr);
	if(traps[index] != &t) {
		throw ResultError(ILIA_ERR_INVALID_TRAP);
	}
	traps[index] = nullptr;
	trap_free_list.push_back(index);
}

size_t Process::LookupTrap(uint64_t addr) {
	if(addr < TrapBaseAddress) {
		throw ResultError(ILIA_ERR_INVALID_TRAP);
	}
	if(addr >= TrapBaseAddress + (traps.size() * TrapSize)) {
		throw ResultError(ILIA_ERR_INVALID_TRAP);
	}
	return (addr - TrapBaseAddress) / TrapSize;
}

uint64_t Process::TrapAddress(size_t index) {
	return TrapBaseAddress + (index * TrapSize);
}

void Process::ScanSTables() {
	std::vector<LoaderModuleInfo> nso_infos(16, {{},0,0});
	int32_t num_nsos;

   if(pid >= 0x50) {
		 ResultCode::AssertOk(
			 ldrDmntGetProcessModuleInfo(pid, nso_infos.data(), nso_infos.size(), &num_nsos));
	 } else {
		 uint64_t addr = 0;
		 uint32_t pi = 0;
		 MemoryInfo mi;
		 while (ResultCode::AssertOk(svcQueryDebugProcessMemory(&mi, &pi, debug, addr)), mi.type != 3) {
			 if((uint64_t) mi.addr + mi.size < addr) {
				 fprintf(stderr, "giving up on finding module...\n");
				 return;
			 }
			 addr = (uint64_t) mi.addr + mi.size;
		 }

		 fprintf(stderr, "found module at 0x%lx\n", addr);
		 
		 nso_infos[0] = {.base_address = addr};
		 num_nsos = 1;
	 }

	 likely_aslr_base = nso_infos[0].base_address;

	for(int32_t i = 0; i < num_nsos; i++) {
		LoaderModuleInfo &info = nso_infos[i];
		nsos.emplace_back(*this, info.base_address, info.size);
		
		uint32_t mod_offset = Read<uint32_t>(info.base_address + 4);
		ModHeader hdr = Read<ModHeader>(info.base_address + mod_offset);

		std::map<int64_t, Elf64_Dyn> dyn_map;
		uint64_t dyn_addr = info.base_address + mod_offset + hdr.dynamic_off;
		for(Elf64_Dyn dyn; (dyn = Read<Elf64_Dyn>(dyn_addr)).d_tag != DT_NULL; dyn_addr+= sizeof(dyn)) {
			dyn_map[dyn.d_tag] = dyn;
		}

		if(dyn_map.find(DT_STRTAB) == dyn_map.end()) {
			fprintf(stderr, "  couldn't find string table\n");
			continue;
		}
		if(dyn_map.find(DT_STRSZ) == dyn_map.end()) {
			fprintf(stderr, "  couldn't find string table size\n");
			continue;
		}

		RemotePointer<char> string_table = RemotePointer<char>(debug, info.base_address + dyn_map[DT_STRTAB].d_un.d_val);
		if(dyn_map.find(DT_SYMTAB) == dyn_map.end()) {
			fprintf(stderr, "  couldn't find symbol table\n");
			continue;
		}

		if(dyn_map.find(DT_HASH) == dyn_map.end()) {
			fprintf(stderr, "  couldn't find hash table\n");
			continue;
		}

		uint32_t nchain = Access<uint32_t>(info.base_address + dyn_map[DT_HASH].d_un.d_val)[1];
		RemotePointer<Elf64_Sym> sym_table = Access<Elf64_Sym>(info.base_address + dyn_map[DT_SYMTAB].d_un.d_val);
		for(uint32_t i = 0; i < nchain; i++) {
			Elf64_Sym sym = sym_table[i];
			if(sym.st_name != 0) {
				std::string name;
				size_t p = sym.st_name;
				char c;
				while((c = string_table[p++])) {
					name.push_back(c);
				}
				
				size_t pos = name.find("s_Table");
				if(pos == std::string::npos) {
					continue;
				}
				
				int status;
				char *demangled = abi::__cxa_demangle(name.c_str(), 0, 0, &status);
				name = status==0 ? demangled : name.c_str();
				free(demangled);
            
				static const char prefix[] = "nn::sf::cmif::server::detail::CmifProcessFunctionTableGetter<";
				static const char postfix[] = ", void>::s_Table";
				if(name.compare(0, sizeof(prefix)-1, prefix) == 0 &&
					 name.compare(name.length() - (sizeof(postfix) - 1),
												sizeof(postfix) - 1, postfix) == 0) {
					name = name.substr(sizeof(prefix) - 1, name.length() - sizeof(prefix) + 1 - sizeof(postfix) + 1);
					fprintf(stderr, "  found s_Table: %s\n", name.c_str());
					s_tables.emplace(name, STable(*this, name, info.base_address + sym.st_value));
				} else {
					fprintf(stderr, "  found non-matching s_Table: %s\n", name.c_str());
				}
			}
		}
	}

   has_scanned = true;
}

} // namespace ilia
