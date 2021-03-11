#include "Ilia.hpp"
#include "scope_guard.hpp"
#include "assert.hpp"

#include<unistd.h>
#include<stdio.h>
#include<string.h>
#include<sys/iosupport.h>

#include "ini.h"

#include "err.hpp"
#include "pcapng.hpp"

#include "Process.hpp"
#include "InterfaceSniffer.hpp"

static int IniSectionHandler(void *user, const char *section, void **section_context) {
	ilia::Ilia &ilia = *(ilia::Ilia*) user;

	std::string buf = section;
	std::string::size_type i = buf.find(' ');
	if(i == std::string::npos) {
		fprintf(stderr, "didn't find space\n");
		return 0;
	}

	uint64_t pid;
	if(buf.substr(0, i) == "title") {
		size_t index;
		uint64_t tid = std::stoull(buf.substr(i+1), &index, 16);
		fprintf(stderr, "looking up tid 0x%lx\n", tid);
		if(index != buf.size() - i - 1) {
			return 0;
		}
		ResultCode::AssertOk(pmdmntGetProcessId(&pid, tid));
	} else if(buf.substr(0, i) == "pid") {
		size_t index;
		pid = std::stoull(buf.substr(i+1), &index, 0);
		if(index != buf.size() - i - 1) {
			return 0;
		}
	} else {
		fprintf(stderr, "unrecognized: '%s'\n",buf.substr(0, i).c_str());
		return 0;
	}

	fprintf(stderr, "attaching to process 0x%lx\n", pid);
   
	auto p = ilia.processes.find(pid);
	if(p == ilia.processes.end()) {
		p = ilia.processes.emplace(
			std::piecewise_construct,
			std::make_tuple(pid),
			std::tuple<ilia::Ilia&, uint64_t>(ilia, pid)).first;
	}

	*section_context = (void*) &p->second;
	return 1;
}

static int IniValueHandler(void *user, void *section_context, const char *name, const char *value) {
	if(section_context == nullptr) {
		return 0;
	}
	
	ilia::Ilia &ilia = *(ilia::Ilia*) user;
	ilia::Process &proc = *(ilia::Process*) section_context;

	if(strcmp(value, "auto") == 0) {
		ilia.sniffers.emplace_back(std::move(proc.Sniff(name)));
	} else {
		size_t offset = std::stoull(value, nullptr, 0);
		fprintf(stderr, "attaching to manual '%s' = 0x%lx (\"%s\")\n", name, offset, value);
		ilia.sniffers.emplace_back(std::move(proc.Sniff(name, offset)));
	}
	
	return 1;
}

extern "C" void __libnx_initheap(void) {
    static char nx_inner_heap[0x100000];

    extern char *fake_heap_start;
    extern char *fake_heap_end;
    fake_heap_start = nx_inner_heap;
    fake_heap_end   = nx_inner_heap + sizeof(nx_inner_heap);
}

extern "C" void __appInit(void) {
	Result rc=0;

	rc = smInitialize();
	if (R_SUCCEEDED(rc)) rc = setsysInitialize();
	if (R_SUCCEEDED(rc)) {
		SetSysFirmwareVersion version;
		setsysGetFirmwareVersion(&version);
		hosversionSet(MAKEHOSVERSION(version.major, version.minor, version.micro));
		setsysExit();
	}
	if (R_SUCCEEDED(rc)) rc = timeInitialize();
	if (R_SUCCEEDED(rc)) rc = pmdmntInitialize();
	if (R_SUCCEEDED(rc)) rc = ldrDmntInitialize();
	if (R_SUCCEEDED(rc)) rc = fsInitialize();
	if (R_SUCCEEDED(rc)) rc = fsdevMountSdmc();
	if (R_SUCCEEDED(rc)) rc = pscmInitialize();

	if (R_FAILED(rc)) diagAbortWithResult(rc);

	smExit();
}

extern "C" void __appExit(void) {
	pscmExit();
	fsExit();
	ldrDmntExit();
	pmdmntExit();
	timeExit();
}

FILE* fp=nullptr;

extern "C" void __libnx_exception_handler(ThreadExceptionDump *ctx) {
    MemoryInfo mem_info; u32 page_info;
    svcQueryMemory(&mem_info, &page_info, ctx->pc.x);
	fprintf(fp, "%#x exception with pc=%#lx\n", ctx->error_desc, ctx->pc.x - mem_info.addr);
	fclose(fp);
}

int main(int argc, char *argv[]) {
	fp = fopen("/sd/log.txt", "a");
	auto log_guard = SCOPE_GUARD { fclose(fp); };

	constexpr devoptab_t dotab_stdout = {
		.name    = "con",
		.write_r = +[](struct _reent *r,void *fd,const char *ptr, size_t len) -> ssize_t {
			fwrite(ptr, 1, len, fp);
			return len;
		},
	};

	devoptab_list[STD_OUT] = &dotab_stdout;
	devoptab_list[STD_ERR] = &dotab_stdout;

	try {
		time_t time=0;
		timeGetCurrentTime(TimeType_Default, reinterpret_cast<u64*>(&time));
		char fname[301];
		strftime(fname, sizeof(fname)-1, "/sd/ilia_%F_%H-%M-%S.pcapng", gmtime(&time));
		fprintf(stderr, "opening '%s'...\n", fname);
		FILE *log = fopen(fname, "wb");
		auto pcapng_guard = SCOPE_GUARD { fclose(log); };
		
		ilia::Ilia ilia(log);

		{
			FILE *f = fopen("/sd/ilia.ini", "r");
			auto config_guard = SCOPE_GUARD { fclose(f); };

			if(!f) {
				fprintf(stderr, "could not open configuration\n");
				return 1;
			}

			int error = ini_parse_file(f, &IniValueHandler, &IniSectionHandler, &ilia);
			if(error != 0) {
				fprintf(stderr, "ini error on line %d\n", error);
				return 1;
			}
		}
		
		while(!ilia.destroy_flag && !ilia.event_waiter.Wait(3000000000));
		fprintf(stderr, "ilia terminating\n");
   
		return 0;
	} catch(ResultError &e) {
		fprintf(stderr, "caught ResultError: 0x%x\n", e.code.code);
		// return e.code.code;
	} catch (std::exception &e) {
		fprintf(stderr, "caught exception %s\n", e.what());
	} catch (...) {
		fprintf(stderr, "caught exception\n");
	}
}

namespace ilia {

Ilia::Ilia(FILE *pcap) :
	pcap_writer(pcap) {
	static const char shb_hardware[] = "Nintendo Switch";
	static const char shb_os[] = "Horizon";
	static const char shb_userappl[] = "ilia";
	pcapng::Option shb_options[] = {
		{.code = pcapng::SHB_HARDWARE, .length = sizeof(shb_hardware), .value = shb_hardware},
		{.code = pcapng::SHB_OS, .length = sizeof(shb_os), .value = shb_os},
		{.code = pcapng::SHB_USERAPPL, .length = sizeof(shb_userappl), .value = shb_userappl},
		{.code = 0, .length = 0, .value = 0}
	};
	pcap_writer.WriteSHB(shb_options);
}

/*
	void Ilia::ProbeProcesses() {
	uint64_t pids[256];
	uint32_t num_pids;
	trn::ResultCode::AssertOk(svcGetProcessList(&num_pids, pids, ARRAY_LENGTH(pids)));

	trn::service::SM sm = trn::ResultCode::AssertOk(trn::service::SM::Initialize());
	trn::ipc::client::Object pm_dmnt = trn::ResultCode::AssertOk(
	sm.GetService("pm:dmnt"));
	trn::ipc::client::Object ldr_dmnt = trn::ResultCode::AssertOk(
	sm.GetService("ldr:dmnt"));
   
	for(uint32_t i = 0; i < num_pids; i++) {
	handle_t proc_handle;
	auto r = pm_dmnt.SendSyncRequest<65000>( // Atmosphere-GetProcessHandle
	trn::ipc::InRaw<uint64_t>(pids[i]),
	trn::ipc::OutHandle<handle_t, trn::ipc::copy>(proc_handle));
	if(!r) {
	fprintf(stderr, "failed to get process handle for %ld: 0x%x\n", pids[i], r.error().code);
	continue;
	}
   
	processes.try_emplace(pids[i], this, ldr_dmnt, std::move(trn::KProcess(proc_handle)), pids[i]);
	}
	}

	trn::ResultCode Ilia::InterceptAll(std::string interface_name) {
	for(auto &kv : processes) {
	auto &proc = kv.second;
	for(auto &st : proc.s_tables) {
	if(st.interface_name == interface_name) {
	fprintf(stderr, "patching s_Table(%s) in %ld\n", st.interface_name.c_str(), proc.pid);
	if(proc.pipes.size() >= 16) {
	return trn::ResultCode(ILIA_ERR_TOO_MANY_PIPES);
	}
	Pipe pipe(this, &st, proc.pipes.size());
	proc.pipes.push_back(pipe);
	pipe.Patch();
	}
	}
	}
   
	return trn::ResultCode(RESULT_OK);
	}
*/

} // namespace ilia
