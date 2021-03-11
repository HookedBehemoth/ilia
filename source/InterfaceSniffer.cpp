#include "InterfaceSniffer.hpp"

#include<experimental/array>
#include<algorithm>

namespace ilia {

/*

struct nn::sf::cmif::server::CmifServerMessage::vtable {
  nn::Result (*PrepareForProcess)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::cmif::CmifMessageMetaInfo *info);
  nn::Result (*OverwriteClientProcessId)(nn::sf::cmif::server::CmifServerMessage *this, pid_t *pid);
  nn::Result (*GetBuffers)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::detail::PointerAndSize *pas);
  nn::Result (*GetInNativeHandles)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::NativeHandle *handles);
  nn::Result (*GetInObjects)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::cmif::server::CmifServerObjectInfo *info);
  nn::Result (*BeginPreparingForReply)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::detail::PointerAndSize *pas);
  nn::Result (*SetBuffers)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::detail::PointerAndSize *pas);
  nn::Result (*SetOutObjects)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::cmif::server::CmifServerObjectInfo *info);
  nn::Result (*SetOutNativeHandles)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::NativeHandle *handles);
  nn::Result (*BeginPreparingForErrorReply)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::detail::PointerAndSize *pas, uint64_t error_code);
  nn::Result (*EndPreparingForReply)(nn::sf::cmif::server::CmifServerMessage *this);
};
 */

InterfaceSniffer::InterfaceSniffer(Ilia &ilia, Process::STable &s_table) :
	ilia(ilia),
	interface_id(
		ilia.pcap_writer.WriteIDB(
			pcapng::LINKTYPE_USER1, 0,
			std::experimental::make_array(
				pcapng::Option {.code = 2, .length = (uint16_t) (s_table.interface_name.length() + 1), .value = s_table.interface_name.c_str()},
				pcapng::Option {.code = 0, .length = 0, .value = nullptr}
				).data())),
	s_table(s_table),
	s_table_trap(s_table.process, s_table.addr, *this) {
	fprintf(stderr, "made interface sniffer for %s\n", s_table.interface_name.c_str());
}

enum class ChunkType : uint8_t {
	RequestPas,
	RequestData,
	MetaInfo,
	ResponsePas,
	ResponseData,
	ResultCode,
	Buffers,
};

template<typename T>
static void MakeChunk(util::Buffer &message, ChunkType type, T &t) {
	message.Write(type);
	message.Write(util::Buffer::Size(t));
	message.Write(t);
}

InterfaceSniffer::MessageContext::MessageContext(
	InterfaceSniffer &sniffer,
	Process::Thread &thread,
	uint64_t object,
	Process::RemotePointer<nn::sf::cmif::server::CmifServerMessage> message,
	Process::RemotePointer<nn::sf::detail::PointerAndSize> pas) :
	CommonContext<InterfaceSniffer>(sniffer, thread),
	out_buffer(pcapng::WTAP_MAX_PACKET_SIZE_STANDARD),
	message(message),
	vtable(*this, thread.process, (*message).vtable),
	holder(thread, vtable.trap_vtable) {
	// fprintf(stderr, "entering message handling context for thread 0x%lx\n", thread.thread_id);

	auto rq_pas = *pas;
	// RequestPas
	MakeChunk(out_buffer, ChunkType::RequestPas, rq_pas);

	if (out_buffer.ReadAvailable() + rq_pas.size < pcapng::WTAP_MAX_PACKET_SIZE_STANDARD) {
		// RequestData
		out_buffer.Write(ChunkType::RequestData);
		out_buffer.Write(rq_pas.size);
		auto dst = out_buffer.Reserve(rq_pas.size);
		process.ReadBytes({ dst.data(), rq_pas.size }, rq_pas.pointer);
		out_buffer.MarkWritten(rq_pas.size);
	} else {
		fprintf(stderr, "Writing ResponseData of size: 0x%lx would excede WTAP_MAX_PACKET_SIZE_STANDARD. Skipping!\n", rq_pas.size);
	}

	message = {holder.addr}; // poison vtable
}

InterfaceSniffer::MessageContext::~MessageContext() {
	//fprintf(stderr, "leaving message handling context for thread 0x%lx\n", thread.thread_id);
	message = {vtable.real_vtable_addr}; // restore vtable

	uint32_t result = (uint32_t) thread.GetContext().cpu_gprs[0].x;

	MakeChunk(out_buffer, ChunkType::ResultCode, result);

	owner.ilia.pcap_writer.WriteEPB(owner.interface_id, armTicksToNs(armGetSystemTick()) / 1000, out_buffer.ReadAvailable(), out_buffer.ReadAvailable(), out_buffer.Read(), nullptr);
}

InterfaceSniffer::MessageContext::PrepareForProcess::PrepareForProcess(
	MessageContext &ctx,
	Process::Thread &thread,
	uint64_t _this,
	Process::RemotePointer<nn::sf::cmif::CmifMessageMetaInfo> info) :
	CommonContext<MessageContext>(ctx, thread) {
	owner.meta_info.emplace(*info);
	MakeChunk(owner.out_buffer, ChunkType::MetaInfo, *owner.meta_info);
}

InterfaceSniffer::MessageContext::BeginPreparingForReply::BeginPreparingForReply(
	MessageContext &ctx,
	Process::Thread &thread,
	uint64_t _this,
	Process::RemotePointer<nn::sf::detail::PointerAndSize> pas) :
	CommonContext<MessageContext>(ctx, thread),
	pas(pas) {
}

InterfaceSniffer::MessageContext::BeginPreparingForReply::~BeginPreparingForReply() {
	owner.rs_pas.emplace(*pas);
}

InterfaceSniffer::MessageContext::SetBuffers::SetBuffers(
	MessageContext &ctx,
	Process::Thread &thread,
	uint64_t _this,
	Process::RemotePointer<nn::sf::detail::PointerAndSize> pas_array) :
	CommonContext<MessageContext>(ctx, thread) {
	if(owner.meta_info) {
		// Calculate total buffer size
		size_t buffer_size = owner.meta_info->buffer_count * sizeof(uint64_t);
		for (size_t i = 0; i < owner.meta_info->buffer_count; i++)
			buffer_size += pas_array[i].size;
		if (owner.out_buffer.ReadAvailable() + buffer_size < pcapng::WTAP_MAX_PACKET_SIZE_STANDARD) {
			// Write buffer head
			owner.out_buffer.Write(ChunkType::Buffers);
			owner.out_buffer.Write(buffer_size);
			auto span = owner.out_buffer.Reserve(buffer_size);
			auto ptr = span.data();
			for(size_t i = 0; i < owner.meta_info->buffer_count; i++) {
				nn::sf::detail::PointerAndSize pas = pas_array[i];
				*reinterpret_cast<uint64_t*>(ptr) = pas.size;
				ptr += sizeof(uint64_t);
				process.ReadBytes({ptr, pas.size}, pas.pointer);
				ptr += pas.size;
			}
			owner.out_buffer.MarkWritten(buffer_size);
		} else {
			fprintf(stderr, "Writing ResponseData of size: 0x%lx would excede WTAP_MAX_PACKET_SIZE_STANDARD. Skipping!\n", buffer_size);
		}
	} else {
		fprintf(stderr, "WARNING: SetBuffers called without PrepareForProcess?\n");
	}
}

InterfaceSniffer::MessageContext::EndPreparingForReply::EndPreparingForReply(
	MessageContext &ctx,
	Process::Thread &thread,
	uint64_t _this) :
	CommonContext<MessageContext>(ctx, thread) {
	if(owner.rs_pas) {
		auto rs_pas = *owner.rs_pas;
		// ResponsePas
		MakeChunk(owner.out_buffer, ChunkType::ResponsePas, rs_pas);
		// ResponseData
		if (owner.out_buffer.ReadAvailable() + rs_pas.size < pcapng::WTAP_MAX_PACKET_SIZE_STANDARD) {
			owner.out_buffer.Write(ChunkType::ResponseData);
			owner.out_buffer.Write(rs_pas.size);
			auto dst = owner.out_buffer.Reserve(rs_pas.size);
			process.ReadBytes({ dst.data(), rs_pas.size }, rs_pas.pointer);
			owner.out_buffer.MarkWritten(rs_pas.size);
		} else {
			fprintf(stderr, "Writing ResponseData of size: 0x%lx would excede WTAP_MAX_PACKET_SIZE_STANDARD. Skipping!\n", rs_pas.size);
		}
	}
}

} // namespace ilia
