#include "pcapng.hpp"

namespace ilia {
namespace pcapng {

Writer::Writer(FILE *file) : file(file) {
}

template<typename T>
static void WriteData(FILE *file, T &t) {
	fwrite(&t, sizeof(T), 1, file);
}

void Writer::WriteOptions(Option *options) {
	for(int i = 0; options != NULL && options[i].code != 0; i++) {
		fwrite(&options[i], sizeof(uint16_t), 2, file);
		fwrite(options[i].value, options[i].length, 1, file);
		uint8_t zeros[4] = {};
		fwrite(zeros, 1, ((options[i].length + 3) & ~3) - options[i].length, file);
	}
	Option end = {.code = 0, .length = 0, .value = NULL};
	fwrite(&end, sizeof(uint16_t), 2, file);
}

uint32_t Writer::GetOptionSize(Option *options) {
	uint32_t size = 0;

	for(int i = 0; options != NULL && options[i].code != 0; i++) {
		size += sizeof(options[i].code);   // code
		size += sizeof(options[i].length); // length
		size += (options[i].length + 3) & ~3;
	}
	size += 4; // end

	return size;
}

void Writer::WriteSHB(Option *options) {
	struct {
		uint32_t bom;
		uint16_t major;
		uint16_t minor;
		int64_t length;
	} shb_head = { .bom = 0x1A2B3C4D, .major=1, .minor=0, .length=-1 };

	const uint32_t type = 0x0A0D0D0A;
	const uint32_t total_size = sizeof(uint32_t) // Block Type
							  + sizeof(uint32_t) // Block Total Length
							  + sizeof(shb_head)
							  + GetOptionSize(options)
							  + sizeof(uint32_t); // Block Total Length

	WriteData(file, type);
	WriteData(file, total_size);
	WriteData(file, shb_head);
	WriteOptions(options);
	WriteData(file, total_size);

	interface_id = 0; // local to section
}

uint32_t Writer::WriteIDB(uint16_t link_type, uint32_t snap_len, Option *options) {
	struct {
		uint16_t link_type;
		uint16_t reserved;
		uint32_t snap_len;
	} idb_head = { .link_type = link_type, .reserved = 0, .snap_len = snap_len };

	const uint32_t type = 0x1;
	const uint32_t total_size = sizeof(uint32_t) // Block Type
							  + sizeof(uint32_t) // Block Total Length
							  + sizeof(idb_head)
							  + GetOptionSize(options)
							  + sizeof(uint32_t); // Block Total Length

	WriteData(file, type);
	WriteData(file, total_size);
	WriteData(file, idb_head);
	WriteOptions(options);
	WriteData(file, total_size);

	return interface_id++;
}

void Writer::WriteEPB(uint32_t if_id, uint64_t timestamp, uint32_t cap_length, uint32_t orig_length, const void *data, Option *options) {
	struct __attribute__((packed)) {
		uint32_t if_id;
		uint32_t ts_hi;
		uint32_t ts_lo;
		uint32_t cap_length;
		uint32_t orig_length;
	} epb_head = {
		.if_id = if_id,
		.ts_hi = static_cast<uint32_t>(timestamp >> 32),
		.ts_lo = static_cast<uint32_t>(timestamp & 0xFFFFFFFF),
		.cap_length = cap_length,
		.orig_length = orig_length
	};
	
	const uint32_t type = 0x6;
	const uint32_t total_size = sizeof(uint32_t) // Block Type
							  + sizeof(uint32_t) // Block Total Length
							  + sizeof(epb_head)
							  + GetOptionSize(options)
							  + ((cap_length + 3) & ~3)
							  + sizeof(uint32_t); // Block Total Length

	WriteData(file, type);
	WriteData(file, total_size);
	WriteData(file, epb_head);
	fwrite(data, cap_length, 1, file);
	uint8_t zeros[4] = {};
	fwrite(zeros, 1, ((cap_length + 3) & ~3) - cap_length, file);
	WriteOptions(options);
	WriteData(file, total_size);
}

} // namespace pcapng
} // namespace ilia
