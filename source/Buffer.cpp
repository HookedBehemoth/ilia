//
// Ilia - Homebrew debug monitor for the Nintendo Switch
// Copyright (C) 2018 misson20000 <xenotoad@xenotoad.net>
//
// This file is part of Ilia.
//
// Ilia is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Ilia is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Ilia.  If not, see <http://www.gnu.org/licenses/>.
//

#include "Buffer.hpp"

#include<algorithm>
#include<cstring>

namespace ilia {
namespace util {

Buffer::Buffer(size_t size) :
	data(size, 0) {
}

Buffer::~Buffer() {
}

void Buffer::Write(const uint8_t *io, size_t size) {
	EnsureSpace(size);
	std::copy_n(io, size, data.begin() + write_head);
	write_head+= size;
}

std::span<uint8_t> Buffer::Reserve(size_t size) {
	EnsureSpace(size);
	return { data.data() + write_head, data.size() - write_head };
}

void Buffer::MarkWritten(size_t size) {
	write_head+= size;
}

bool Buffer::Read(uint8_t *io, size_t size) {
	if(read_head + size > write_head) {
		return false;
	}
	std::copy_n(data.begin() + read_head, size, io);
	read_head+= size;
	return true;
}

bool Buffer::Read(std::string &str, size_t len) {
	if(ReadAvailable() < len) {
		return false;
	}
	str = std::string(Read(), Read() + len);
	MarkRead(len);
	return true;
}

uint8_t *Buffer::Read() {
	return data.data() + read_head;
}

void Buffer::MarkRead(size_t size) {
	read_head+= size;
}

void Buffer::Clear() {
	read_head = 0;
	write_head = 0;
}

size_t Buffer::ReadAvailable() {
	return write_head - read_head;
}

size_t Buffer::WriteAvailableHint() {
	return data.size() - write_head;
}

void Buffer::EnsureSpace(size_t size) {
	if(write_head + size > data.size()) {
		Compact();
	}
	if(write_head + size > data.size()) {
		data.resize(write_head + size);
	}
}

void Buffer::Compact() {
	std::copy(data.begin() + read_head, data.end(), data.begin());
	write_head-= read_head;
	read_head = 0;
}

} // namespace util
} // namespace ilia
