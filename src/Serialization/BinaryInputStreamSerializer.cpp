// Copyright (c) 2011-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BinaryInputStreamSerializer.h"

#include <algorithm>
#include <cassert>
#include <stdexcept>
#include <Common/StreamTools.h>
#include "SerializationOverloads.h"

using namespace common;

namespace cn {

namespace {

template<typename StorageType, typename T>
void readVarintAs(IInputStream& s, T &i) {
  i = static_cast<T>(readVarint<StorageType>(s));
}

}

ISerializer::SerializerType BinaryInputStreamSerializer::type() const {
  return ISerializer::INPUT;
}

bool BinaryInputStreamSerializer::beginObject(common::StringView name) {
  return true;
}

void BinaryInputStreamSerializer::endObject() {
}

bool BinaryInputStreamSerializer::beginArray(size_t& size, common::StringView name) {
  readVarintAs<uint64_t>(stream, size);

  if (size > 128*1024*1024) {
    throw std::runtime_error("array size is too big");
  }

  return true;
}

void BinaryInputStreamSerializer::endArray() {
}

bool BinaryInputStreamSerializer::operator()(uint8_t& value, common::StringView name) {
  readVarint(stream, value);
  return true;
}

bool BinaryInputStreamSerializer::operator()(uint16_t& value, common::StringView name) {
  readVarint(stream, value);
  return true;
}

bool BinaryInputStreamSerializer::operator()(int16_t& value, common::StringView name) {
  readVarintAs<uint16_t>(stream, value);
  return true;
}

bool BinaryInputStreamSerializer::operator()(uint32_t& value, common::StringView name) {
  readVarint(stream, value);
  return true;
}

bool BinaryInputStreamSerializer::operator()(int32_t& value, common::StringView name) {
  readVarintAs<uint32_t>(stream, value);
  return true;
}

bool BinaryInputStreamSerializer::operator()(int64_t& value, common::StringView name) {
  readVarintAs<uint64_t>(stream, value);
  return true;
}

bool BinaryInputStreamSerializer::operator()(uint64_t& value, common::StringView name) {
  readVarint(stream, value);
  return true;
}

bool BinaryInputStreamSerializer::operator()(bool& value, common::StringView name) {
  value = read<uint8_t>(stream) != 0;
  return true;
}

bool BinaryInputStreamSerializer::operator()(std::string& value, common::StringView name) {
  return readBinaryString(value, 128ull * 1024 * 1024);
}

bool BinaryInputStreamSerializer::readBinaryString(std::string& value, uint64_t maxSize) {
  uint64_t size;
  readVarint(stream, size);

  if (size > maxSize) {
    throw std::runtime_error("binary field exceeds the parse limit");
  } else if (size > 0) {
    // Read incrementally in bounded chunks instead of resizing to the full declared size up front.
    // A hostile length prefix that exceeds the bytes actually available would otherwise force a large
    // allocation (up to the parse limit) before the read fails — a parse-time memory-amplification DoS
    // (tiny input claiming a huge blob). Reading in fixed chunks makes the peak allocation track the
    // bytes actually delivered: checkedRead throws as soon as the stream cannot supply the next chunk,
    // so an over-claimed length is rejected after reading only what exists. For valid input the result
    // is byte-identical to the previous resize-then-read path. Callers that know a tighter bound pass
    // it via maxSize so an over-limit length prefix is rejected before any chunk is allocated.
    static const uint64_t CHUNK = 1u << 16; // 64 KiB
    std::vector<char> chunk(static_cast<size_t>(size < CHUNK ? size : CHUNK));
    value.clear();
    value.reserve(static_cast<size_t>(size < CHUNK ? size : CHUNK));
    uint64_t remaining = size;
    while (remaining > 0) {
      const size_t want = static_cast<size_t>(remaining < CHUNK ? remaining : CHUNK);
      checkedRead(&chunk[0], want);
      value.append(&chunk[0], want);
      remaining -= want;
    }
  } else {
    value.clear();
  }

  return true;
}

bool BinaryInputStreamSerializer::binary(void* value, size_t size, common::StringView name) {
  checkedRead(static_cast<char*>(value), size);
  return true;
}

bool BinaryInputStreamSerializer::binary(std::string& value, common::StringView name) {
  return (*this)(value, name);
}

bool BinaryInputStreamSerializer::binary(std::string& value, uint64_t maxSize, common::StringView name) {
  return readBinaryString(value, maxSize);
}

bool BinaryInputStreamSerializer::operator()(double& value, common::StringView name) {
  assert(false); //the method is not supported for this type of serialization
  throw std::runtime_error("BinaryInputStreamSerializer does not support double serialization");
  return false;
}

void BinaryInputStreamSerializer::checkedRead(char* buf, size_t size) {
  read(stream, buf, size);
}

}
