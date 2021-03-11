#pragma once

#include<switch.h>

#include "handle_handler.hpp"
#include "Process.hpp"
#include "pcapng.hpp"

#include<map>

namespace ilia {

class InterfaceSniffer;

class Ilia {
  public:
   Ilia(FILE *pcap);
   Ilia(Ilia&) = delete;
   Ilia operator=(Ilia&) = delete;
   
   bool destroy_flag = false;
   pcapng::Writer pcap_writer;
   HandleWaiter event_waiter;

   std::map<uint64_t, Process> processes;
   std::vector<std::unique_ptr<InterfaceSniffer>> sniffers;
};

} // namespace ilia
