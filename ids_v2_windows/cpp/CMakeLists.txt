cmake_minimum_required(VERSION 3.16)
project(ids_backend CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
  add_compile_options(/W4)
else()
  add_compile_options(-Wall -Wextra)
endif()

include_directories(${CMAKE_SOURCE_DIR})

# ── libpcap / Npcap ──────────────────────────────────────────────────────────
if(WIN32)
  # Needed for inet_ntop/inet_pton (Vista+) and to keep <windows.h> lean so it
  # doesn't clash with <winsock2.h>.
  add_compile_definitions(_WIN32_WINNT=0x0600 WIN32_LEAN_AND_MEAN NOMINMAX)

  if(NOT DEFINED ENV{NPCAP_SDK})
    message(FATAL_ERROR
      "NPCAP_SDK environment variable is not set.\n"
      "Download the Npcap SDK from https://npcap.com/#download, extract it, "
      "and set NPCAP_SDK to that folder (e.g. C:\\npcap-sdk-1.13).\n"
      "Also install the Npcap runtime (with 'WinPcap API-compatible mode' "
      "checked) from https://npcap.com so pcap_open_live() works at runtime.")
  endif()

  set(PCAP_INCLUDE_DIR "$ENV{NPCAP_SDK}/Include" CACHE PATH "Npcap include dir")

  # The Npcap SDK ships separate 32/64-bit lib dirs.
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PCAP_LIB_DIR "$ENV{NPCAP_SDK}/Lib/x64" CACHE PATH "Npcap lib dir")
  else()
    set(PCAP_LIB_DIR "$ENV{NPCAP_SDK}/Lib" CACHE PATH "Npcap lib dir")
  endif()

  include_directories(${PCAP_INCLUDE_DIR})
  link_directories(${PCAP_LIB_DIR})
  set(PCAP_LIBS wpcap Packet ws2_32 iphlpapi)
else()
  find_library(PCAP_LIBS pcap REQUIRED)
  find_path(PCAP_INC pcap.h REQUIRED)
  include_directories(${PCAP_INC})
endif()

# ── IDS binary ───────────────────────────────────────────────────────────────
add_executable(ids_backend main.cpp)
target_link_libraries(ids_backend PRIVATE ${PCAP_LIBS})
if(NOT WIN32)
  target_link_libraries(ids_backend PRIVATE pthread)
endif()

install(TARGETS ids_backend DESTINATION bin)
