# packet-spoon

Packet capture tool based on Pcap and Qt

## Buliding

### Dependency

- CMake 3.10+
- QT 6.1+
- GCC
- Npcap installed

### Steps

First, add `QT_DIR` and `Qt6_Dir` to your environment variables, which should point to `MinGW` folder inside Qt, perhaps like `C:\Qt\6.4.1\mingw_64`.

Then, use CMake

```powershell
cmake .
make
```

Build outputs will be placed in `.\build\`.

## Planned Features

- [ ] GUI support
- [ ] Detect all network interfaces
- [ ] Packet capture on requested NIC
- [ ] Parse packets and print out layered results
  - [ ] Custom parser support
  - [ ] Plugin system
- [ ] Dump result to *.pcap file
  - [ ] \*.pcapng format support (not likely to be implemented)
- [ ] Load existing \*.pcap file for analysis
