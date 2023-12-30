#include <Carbon.h>
#include <Events.h>
#include <OpenTransport.h>
#include <QuickDraw.h>

#define OT_BFRAME_OVERFLOW_SIZE 8
#define OT_XFER_BUFSIZE 512
#define BFRAME_BUFSIZE 255

// credit: minivmac/MOUSEMDV.c
//         pce/src/arch/macplus/cmd_68k.c
//         mpw/macos/sysequ.h
#define MACOS_CURSOR_INT    0x0828
#define MACOS_CURSOR_RAW    0x082C
#define MACOS_CURSOR_CHG   0x08CE
#define MACOS_CURSOR_BUTTON 0x0172

static const UInt16 bMajor = 1;
static const UInt16 bMinor = 6;

#pragma pack(push, 1)

typedef struct UInt16Tuple {
	UInt16 a;
	UInt16 b;
} UInt16Tuple;

#pragma pack(pop)

typedef struct BFrame {
	unsigned int cmdlen;
	char cmd[8];
	char buf[BFRAME_BUFSIZE+1];
} BFrame;

// Event handlers
OTResult handleBFrame(BFrame *bFrame);

static pascal void bNotifier(
	void *contextPtr, 
	OTEventCode code, 
	OTResult result, 
	void *cookie
);

// Client calls
OTResult bClientHelloBack(BFrame *bFrameIn);
OTResult bClientCALV();
OTResult bClientCNOP();
OTResult bClientDINF();
OTResult bClientDMMV(BFrame *bFrameIn);
OTResult bClientDMDNUP(BFrame *bFrameIn, Boolean down);

// Network setup
OSStatus bOTInit(AppContext *ctx);
OSStatus bTeardown(AppContext *ctx);
OSStatus bDisconnect(AppContext *ctx);
OSStatus bConnect(AppContext *appContext, const char *host);

// serde
BFrame newBFrame(const char *cmd);
OTResult sendBFrame(BFrame *bFrame);
BFrame *bRecv2Frame(unsigned int len, unsigned char *buf);
void bfWriteUInt16(BFrame *bFrame, UInt16 val);
void bfWriteSInt16(BFrame *bFrame, SInt16 val);
void bfWriteString(BFrame *bFrame, char *val);