#undef CALL_NOT_IN_CARBON
#define CALL_NOT_IN_CARBON 1

#include <Carbon.h>
#include <CursorDevices.h>
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
#define MACOS_CURSOR_CHG    0x08CE
#define MACOS_CURSOR_BUTTON 0x0172

static const UInt16 bMajor = 1;
static const UInt16 bMinor = 6;

#pragma pack(push, 1)

typedef struct UInt16Tuple {
	UInt16 a;
	UInt16 b;
	UInt16 c;
} UInt16Tuple;

typedef struct SInt16Tuple {
	SInt16 a;
	SInt16 b;
	SInt16 c;
} SInt16Tuple;

#pragma pack(pop)

typedef struct BFrame {
	unsigned int cmdlen;
	char cmd[8];
	char buf[BFRAME_BUFSIZE+1];
} BFrame;

// Event handlers
static OTResult handleBFrame(BFrame *bFrame);
static OTResult handleOTResult(OTResult err);
static OTResult handleOTEvent(OTEventCode code);

static pascal void bNotifier(
	void *contextPtr, 
	OTEventCode code, 
	OTResult result, 
	void *cookie
);

// Client calls
static OTResult bClientHelloBack(BFrame *bFrameIn);
static OTResult bClientCALV();
static OTResult bClientCNOP();
static OTResult bClientDINF();
static OTResult bClientDMMV(BFrame *bFrameIn);
static OTResult bClientDMDNUP(BFrame *bFrameIn, Boolean down);
static OTResult bClientDKDNUP(BFrame *bFrameIn, Boolean down);

// Network setup
OSStatus bOTInit(AppContext *ctx);
OSStatus bTeardown(AppContext *ctx);
OSStatus bDisconnect(AppContext *ctx);
OSStatus bConnect(AppContext *appContext, const char *host);

// serde
static BFrame newBFrame(const char *cmd);
static OTResult sendBFrame(BFrame *bFrame);
static BFrame *bRecv2Frame(unsigned int len, unsigned char *buf);
static void bfWriteUInt16(BFrame *bFrame, UInt16 val);
static void bfWriteSInt16(BFrame *bFrame, SInt16 val);
static void bfWriteString(BFrame *bFrame, char *val);

// CFM Mouse

// EXTERN_API( void ) LMSetMouseButtonState(UInt8 value)         TWOWORDINLINE(0x11DF, 0x0172);
void _LMSetMouseButtonState(unsigned char val);

