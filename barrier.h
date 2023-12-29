#include <Carbon.h>
#include <OpenTransport.h>
#include <QuickDraw.h>

#define OT_XFER_BUFSIZE 512
#define BFRAME_BUFSIZE 255

static const UInt16 bMajor = 1;
static const UInt16 bMinor = 6;
static const UInt16 bDefaultPort = 24800;

#pragma pack(push, 1)

typedef struct BCmdHello {
	UInt16 major;
	UInt16 minor;
} BCmdHello;

#pragma pack(pop)

typedef struct BFrame {
	unsigned int cmdlen;
	char cmd[8];
	char buf[BFRAME_BUFSIZE+1];
} BFrame;

// Event handlers
void handleBFrame(BFrame *bFrame);

static pascal void bNotifier(
	void *contextPtr, 
	OTEventCode code, 
	OTResult result, 
	void *cookie
);

// Client calls
void bClientHelloBack(BFrame *bFrame);
void bClientDINF();
void bClientCNOP();

// Network setup
OSStatus bOTInit(AppContext *ctx);
OSStatus bTeardown(AppContext *ctx);
OSStatus bDisconnect(AppContext *ctx);
OSStatus bConnect(AppContext *appContext, const char *host);

// serde
OTResult sendBFrame(BFrame *bFrame);
BFrame *bRecv2Frame(unsigned int len, unsigned char *buf);
void bfWriteUInt16(BFrame *bFrame, UInt16 val);
void bfWriteSInt16(BFrame *bFrame, SInt16 val);
void bfWriteString(BFrame *bFrame, char *val);