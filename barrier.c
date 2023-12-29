#include "context.h"
#include "barrier.h"
#include "utils.h"

static AppContext *appContext = NULL;

//
// events
//

void handleBFrame(BFrame *bFrame) {
	if (!bFrame || !appContext) return;
	
	// Server hello
	if (!strcmp(bFrame->cmd, "Barrier")) {
		bClientHelloBack(bFrame);
	} else if (!strcmp(bFrame->cmd, "QINF")) {
		bClientDINF();
	} else if (!strcmp(bFrame->cmd, "CIAK")) {
		loggerf(TRACE, "barrier: rx CIAK");
	} else if (!strcmp(bFrame->cmd, "CALV")) {
		loggerf(TRACE, "barrier: rx CALV");
		bClientCALV();
	} else if (!strcmp(bFrame->cmd, "EUNK")) {
		loggerf(TRACE, "barrier: rx EUNK");

		StandardAlert(
			kAlertStopAlert,
			"\pUnknown client", 
			"\pServer does not recognize this host, disconnecting. Did you add a screen for this machine?",
			NULL,
			NULL
		);
	} else if (!strcmp(bFrame->cmd, "DMMV")) {
		bClientDMMV(bFrame);
	}
}

void bClientCALV() {
	BFrame bFrameOut = { 0, "CALV", {0} };
	OTResult sent = noErr;
	
	loggerf(TRACE, "barrier: tx CALV");
	sent = sendBFrame(&bFrameOut);
}

void bClientCNOP() {
	BFrame bFrameOut = { 0, "CNOP", {0} };
	OTResult sent = noErr;
	
	loggerf(TRACE, "barrier: tx CNOP");
	sent = sendBFrame(&bFrameOut);
}

void bClientDMMV(BFrame *bFrameIn) {
	// { x, y }
	UInt16Tuple *coords = (UInt16Tuple *) bFrameIn->buf;
	unsigned int newMouse = (coords->b << 16) | coords->a;
	
	// credit: minivmac/MOUSEMDV.c
	unsigned int *mx = (unsigned int *) MACOS_CURSOR_X;
	unsigned int *my = (unsigned int *) MACOS_CURSOR_Y;
	unsigned char *redraw = (unsigned char *) MACOS_CURSOR_DRAW;
	
	*mx = newMouse;
	*my = newMouse;
	*redraw = 0xFF;
	
	loggerf(TRACE, "barrier: rx DMMV (%d, %d)", coords->a, coords->b);
}

void bClientDINF() {
	BFrame bFrameOut = { 0, "DINF", {0} };
	OTResult sent = noErr;

	UInt16 xOrigin = 0;
	UInt16 yOrigin = 0;
	UInt16 mx = 0;
	UInt16 my = 0;
	
	GDHandle mainDevice = GetMainDevice();
	Rect screenRect;
	Point mousePoint;
	
	UInt16 width;
	UInt16 height;
	
	GetMouse(&mousePoint);
	width = (*(*mainDevice)->gdPMap)->bounds.right;
	height = (*(*mainDevice)->gdPMap)->bounds.bottom;
	mx = mousePoint.h;
	my = mousePoint.v;
	
	loggerf(TRACE, "barrier: tx DINF (o %d,%d %dx%d m %d,%d)", xOrigin, yOrigin, width, height, mx, my, mx, my);

	bfWriteUInt16(&bFrameOut, xOrigin);
	bfWriteUInt16(&bFrameOut, yOrigin);
	bfWriteUInt16(&bFrameOut, width);
	bfWriteUInt16(&bFrameOut, height);
	bfWriteUInt16(&bFrameOut, 0);
	bfWriteUInt16(&bFrameOut, mx);
	bfWriteUInt16(&bFrameOut, my);

	sent = sendBFrame(&bFrameOut);
}

void bClientHelloBack(BFrame *bFrameIn) {
	// { major, minor }
	UInt16Tuple *recv;
	Str255 pClientName;
	char *clientName;
	BFrame bFrameOut = { 0, "Barrier", {0} };
	OTResult sent = noErr;
	
	if (bFrameIn->cmdlen < 4) return;
	recv = (UInt16Tuple *) bFrameIn->buf;
	loggerf(TRACE, "barrier: hello from server (protocol v%d.%d)", recv->a, recv->b);
	
	GetDialogItemText(appContext->mdClientName, pClientName);
	clientName = pstr2cstr(pClientName);
	
	bfWriteUInt16(&bFrameOut, bMajor);
	bfWriteUInt16(&bFrameOut, bMinor);
	bfWriteString(&bFrameOut, clientName);
	
	sent = sendBFrame(&bFrameOut);
}

static pascal void bNotifier(
	void *contextPtr,
	OTEventCode code,
	OTResult result,
	void *cookie
) {
	BFrame *bFrame;
	OTFlags junkFlags;
	OSStatus err;
	OTResult rcv;

	loggerf(TRACE, "OT event 0x%08x", code);
	
	switch (code) {
		case T_CONNECT:
			loggerf(TRACE, "T_CONNECT");
			OTRcvConnect(appContext->bEndpoint, NULL);
			appContext->state = CONNECTED;
			break;
		case T_DATA:
			do {
				rcv = OTRcv(appContext->bEndpoint, appContext->otXferBuffer, OT_XFER_BUFSIZE, &junkFlags);
				loggerf(TRACE, "T_DATA OTRcv %d", rcv);
				bFrame = bRecv2Frame(rcv, (unsigned char *) appContext->otXferBuffer);
				if (!bFrame) continue;
				handleBFrame(bFrame);
				free(bFrame);
			} while (rcv > 0);
			break;
		case T_DISCONNECT:
			loggerf(INFO, "Disconnected (T_DISCONNECT)");
			OTRcvDisconnect(appContext->bEndpoint, NULL);
			bDisconnect(appContext);
			break;
		case T_ORDREL:
			loggerf(INFO, "Disconnected (T_ORDREL)");
			err = OTRcvOrderlyDisconnect(appContext->bEndpoint);
			if (err == noErr) OTSndOrderlyDisconnect(appContext->bEndpoint);
			bDisconnect(appContext);
			break;
	}
}

//
// serde
//

OTResult sendBFrame(BFrame *bFrame) {
	OTResult err;
	UInt32 plen = 0;
	unsigned char *buf, *bump;
	size_t sent = 0;
	
	if (!bFrame) return kEINVALErr;
	
	// int32 len, cmd, ...
	plen += strlen(bFrame->cmd);
	plen += bFrame->cmdlen;
	
	buf = calloc(plen, sizeof(char));
	bump = buf;
	
	// payload length
	memcpy(bump, &plen, sizeof(UInt32));
	bump += sizeof(UInt32);
	// note: the payload length as sent does _not_ include the payload
	// integer, but we need to know how much we're sending below!
	plen += 4;
	
	// command
	memcpy(bump, &bFrame->cmd[0], strlen(&bFrame->cmd[0]));
	bump += strlen(&bFrame->cmd[0]);
	
	// payload
	memcpy(bump, &bFrame->buf[0], bFrame->cmdlen);
	
	bump = buf;
	
	do {
		err = OTSnd(appContext->bEndpoint, bump, (size_t) plen-sent, 0);
		loggerf(TRACE, "OT EP %p: sent %d", appContext->bEndpoint, err);
		if (err > 0) {
			sent += err;
			bump += err;
		}
	} while ((err > 0) && ((plen-sent) > 0));

	if (buf) free(buf);
	return err < 0 ? err : sent;
}

BFrame *bRecv2Frame(unsigned int len, unsigned char *buf) {
	BFrame *bFrame;
	char *commandName;
	UInt32 plen;
	UInt32 cmdlen;
	
	// Must be able to read payload len
	if (len < 4 || len > BFRAME_BUFSIZE) return NULL;
	memcpy(&plen, buf, sizeof(UInt32));
	buf += sizeof(UInt32);
	
	cmdlen = plen;
	
	commandName = calloc(1, sizeof("Barrier"));
	
	// Read 4 byte command
	memcpy(commandName, buf, 4);
	if (!strcmp(commandName, "Barr")) {
		memcpy(commandName, buf, sizeof("Barrier") - 1);
		if (strcmp(commandName, "Barrier")) return NULL;
		buf += sizeof("Barrier") - 1;
		cmdlen -= sizeof("Barrier") - 1;
	} else {
		buf += 4;
		cmdlen -= 4;
	}
	
	if (strlen(commandName) > 7) return NULL;
	loggerf(TRACE, "barrier: recv %d bytes; %s (+%d bytes)", plen, commandName, cmdlen);
	
	bFrame = calloc(1, sizeof(BFrame));
	bFrame->cmdlen = cmdlen;
	memcpy(&bFrame->cmd[0], commandName, strlen(commandName));
	memcpy(&bFrame->buf[0], buf, cmdlen);
	free(commandName);
	
	return bFrame;
}

void bfWriteUInt16(BFrame *bFrame, UInt16 val) {
	if ((bFrame->cmdlen > BFRAME_BUFSIZE) || 
	    (bFrame->cmdlen+4 > BFRAME_BUFSIZE)) return;
	
	memcpy(&bFrame->buf[bFrame->cmdlen], &val, sizeof(UInt16));
	bFrame->cmdlen += sizeof(UInt16);
}

void bfWriteSInt16(BFrame *bFrame, SInt16 val) {
	if ((bFrame->cmdlen > BFRAME_BUFSIZE) || 
	    (bFrame->cmdlen+4 > BFRAME_BUFSIZE)) return;
	
	memcpy(&bFrame->buf[bFrame->cmdlen], &val, sizeof(SInt16));
	bFrame->cmdlen += sizeof(SInt16);
}

// uint32 strlen, ...str
void bfWriteString(BFrame *bFrame, char *val) {
	UInt32 vlen;
	if (!val) return;
	vlen = strlen(val);
	
	if ((bFrame->cmdlen > BFRAME_BUFSIZE) || 
	    (bFrame->cmdlen+vlen+sizeof(UInt32) > BFRAME_BUFSIZE)) return;
	
	memcpy(&bFrame->buf[bFrame->cmdlen], &vlen, sizeof(UInt32));
	bFrame->cmdlen += sizeof(UInt32);
	memcpy(&bFrame->buf[bFrame->cmdlen], val, vlen);
	bFrame->cmdlen += vlen;
}

//
// Network setup
//

// Initialize OpenTransport and bind to context
OSStatus bOTInit(AppContext *ctx) {
	OSStatus err = InitOpenTransportInContext(
		kInitOTForApplicationMask, 
		&ctx->otClientContext
	);

	loggerf(TRACE, "OpenTransport client context %p", appContext->otClientContext);
	ctx->inetSvc = OTOpenInternetServicesInContext(
		kDefaultInternetServicesPath,
		0,
		&err,
		ctx->otClientContext
	);
	
	return err;
}

OSStatus bTeardown(AppContext *ctx) {
	OSStatus result = noErr;
	if (!ctx) return result;
	
	bDisconnect(ctx);
	if (ctx->inetSvc != kOTInvalidEndpointRef) {
		result = OTCloseProvider(ctx->inetSvc);
		loggerf(TRACE, "OT InetSvc %p: closing provider %d", ctx->inetSvc, result);
	}
	
	ctx->state = DISCONNECTED;
	ctx->bEndpoint = NULL;
	ctx->otXferBuffer = NULL;
	ctx->inetSvc = NULL;
	
	if (appContext) appContext = NULL;
	
	return result;
}

OSStatus bDisconnect(AppContext *ctx) {
	OSStatus result = noErr;
	if (!ctx) return result;
	if (!(ctx->state == CONNECTING || ctx->state == CONNECTED)) return result;
	
	if (ctx->bEndpoint && ctx->bEndpoint != kOTInvalidEndpointRef) {
		result = OTUnbind(ctx->bEndpoint);
		loggerf(TRACE, "OT EP %p: unbound %d", ctx->bEndpoint, result);
		
		result = OTCloseProvider(ctx->bEndpoint);
		loggerf(TRACE, "OT EP %p: closing provider %d", ctx->bEndpoint, result);
	}
	
	if (ctx->otXferBuffer) {
		OTFreeMem(ctx->otXferBuffer);
		loggerf(TRACE, "OT xfer buf %p: freed", ctx->otXferBuffer);
	}
	
	ctx->state = DISCONNECTED;
	ctx->bEndpoint = NULL;
	ctx->otXferBuffer = NULL;
	
	if (appContext) appContext = NULL;
	return result;
}

OSStatus bConnect(AppContext *ctx, const char *host) {
	OSStatus err = noErr;
	TCall sndCall;
	DNSAddress hostDNSAddress;
	OTNotifyUPP notifyPP;
	
	appContext = ctx;
	loggerf(INFO, "Attempting connection to %s", host);
	
	if (appContext->state != DISCONNECTED) return kEINVALErr;
	appContext->state = CONNECTING;
	
	appContext->otXferBuffer = OTAllocMemInContext(OT_XFER_BUFSIZE, appContext->otClientContext);
	if (!appContext->otXferBuffer) return kENOMEMErr;
	loggerf(TRACE, "OT xfer buf %p: alloc %db", appContext->otXferBuffer, OT_XFER_BUFSIZE);

	appContext->bEndpoint = OTOpenEndpointInContext(
		OTCreateConfiguration("tcp(NoDelay=1)"),
		0,
		NULL, 
		&err,
		appContext->otClientContext
	);
	loggerf(TRACE, "OT EP %p: open %d", appContext->bEndpoint, err);
	
	// Do setup synchronously
	err = OTSetSynchronous(appContext->bEndpoint);
	err = OTSetBlocking(appContext->bEndpoint);
	if (err) return err;
	
	// Install notifier & bind endpoint
	notifyPP = NewOTNotifyUPP(bNotifier);
	err = OTInstallNotifier(appContext->bEndpoint, notifyPP, NULL);
	loggerf(TRACE, "OT EP %p: notify UPP %p bound", appContext->bEndpoint, notifyPP);
	if (err) return err;
	
	err = OTBind(appContext->bEndpoint, NULL, &appContext->bEndpointBind);
	loggerf(TRACE, "OT EP %p: bound", appContext->bEndpoint);
	if (err) return err;
	
	// Resolve target host or IP
	appContext->state = RESOLVING;
	OTMemzero(&sndCall, sizeof(TCall));
	sndCall.addr.buf = (UInt8 *) &hostDNSAddress;
	sndCall.addr.len = OTInitDNSAddress(&hostDNSAddress, (char *) host);
	appContext->state = CONNECTING;
	
	// Use notifier events moving forward, including further
	// connect handling
	err = OTSetAsynchronous(appContext->bEndpoint);
	if (err) return err;
	
	// It's ok, it should give kOTNoDataErr
	err = OTConnect(appContext->bEndpoint, &sndCall, NULL);
	loggerf(INFO, "OT EP %p: connect %d", appContext->bEndpoint, err);
	
	return err == kOTNoDataErr ? noErr : err;
}