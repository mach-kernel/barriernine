#include "context.h"
#include "barrier.h"
#include "utils.h"

static AppContext *appContext = NULL;

//
// events
//

void handleBFrame(BFrame *bFrame) {
	if (!bFrame || !appContext) return;
	
	OTEnterNotifier(appContext->bEndpoint);
	
	// Server hello
	if (!strcmp(bFrame->cmd, "Barrier")) {
		bClientHelloBack(bFrame);
	}
	
	OTLeaveNotifier(appContext->bEndpoint);
}

void bClientHelloBack(BFrame *bFrameIn) {
	BCmdHello *recv;
	Str255 pClientName;
	char *clientName;
	BFrame bFrameOut = { 0, "Barrier", {0} };
	OTResult sent;
	UInt32 slen = 0;
	
	if (bFrameIn->cmdlen < 4) return;
	recv = (BCmdHello *) bFrameIn->buf;
	loggerf(TRACE, "barrier: hello from server (protocol v%d.%d)", recv->major, recv->minor);
	
	GetDialogItemText(appContext->mdClientName, pClientName);
	clientName = pstr2cstr(pClientName);
	
	bfWriteUInt16(&bFrameOut, bMajor);
	bfWriteUInt16(&bFrameOut, bMinor);
	bfWriteString(&bFrameOut, clientName);
	
	sent = sendBFrame(&bFrameOut);
	loggerf(TRACE, "OT Sent: %d", sent);
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
				loggerf(TRACE, "T_DATA Recv %d (bytes/err)", rcv);
				bFrame = bRecv2Frame(rcv, (unsigned char *) appContext->otXferBuffer);
				if (bFrame) handleBFrame(bFrame);
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
	
	if (!bFrame) return kEINVALErr;
	
	// int32 len, cmd, ...
	plen += sizeof(UInt32);
	plen += strlen(bFrame->cmd);
	plen += bFrame->cmdlen;
	
	buf = calloc(plen, sizeof(char));
	bump = buf;
	
	memcpy(bump, &plen, sizeof(UInt32));
	bump += sizeof(UInt32);
	
	memcpy(bump, &bFrame->cmd[0], strlen(&bFrame->cmd[0]));
	bump += strlen(&bFrame->cmd[0]);
	
	memcpy(bump, &bFrame->buf[0], bFrame->cmdlen);
	
	err = OTSnd(appContext->bEndpoint, buf, plen, 0);
	if (buf) free(buf);
	return err;
}

BFrame *bRecv2Frame(unsigned int len, unsigned char *buf) {
	BFrame *bFrame;
	char *commandName;
	UInt32 plen;
	UInt32 cmdlen;
	
	// Must be able to read payload len
	if (len < 4 || len > BFRAME_BUFSIZE) return NULL;
	memcpy(&plen, buf, sizeof(UInt32));
	cmdlen = plen;

	buf += sizeof(UInt32);
	
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
	loggerf(TRACE, "barrier: recv %d bytes; %s (%d bytes)", plen, commandName, cmdlen);
	
	bFrame = calloc(1, sizeof(BFrame));
	bFrame->cmdlen = cmdlen;
	memcpy(&bFrame->cmd[0], commandName, strlen(commandName));
	memcpy(&bFrame->buf[0], buf, cmdlen);
	
	return bFrame;
}

void bfWriteUInt16(BFrame *bFrame, UInt16 val) {
	if ((bFrame->cmdlen > BFRAME_BUFSIZE) || 
	    (bFrame->cmdlen+4 > BFRAME_BUFSIZE)) return;
	
	memcpy(&bFrame->buf[bFrame->cmdlen], &val, sizeof(UInt16));
	bFrame->cmdlen += sizeof(UInt16);
}

void bfWriteString(BFrame *bFrame, char *val) {
	size_t vlen;
	if (!val) return;
	vlen = strlen(val);
	
	if ((bFrame->cmdlen > BFRAME_BUFSIZE) || 
	    (bFrame->cmdlen+vlen > BFRAME_BUFSIZE)) return;
	    
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
		OTCreateConfiguration(kTCPName),
		0,
		NULL, 
		&err,
		appContext->otClientContext
	);
	loggerf(TRACE, "OT EP %p: open %d", appContext->bEndpoint, err);
	
	// Do setup synchronously
	OTSetSynchronous(appContext->bEndpoint);
	OTSetBlocking(appContext->bEndpoint);
	
	// Install notifier & bind endpoint
	notifyPP = NewOTNotifyUPP(bNotifier);
	OTInstallNotifier(appContext->bEndpoint, notifyPP, NULL);
	loggerf(TRACE, "OT EP %p: notifier proc %p bound", appContext->bEndpoint, notifyPP);
	OTBind(appContext->bEndpoint, NULL, NULL);
	loggerf(TRACE, "OT EP %p: bound", appContext->bEndpoint);
	
	// Resolve target host or IP
	appContext->state = RESOLVING;
	OTMemzero(&sndCall, sizeof(TCall));
	sndCall.addr.buf = (UInt8 *) &hostDNSAddress;
	sndCall.addr.len = OTInitDNSAddress(&hostDNSAddress, (char *) host);
	appContext->state = CONNECTING;
	
	// Use notifier events moving forward, including further
	// connect handling
	OTSetAsynchronous(appContext->bEndpoint);
	
	// It's ok, it should give kOTNoDataErr
	err = OTConnect(appContext->bEndpoint, &sndCall, NULL);
	loggerf(INFO, "OT EP %p: connect %d", appContext->bEndpoint, err);
	
	return noErr;
}