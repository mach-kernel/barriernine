#include "context.h"
#include "barrier.h"
#include "utils.h"

static AppContext *appContext = NULL;

//
// events
//

OTResult handleBFrame(BFrame *bFrame) {
	OTResult lookErr;
	OTResult err = noErr;
	if (!bFrame || !appContext) return err;
	
	// Server hello
	if (!strcmp(bFrame->cmd, "Barrier")) {
		err = bClientHelloBack(bFrame);
	} else if (!strcmp(bFrame->cmd, "QINF")) {
		loggerf(INFO, "barrier: rx QINF");
		err = bClientDINF();
	} else if (!strcmp(bFrame->cmd, "CIAK")) {
		loggerf(INFO, "barrier: rx CIAK");
	} else if (!strcmp(bFrame->cmd, "CALV")) {
		loggerf(TRACE, "barrier: rx CALV");
		err = bClientCALV();
	// TODO
	} else if (!strcmp(bFrame->cmd, "EUNK")) {
		loggerf(INFO, "barrier: rx EUNK");

		StandardAlert(
			kAlertStopAlert,
			"\pUnknown client", 
			"\pServer does not recognize this host, disconnecting. Did you add a screen for this machine?",
			NULL,
			NULL
		);
		bDisconnect(appContext);
		err = kEPERMErr;
	} else if (!strcmp(bFrame->cmd, "DMMV")) {
		err = bClientDMMV(bFrame);
	} else if (!strcmp(bFrame->cmd, "DMDN")) {
		err = bClientDMDNUP(bFrame, true);
	} else if (!strcmp(bFrame->cmd, "DMUP")) {
		err = bClientDMDNUP(bFrame, false);
	}
		
	switch (err) {
		// probably always bad, disconnect
		case kOTLookErr:
			OTLook(&lookErr);
			loggerf(TRACE, "OT EP %p: OTLook err %d", lookErr);
			bDisconnect(appContext);
			break;
		case kOTFlowErr:
			loggerf(TRACE, "OT EP %p: flow control, BFrame %p dropped", bFrame);
			break;
	}
	
	free(bFrame);
	return err;
}

static pascal void bNotifier(
	void *contextPtr,
	OTEventCode code,
	OTResult result,
	void *cookie
) {
	BFrame *bFrame;
	OTFlags junkFlags;
	OTResult err;
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
				
				if (rcv == kOTLookErr) bDisconnect(appContext);
				
				bFrame = bRecv2Frame(rcv, (unsigned char *) appContext->otXferBuffer);
				if (!bFrame) continue;
				err = handleBFrame(bFrame);
			} while (rcv > 0);
			break;
		// flow control
		case T_GODATA:
			loggerf(TRACE, "T_GODATA");
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

OTResult bClientHelloBack(BFrame *bFrameIn) {
	// { major, minor }
	UInt16Tuple *recv;
	Str255 pClientName;
	char *clientName;
	BFrame bFrameOut = newBFrame("Barrier");
	OTResult sent = noErr;
	
	if (bFrameIn->cmdlen < 4) return kOTBadDataErr;
	recv = (UInt16Tuple *) bFrameIn->buf;
	loggerf(INFO, "barrier: hello from server (protocol v%d.%d)", recv->a, recv->b);
	
	GetDialogItemText(appContext->mdClientName, pClientName);
	clientName = pstr2cstr(pClientName);
	
	bfWriteUInt16(&bFrameOut, bMajor);
	bfWriteUInt16(&bFrameOut, bMinor);
	bfWriteString(&bFrameOut, clientName);
	
	return sendBFrame(&bFrameOut);
}

OTResult bClientCALV() {
	BFrame bFrameOut = newBFrame("CALV");
	loggerf(TRACE, "barrier: tx CALV");
	return sendBFrame(&bFrameOut);
}

OTResult bClientCNOP() {
	BFrame bFrameOut = newBFrame("CNOP");
	loggerf(TRACE, "barrier: tx CNOP");
	return sendBFrame(&bFrameOut);
}

OTResult bClientDINF() {
	BFrame bFrameOut = newBFrame("DINF");

	UInt16 xOrigin = 0;
	UInt16 yOrigin = 0;
	UInt16 mx = 0;
	UInt16 my = 0;
	
	GDHandle mainDevice = GetMainDevice();
	Point mousePoint;
	
	UInt16 width;
	UInt16 height;
	
	GetMouse(&mousePoint);
	width = (*(*mainDevice)->gdPMap)->bounds.right;
	height = (*(*mainDevice)->gdPMap)->bounds.bottom;
	mx = mousePoint.h;
	my = mousePoint.v;
	
	loggerf(INFO, "barrier: tx DINF (o %d,%d %dx%d m %d,%d)", xOrigin, yOrigin, width, height, mx, my, mx, my);

	bfWriteUInt16(&bFrameOut, xOrigin);
	bfWriteUInt16(&bFrameOut, yOrigin);
	bfWriteUInt16(&bFrameOut, width);
	bfWriteUInt16(&bFrameOut, height);
	// ?? reserved
	bfWriteUInt16(&bFrameOut, 0);
	bfWriteUInt16(&bFrameOut, mx);
	bfWriteUInt16(&bFrameOut, my);

	return sendBFrame(&bFrameOut);
}

OTResult bClientDMMV(BFrame *bFrameIn) {
	// { x, y }
	UInt16Tuple *coords = (UInt16Tuple *) bFrameIn->buf;
	
	// pack into int32 yyxx
	unsigned int newMouse = (coords->b << 16) | coords->a;
	
	unsigned int *cInternal = (unsigned int *) MACOS_CURSOR_INT;
	unsigned int *cRaw = (unsigned int *) MACOS_CURSOR_RAW;
	unsigned char *chg = (unsigned char *) MACOS_CURSOR_CHG;
	
	if (coords->a < 0 || coords->b < 0) return;

	if (*cInternal != newMouse) {
		*cInternal = newMouse;
		*cRaw = newMouse;
		*chg = 0xFF;
	}
	
	loggerf(TRACE, "barrier: rx DMMV (%d, %d)", coords->a, coords->b);

	return noErr;
}

OTResult bClientDMDNUP(BFrame *bFrameIn, Boolean down) {
	// TODO: ctrl click?
	// char buttonId = *bFrameIn->buf;
	loggerf(INFO, "barrier: rx DMDN/UP (down: %d)", down);
	PostEvent(down ? mouseDown : mouseUp, 0);
	return noErr;
}

//
// serde
//

BFrame newBFrame(const char *cmd) {
	BFrame newBFrame = {
		// cmdlen
		0,
		// cmd
		{0},
		// buf
		{0}
	};
	size_t cmdstrlen = strlen(cmd);
	memcpy(&newBFrame.cmd, cmd, cmdstrlen > 7 ? 7 : cmdstrlen);
	return newBFrame;
}

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
		result = OTSndDisconnect(appContext->bEndpoint, NULL);
		loggerf(TRACE, "OT EP %p: sending d/c %d", ctx->bEndpoint, result);
		OTCancelSynchronousCalls(ctx->bEndpoint, result);
		loggerf(TRACE, "OT EP %p: cancel sync calls %d", ctx->bEndpoint, result);
		result = OTUnbind(ctx->bEndpoint);
		loggerf(TRACE, "OT EP %p: unbind %d", ctx->bEndpoint, result);
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
		OTCreateConfiguration("tcp(NoDelay=0)"),
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