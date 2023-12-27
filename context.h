#pragma once

#include <Carbon.h>
#include <OpenTransport.h>

typedef enum AppState {
	INITIALIZING,
	DISCONNECTED,
	RESOLVING,
	CONNECTING,
	CONNECTED,
	QUIT
} AppState;

typedef struct AppContext {
	AppState state;

	// OpenTransport stuff
	OTClientContextPtr otClientContext;
	InetSvcRef inetSvc;
	Ptr otXferBuffer;
	EndpointRef bEndpoint;

	// SIOUX.h window
	WindowRef siouxWindow;
	
	// Modeless dialog + controls
	DialogRef mainDialog;
	ControlRef mdConnectBtn;
	Handle mdServerUrl;
	Handle mdClientName;
	ControlRef mdProgBar;
	Handle mdStatusMsg;
} AppContext;