#include <Carbon.h>
#include <OpenTransport.h>
#include <stdio.h>
#include <stdlib.h>

#include "context.h"
#include "events.h"
#include "ui.h"
#include "utils.h"
#include "barrier.h"

static AppContext *appContext = NULL;

// MoreMasterPointers(64);

void main(void)
{
	appContext = calloc(1, sizeof(AppContext));
	// Some OpenTransport calls take a while
	appContext->state = INITIALIZING;
	
	if (bOTInit(appContext) != noErr) {
		StandardAlert(
			kAlertStopAlert,
			"\pOpenTransport", 
			"\pUnable to initialize OpenTransport. Cannot continue.",
			NULL,
			NULL
		);
		return;
	}
		
	uiInit(appContext);
	eventInit(appContext);

	appContext->state = DISCONNECTED;
	
	RunApplicationEventLoop();
	
	if (appContext && appContext->bEndpoint) {
		bTeardown(appContext);
	}
	
	CloseOpenTransportInContext(appContext->otClientContext);
	free(appContext);
}