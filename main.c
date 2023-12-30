#include <Carbon.h>
#include <OpenTransport.h>
#include <stdio.h>
#include <stdlib.h>

#include "context.h"
#include "bevents.h"
#include "ui.h"
#include "utils.h"
#include "barrier.h"

static AppContext *appContext = NULL;

// 

void main(void)
{
	OSStatus err = noErr;
	AppContext appContext = {
		INITIALIZING,
		// OT
		0,
		0,
		0,
		0,
		0,
		// SIOUX
		0,
		// Controls
		0,
		0,
		0,
		0,
		0,
		0
	};
	
	err = bOTInit(&appContext);
	
	if (err != noErr) {
		StandardAlert(
			kAlertStopAlert,
			"\pOpenTransport", 
			"\pUnable to initialize OpenTransport. Cannot continue.",
			NULL,
			NULL
		);
	}
		
	if (err == noErr) {
		uiInit(&appContext);
		eventInit(&appContext);
		appContext.state = DISCONNECTED;
		RunApplicationEventLoop();
		
		if (appContext.bEndpoint) {
			bTeardown(&appContext);
		}
		
		CloseOpenTransportInContext(appContext.otClientContext);
	}
}