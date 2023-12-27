#include "context.h"
#include "events.h"
#include "ui.h"
#include "utils.h"
#include "barrier.h"

static AppContext *appContext;

static EventTypeSpec windowEvents[] = {
	{ kEventClassWindow, kEventWindowUpdate },
	{ kEventClassWindow, kEventWindowActivated },
	{ kEventClassWindow, kEventWindowDeactivated },
	{ kEventClassWindow, kEventWindowDrawContent },
	{ kEventClassControl, kEventControlHit },
	{ kEventClassKeyboard, kEventRawKeyDown },
	{ kEventClassCommand, kEventProcessCommand }
};

// If you BYO event loop, you need to make a default handler that
// forwards events to SIOUX (e.g. so we don't have to handle scrolling)
static EventTypeSpec siouxEvents[] = {
	{ kEventClassWindow, kEventWindowUpdate },
	{ kEventClassMouse, kEventMouseDown }
};

void eventInit(AppContext *ctx) {
	if (!ctx) return;

	bindSIOUXEvents(ctx->siouxWindow);
	bindWindowEvents((WindowRef) ctx->mainDialog);
	bindWindowEvents(ctx->siouxWindow);
	bindIdleTimer();
	appContext = ctx;
}

static void bindIdleTimer() {
	EventLoopTimerUPP eventLoopTimerUPP = NewEventLoopTimerUPP((EventLoopTimerProcPtr) handleIdleTick);
	InstallEventLoopTimer(
		GetCurrentEventLoop(),
		0,
		TicksToEventTime(GetCaretTime()),
		eventLoopTimerUPP,
		NULL,
		NULL
	);
}

static void handleIdleTick() {
	if (FrontWindow() == GetDialogWindow(appContext->mainDialog)) {
		IdleControls(GetDialogWindow(appContext->mainDialog));
	}
	
	if (!appContext) return;
	
	switch (appContext->state) {
		case INITIALIZING:
			SetDialogItemText(appContext->mdStatusMsg, "\pInitializing...");
			ShowControl(appContext->mdProgBar);
			break;
		case DISCONNECTED:
			SetDialogItemText(appContext->mdStatusMsg, "\pDisconnected");
			HideControl(appContext->mdProgBar);
			ActivateControl(appContext->mdConnectBtn);
			break;
		case CONNECTING:
			SetDialogItemText(appContext->mdStatusMsg, "\pConnecting...");
			ShowControl(appContext->mdProgBar);
			DeactivateControl(appContext->mdConnectBtn);
			break;
		case CONNECTED:
			SetDialogItemText(appContext->mdStatusMsg, "\pConnected!");
			HideControl(appContext->mdProgBar);
			DeactivateControl(appContext->mdConnectBtn);
			break;
		case RESOLVING:
			SetDialogItemText(appContext->mdStatusMsg, "\pResolving host...");
			break;
	}

}

static void bindWindowEvents(WindowRef window) {
	InstallWindowEventHandler(
		window,
		NewEventHandlerUPP((EventHandlerProcPtr) handleAppEvent), 
		GetEventTypeCount(windowEvents),
		windowEvents,
		0,
		NULL
	);
}

static void bindSIOUXEvents(WindowRef siouxWindow) {
	InstallWindowEventHandler(
		siouxWindow,
		NewEventHandlerUPP((EventHandlerProcPtr) handleSIOUXEvents), 
		GetEventTypeCount(siouxEvents),
		siouxEvents,
		0,
		NULL
	);
}

static OSStatus handleAppEvent(EventHandlerCallRef ehcr, EventRef eventRef, void *userData) {
	OSStatus resultStatus;
	EventRecord eventRecord;
	short hit;
	HICommand hiCommand;
	ConvertEventRefToEventRecord(eventRef, &eventRecord);
	
	// Feed dialog events so controls etc work
	if (IsDialogEvent(&eventRecord) && \
		// We're not interested in the hit since we get it as kEventControlHit,
		// but passing NULL for hit will cause the event loop to do nothing
		DialogSelect(&eventRecord, &appContext->mainDialog, &hit)) {
		return noErr;
	}
	
	switch (GetEventClass(eventRef)) {
		case kEventClassWindow:
			resultStatus = handleWindowEvent(ehcr, eventRef, userData);
			break;
		case kEventClassControl:
			resultStatus = handleControlEvent(ehcr, eventRef, userData);
			break;
		case kEventClassCommand:
			GetEventParameter(eventRef,kEventParamDirectObject,typeHICommand,NULL,sizeof(HICommand),NULL,&hiCommand);
			if (hiCommand.commandID == kHICommandQuit) {
				appContext->state = QUIT;
				QuitApplicationEventLoop();
			}
			break;
		default:
			resultStatus = eventNotHandledErr;
	}
	
	CallNextEventHandler(ehcr, eventRef);
	
	return resultStatus;
}

static OSStatus handleControlEvent(EventHandlerCallRef ehcr, EventRef eventRef, void *userData) {
	OSStatus status = noErr;
	UInt32 eventKind = GetEventKind(eventRef);
	ControlRef hit;
	Str255 stext;
	loggerf(TRACE, "kEventClassControl (kind %i)", eventKind);
	
	switch (eventKind) {
		case kEventControlHit:
			GetEventParameter(
				eventRef,
				kEventParamDirectObject,
				typeControlRef,
				NULL,
				sizeof(ControlRef),
				NULL,
				&hit
			);
			// Handle connect button
			if (hit == appContext->mdConnectBtn) {
				GetDialogItemText(appContext->mdServerUrl, stext);
				
				if (!stext || stext[0] == 0) {
					StandardAlert(
						kAlertStopAlert,
						"\pInvalid server", 
						"\pThe server is blank or invalid. Specify a server in the scheme of host.fqdn:port",
						NULL,
						NULL
					);
					break;
				}
				
				bConnect(appContext, pstr2cstr(stext));
			}
			break;
		default:
			status = eventNotHandledErr;
	}
	return status;
}

static OSStatus handleWindowEvent(EventHandlerCallRef ehcr, EventRef eventRef, void *userData) {
	OSStatus result = noErr;
	EventRecord eventRecord;
	UInt32 eventKind = GetEventKind(eventRef);
	WindowRef eventWindow;
	DialogRef eventDialog;
	Str255 eventWindowTitle;

	ConvertEventRefToEventRecord(eventRef, &eventRecord);

	GetEventParameter(
		eventRef,
		kEventParamDirectObject,
		typeWindowRef,
		NULL,
		sizeof(eventWindow),
		NULL,
		&eventWindow
	);
	
	eventDialog = GetDialogFromWindow(eventWindow);
	GetWTitle(eventWindow, eventWindowTitle);

	loggerf(TRACE, "kEventClassWindow (kind %i) - %#s", eventKind, eventWindowTitle);
	
	switch (eventKind) {
		case kEventWindowActivated:
			updateWindowMenu(eventWindow, true);
			break;
		case kEventWindowDeactivated:
			updateWindowMenu(eventWindow, false);
			break;
		default:
			result = eventNotHandledErr;
	}

	return result;
}

// Feeds SIOUXHandleOneEvent and delegates to next listener.
static OSStatus handleSIOUXEvents(EventHandlerCallRef ehcr, EventRef eventRef, void *userData) {
	EventRecord eventRecord;
	ConvertEventRefToEventRecord(eventRef, &eventRecord);
	SIOUXHandleOneEvent(&eventRecord);
	CallNextEventHandler(ehcr, eventRef);
	return noErr;
}