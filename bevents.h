#include <Carbon.h>

void eventInit(AppContext *appContext);
static void bindSIOUXEvents(WindowRef siouxWindow);
static void bindWindowEvents(WindowRef window);
static void bindMenuEvents(MenuRef menu);
static void bindIdleTimer();

static OSStatus handleControlEvent(EventHandlerCallRef ehcr, EventRef eventRef, void *userData);
static OSStatus handleWindowEvent(EventHandlerCallRef ehcr, EventRef eventRef, void *userData);
static OSStatus handleAppEvent(EventHandlerCallRef ehcr, EventRef eventRef, void *userData);
static OSStatus handleSIOUXEvents(EventHandlerCallRef ehcr, EventRef eventRef, void *userData);
static void handleIdleTick();
/*
for reference, all of the events

static EventTypeSpec windowEvents[] = {
	{ kEventClassWindow, kEventWindowUpdate },
	{ kEventClassWindow, kEventWindowDrawContent },
	{ kEventClassWindow, kEventWindowActivated },
	{ kEventClassWindow, kEventWindowDeactivated },
	{ kEventClassWindow, kEventWindowGetClickActivation },
	{ kEventClassWindow, kEventWindowShown },
	{ kEventClassWindow, kEventWindowHidden },
	{ kEventClassWindow, kEventWindowBoundsChanging },
	{ kEventClassWindow, kEventWindowBoundsChanged },
	{ kEventClassWindow, kEventWindowClickDragRgn },
	{ kEventClassWindow, kEventWindowClickResizeRgn },
	{ kEventClassWindow, kEventWindowClickCollapseRgn },
	{ kEventClassWindow, kEventWindowClickCloseRgn },
	{ kEventClassWindow, kEventWindowClickZoomRgn },
	{ kEventClassWindow, kEventWindowClickContentRgn },
	{ kEventClassWindow, kEventWindowClickProxyIconRgn },
};
*/