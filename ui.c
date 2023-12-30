#include "ui.h"#include "utils.h"void uiInit(AppContext *ctx) {	OSStatus hostQueryErr;	InetDomainName localhostDomain;	InetHost localhost;	Boolean boolOn = true;	if (!ctx) return;		InitCursor();		// Make windows	ctx->siouxWindow = uiInitSIOUX();	ctx->mainDialog = uiInitMainDialog();		// Find controls	GetDialogItemAsControl(ctx->mainDialog, B9_DLOG_OK, &ctx->mdConnectBtn);	GetDialogItem(ctx->mainDialog, B9_DLOG_SERVER, NULL, &ctx->mdServerUrl, NULL);	GetDialogItem(ctx->mainDialog, B9_DLOG_CNAME, NULL, &ctx->mdClientName, NULL);	GetDialogItemAsControl(ctx->mainDialog, B9_DLOG_PBAR, &ctx->mdProgBar);	GetDialogItem(ctx->mainDialog, B9_DLOG_STATUSMSG, NULL, &ctx->mdStatusMsg, NULL);		// Make connect button a primary button	SetControlData(		ctx->mdConnectBtn,		kControlEntireControl,		kControlPushButtonDefaultTag,		sizeof(boolOn),		&boolOn	);	// Make progress bar indeterminate	SetControlData(		ctx->mdProgBar,		kControlEntireControl,		kControlProgressBarIndeterminateTag,		sizeof(boolOn),		&boolOn	);		// Try to infer the current hostname using internet services	// TODO: I thought this gave us the configured DHCP hostname, but just does	// localhost.default.fqdn	hostQueryErr = OTInetStringToHost("127.0.0.1", &localhost);	if (hostQueryErr == noErr) 		hostQueryErr = OTInetAddressToName(ctx->inetSvc, localhost, localhostDomain);			if (hostQueryErr == noErr) {		loggerf(INFO, "OT InetSvc: hostname is %#s", cstr2pstr(&localhostDomain[0]));		SetDialogItemText(ctx->mdClientName, (const unsigned char*) cstr2pstr(&localhostDomain[0]));	} else {		loggerf(INFO, "OT InetSvc: unable to determine hostname (is this thing on?)");		SetDialogItemText(ctx->mdClientName, "\pbnine");	}	uiInitMenus();	ctx->appleMenu = appleMenuHandle;}static WindowRef uiInitSIOUX() {	WindowRef siouxWindow;	SIOUXSettings.asktosaveonclose = true;	SIOUXSettings.autocloseonquit = false;	SIOUXSettings.showstatusline = false;	SIOUXSettings.standalone = false;	SIOUXSettings.setupmenus = false;	SIOUXSettings.initializeTB = false;	SIOUXSettings.toppixel = 45;	SIOUXSettings.leftpixel = 10;		// TODO: This is functional in the sense that I need the window 	// to appear and this is the only way I know how	loggerf(TRACE, "SIOUX configured");	siouxWindow = FrontWindow();	ChangeWindowAttributes(siouxWindow, 0, kWindowResizableAttribute);	// Bind standard handler	ChangeWindowAttributes(siouxWindow, kWindowStandardHandlerAttribute, 0);	// TODO	// ChangeWindowAttributes(siouxWindow, kWindowCloseBoxAttribute, 0);	SetWTitle(siouxWindow, "\pbarriernine.log");	return siouxWindow;}static void uiInitMenus() {	MenuBarHandle menubarHandle = GetNewMBar(B9_MBAR);	WindowRef current;	Str255 windowTitle;	// Set menu bar handle (needed for subsequent calls)	SetMenuBar(menubarHandle);		// Bind menu handles	appleMenuHandle = GetMenuRef(B9_APPLE_MENU);	fileMenuHandle = GetMenuRef(B9_FILE_MENU);	windowMenuHandle = GetMenuRef(B9_WINDOW_MENU);		// Set quit command to something recognizable by the	// Quit Command "Apple Event" handler	SetMenuItemCommandID(fileMenuHandle, B9_FILE_QUIT, kHICommandQuit);		// Add windows to window menu	current = GetWindowList();	while (current) {		GetWTitle(current, windowTitle);		AppendMenuItemText(windowMenuHandle, windowTitle);		current = GetNextWindow(current);	}	DrawMenuBar();}static DialogRef uiInitMainDialog() {	DialogRef mainDialog;	// Spawn connect dialog on top (-1)	mainDialog = GetNewDialog(B9_DLOG_CONNECT, NULL, (WindowRef) -1);	// Bind standard handler, no zoom	ChangeWindowAttributes((WindowRef) mainDialog, kWindowStandardHandlerAttribute, 0);	ChangeWindowAttributes((WindowRef) mainDialog, 0, kWindowFullZoomAttribute);	DrawDialog(mainDialog);	return mainDialog;}void updateWindowMenu(WindowRef window, char activate) {	int i;	Str255 menuText, windowTitle;	GetWTitle(window, windowTitle);	for (i=0; i<= CountMenuItems(windowMenuHandle); ++i) {		GetMenuItemText(windowMenuHandle, i, menuText);		if (!pstrcmp(menuText, windowTitle)) {			CheckMenuItem(windowMenuHandle, i, activate);		}	}}