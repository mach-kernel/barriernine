#pragma once

#include "context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <Carbon.h>
#include <SIOUX.h>
#include <OpenTransport.h>

// Resources
#define B9_MBAR 128
#define B9_DLOG_CONNECT 128

// Menus
#define B9_APPLE_MENU 1
#define B9_FILE_MENU 2
#define B9_WINDOW_MENU 3

#define B9_APPLE_ABOUT 1
#define B9_FILE_QUIT 1

// Primary dialog items
#define B9_DLOG_OK 1
#define B9_DLOG_SERVER 3
#define B9_DLOG_CNAME 7
#define B9_DLOG_PBAR 4
#define B9_DLOG_STATUSMSG 5

static MenuRef appleMenuHandle = NULL;
static MenuRef fileMenuHandle = NULL;
static MenuRef windowMenuHandle = NULL;

void uiInit(AppContext *ctx);
static WindowRef uiInitSIOUX();
static DialogRef uiInitMainDialog();
static void uiInitMenus();

// Events
void updateWindowMenu(WindowRef window, char activate);
