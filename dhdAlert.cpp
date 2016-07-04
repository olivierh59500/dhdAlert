/*
 * dhdAlert -- is a win32 keylogger, that records and logs suspicious 
 * keypresses. The record process is started by an activation of the 
 * windows run command (Windows Key + R) or an unhumanly fast typespeed 
 * above 300 wpm. 
 * Computers naturaly trust keyboards and their input, because they 
 * usualy come from a trusted user. Someone with prolonged physical 
 * access to the computer. In recent years, hardware has emerged that
 * looks like ordinary USB drives, but hides a keyboard chip and a 
 * mini processor to run scripts on said keyboard hardware.
 * This hardware, for example Teensy or USB Rubber Duck, is used to 
 * run malicious scripts in a very small amount of time. By simply 
 * pluggin it in, the scripts usualy start a windows run command and
 * secure a payload within seconds. Since they look like ordinary USB
 * drives, users often mistakenly plug them in themselves, to find out 
 * who the drive belongs to using it's contents. Even if the user 
 * identifies the windows popping up as scripts running and not a failed 
 * autostart, the script probably cleaned up after itself, making it hard
 * to find out what the payload was and how to revert the script.
 * dhdAlert is designed to help notice a security breach caused by such 
 * hardware and identify the payload that was retreived. dhdAlert can
 * run smoothly in the background, until it is needed and should be run
 * during the autostart of the computer. This makes sure it is running
 * when the attack happens. - Works with english and german keyboard
 * settings.s
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public 
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <fstream>
#include <iostream>
#include <string>
#include <windows.h>
#include <direct.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <vector>
#include <gdiplus.h>
#include <tchar.h>
#include <Windowsx.h>
#include <commctrl.h>
#include <Shellapi.h>
#include <Shlwapi.h>


#include "dhdres.h"

using namespace std;

#define OBSTRUCT_CMD 1 /* Calls the MessageBox's to obstruct commands (stop payloads)
						  and notify the user of security breaches. 					*/
#define DETECT_KPS 1   /* If detecting the run command is enough for you or you use 
						  keyboad macros regularly, this should be turned off, to 
						  prevent false positives.                                      */

#define OUTFILE_NAME	"dhdAlert.log"	/* Output file name */
#define CLASSNAME	"dhdAlert"
#define WINDOWTITLE	"dhd"

#define SWM_TRAYMSG	WM_APP//		the message ID sent to our window
#define SWM_SHOW	WM_APP + 1//	show the window
#define SWM_HIDE	WM_APP + 2//	hide the window
#define SWM_EXIT	WM_APP + 3//	close the window
#define SWM_LOG		WM_APP + 4//	Opens the log file.
#define TRAY_ICON_ID 1

/* Scope identification, not used well in this project. */
#define internal static
#define local_persist static
#define global_variable static

#if DETECT_KPS
#define KPS 25 /* 300 wpm *5kpw = 1500 kpm => 25 kps */
float keyCounter; /* counts keys per second. */
vector<string> keyBuffer; /* Remebers last keypresses for logging purposes. */
#endif 

#define GetCurrentDir _getcwd
global_variable char cCurrentPath[FILENAME_MAX];
global_variable HHOOK	kbdhook;	/* Keyboard hook handle */
global_variable bool	running;	/* Used in main loop */
global_variable bool 	recording; /* true when keylogging is in process */
global_variable bool recordingKPS; /* true when keylogging is in process due to KPS. */
global_variable bool capslock = false;
global_variable bool shift = false;
global_variable bool rightshift = false;	
global_variable bool alt = false;
global_variable bool altgr = false;
global_variable bool ctrl = false;
global_variable bool rightctrl = false;
global_variable bool win = false;
global_variable int newlogs = 0;

HWND		hwnd; /* window */
HINSTANCE hInst;
NOTIFYICONDATA	niData;	

// Get dll version number. Helper used for initializing tray icon.
ULONGLONG GetDllVersion(LPCTSTR lpszDllName)
{
    ULONGLONG ullVersion = 0;
	HINSTANCE hinstDll;
    hinstDll = LoadLibrary(lpszDllName);
    if(hinstDll)
    {
        DLLGETVERSIONPROC pDllGetVersion;
        pDllGetVersion = (DLLGETVERSIONPROC)GetProcAddress(hinstDll, "DllGetVersion");
        if(pDllGetVersion)
        {
            DLLVERSIONINFO dvi;
            HRESULT hr;
            ZeroMemory(&dvi, sizeof(dvi));
            dvi.cbSize = sizeof(dvi);
            hr = (*pDllGetVersion)(&dvi);
            if(SUCCEEDED(hr))
				ullVersion = MAKEDLLVERULL(dvi.dwMajorVersion, dvi.dwMinorVersion,0,0);
        }
        FreeLibrary(hinstDll);
    }
    return ullVersion;
}

//	Initialize the window and tray icon
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	// prepare for XP style controls
	InitCommonControls();

	 // store instance handle and create dialog
	hInst = hInstance;
	HWND hWnd = hwnd;
	if (!hWnd) return FALSE;

	// Fill the NOTIFYICONDATA structure and call Shell_NotifyIcon

	// zero the structure - note:	Some Windows funtions require this but
	//								I can't be bothered which ones do and
	//								which ones don't.
	ZeroMemory(&niData,sizeof(NOTIFYICONDATA));

	// get Shell32 version number and set the size of the structure
	//		note:	the MSDN documentation about this is a little
	//				dubious and I'm not at all sure if the method
	//				bellow is correct
	ULONGLONG ullVersion = GetDllVersion(_T("Shell32.dll"));
	if(ullVersion >= MAKEDLLVERULL(5, 0,0,0))
		niData.cbSize = sizeof(NOTIFYICONDATA);
	else niData.cbSize = NOTIFYICONDATA_V2_SIZE;

	// the ID number can be anything you choose
	niData.uID = TRAY_ICON_ID;

	// state which structure members are valid
	niData.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;

	// load the icon
	niData.hIcon = (HICON)LoadImage(hInstance,MAKEINTRESOURCE(IDR_ICO),
		IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),GetSystemMetrics(SM_CYSMICON),
		LR_DEFAULTCOLOR);

	// the window to send messages to and the message to send
	//		note:	the message value should be in the
	//				range of WM_APP through 0xBFFF
	niData.hWnd = hWnd;
    niData.uCallbackMessage = SWM_TRAYMSG;

	// tooltip message
    lstrcpyn(niData.szTip, _T("dhdAlert is up and running..."), sizeof(niData.szTip)/sizeof(TCHAR));

	Shell_NotifyIcon(NIM_ADD,&niData);

	// free icon handle
	if(niData.hIcon && DestroyIcon(niData.hIcon))
		niData.hIcon = NULL;

	// call ShowWindow here to make the dialog initially visible

	return TRUE;
}

// Shows context menue in System Tray
void ShowContextMenu(HWND hWnd)
{
	POINT pt;
	GetCursorPos(&pt);
	HMENU hMenu = CreatePopupMenu();
	if(hMenu)
	{
		string detections = "No New Detections";
		if( newlogs == 1 ){
			detections = "1 New Detections -> Show Log";
		} else if( newlogs > 1 ){
			detections = to_string(newlogs) + " New Detections -> Show Log";
		}
		InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_LOG, detections.c_str());
		if( IsWindowVisible(hWnd) )
			InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_HIDE, _T("Hide"));
		else
			InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_SHOW, _T("Show"));
		InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_EXIT, _T("Exit"));

		// note:	must set window to the foreground or the
		//			menu won't disappear when it should
		SetForegroundWindow(hWnd);

		TrackPopupMenu(hMenu, TPM_BOTTOMALIGN,
			pt.x, pt.y, 0, hWnd, NULL );
		DestroyMenu(hMenu);
	}
}


// Get current date/time, format is YYYY-MM-DD HH:mm:ss
const std::string currentDateTime() {
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);

    return buf;
}

// Shows the window on screen, depending on its current state.
void show(HWND hwnd)
{
    WINDOWPLACEMENT place;
    memset(&place, 0, sizeof(WINDOWPLACEMENT));
    place.length = sizeof(WINDOWPLACEMENT);
    GetWindowPlacement(hwnd, &place);

    switch (place.showCmd)
    {
    case SW_SHOWMAXIMIZED:
        ShowWindow(hwnd, SW_SHOWMAXIMIZED);
        break;
    case SW_SHOWMINIMIZED:
        ShowWindow(hwnd, SW_RESTORE);
        break;
    default:
        ShowWindow(hwnd, SW_NORMAL);
        break;
    }

    SetForegroundWindow(hwnd);
}

#if OBSTRUCT_CMD
// Creates a messagebox containing some info.
DWORD WINAPI CreateMessageBox( LPVOID lpParam) {
    _sleep(500);
    show(hwnd);
    string notice;
    if( recording )
    	notice = "Someone started the Command Line!\nTrying to obstruct it.\nCheck your logs.\n\t~Duck Hunt Dog";
    if( recordingKPS )
    	notice = "Someone typed unhumanly fast!\nCheck your logs.\n\t~Duck Hunt Dog";
    meB:
	int mb = MessageBox(NULL, notice.c_str(), "Bark!", MB_RETRYCANCEL | MB_ICONWARNING | MB_SETFOREGROUND );
	switch(mb){
		case IDCANCEL:
			break;
		case IDRETRY:
			goto meB;
	}
    return 0;
}
#endif /* OBSTRUCT_CMD */

#if DETECT_KPS
// Is run as seperate thread and continiously consumes pressed keys to determine kps.
DWORD WINAPI reduceKPSCounter( LPVOID lpParam) {
    while(running){
		_sleep(100);
		keyCounter -= KPS/10;
		if(keyCounter <= 0){
			keyCounter = 0;
		}
		while( keyBuffer.size() > keyCounter ){ 
			keyBuffer.erase( keyBuffer.begin() );
		}
    }
    return 0;
}
#endif /* DETECT_KPS */

// Used to load bg pictures from res in the exe.
HBITMAP LoadPictResource(LPCTSTR resId, LPCTSTR resType)
{
	HRSRC hRes = FindResource( NULL, resId, resType);
	_ASSERTE( hRes );

	DWORD dwFileSize = SizeofResource( NULL, hRes );

	HGLOBAL hSplash = LoadResource( NULL, hRes );
	_ASSERTE( hSplash );

	LPVOID pSplash = LockResource( hSplash );

	LPVOID pvData = NULL;
	HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, dwFileSize);
	_ASSERTE(NULL != hGlobal);

	pvData = GlobalLock(hGlobal);
	_ASSERTE(NULL != pvData);

	DWORD dwBytesRead = 0;
	CopyMemory( pvData, pSplash, dwFileSize );
	GlobalUnlock(hGlobal);

	LPSTREAM pstm = NULL;
	HRESULT hr = CreateStreamOnHGlobal(hGlobal, FALSE, &pstm);
	_ASSERTE(SUCCEEDED(hr) && pstm);

	HBITMAP hbm = NULL;
	Gdiplus::Bitmap* pBitmap = Gdiplus::Bitmap::FromStream(pstm);
    if (pBitmap)
    {
        pBitmap->GetHBITMAP(Gdiplus::Color(0, 0, 0), &hbm);
    }
    pstm->Release();
    GlobalFree(pvData);
    return hbm;
}

// Used to blit BG image to the device context.
bool BlitBGBitmap(HDC hWinDC)
{
	ULONG_PTR gdiplusToken;
	Gdiplus::GdiplusStartupInput gdiplusStartupInput;
	if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL) != Gdiplus::Ok)
	{
		return 0;
	}

	HBITMAP hBitmap = NULL;
	BITMAP  pBitmap  = {0};
	if( recording || recordingKPS ){
		hBitmap = LoadPictResource(MAKEINTRESOURCE(IDR_BGREC), RT_HTML);
		if (hBitmap)
		{
			GetObject(hBitmap, sizeof(pBitmap), &pBitmap);
		}
	}else{
		hBitmap = LoadPictResource(MAKEINTRESOURCE(IDR_BG), RT_HTML);
		if (hBitmap)
		{
			GetObject(hBitmap, sizeof(pBitmap), &pBitmap);
		};
	}

	// Verify that the image was loaded
	if (hBitmap == NULL) {
		return false;
	}

	// Create a device context that is compatible with the window
	HDC hLocalDC;
	hLocalDC = ::CreateCompatibleDC(hWinDC);
	// Verify that the device context was created
	if (hLocalDC == NULL) {
		return false;
	}

	// Verify the bitmap's parameters;
	int iReturn = GetObject(reinterpret_cast<HGDIOBJ>(hBitmap), sizeof(BITMAP),
		reinterpret_cast<LPVOID>(&pBitmap));
	if (!iReturn) {
		return false;
	}

	// Select the loaded bitmap into the device context
	HBITMAP hOldBmp = (HBITMAP)::SelectObject(hLocalDC, hBitmap);
	if (hOldBmp == NULL) {
		return false;
	}

	// Blit the dc which holds the bitmap onto the window's dc
	BOOL qRetBlit = ::BitBlt(hWinDC, 0, 0, pBitmap.bmWidth, pBitmap.bmHeight,
		hLocalDC, 0, 0, SRCCOPY);
	if (!qRetBlit) {
		return false;
	}

	// Unitialize and deallocate resources
	::SelectObject(hLocalDC, hOldBmp);
	::DeleteDC(hLocalDC);
	::DeleteObject(hBitmap);
	return true;
}

// This function gets called by windows whenever the keyboard hook receives a message.
// (a button is pressed)
__declspec(dllexport) LRESULT CALLBACK handlekeys(int code, WPARAM wp, LPARAM lp)
{

	if (code == HC_ACTION && (wp == WM_SYSKEYDOWN || wp == WM_KEYDOWN)) {
		char tmp[0xFF] = {0};
		std::string str;
		DWORD msg = 1;
		KBDLLHOOKSTRUCT st_hook = *((KBDLLHOOKSTRUCT*)lp);
		bool printable;

		/*
		 * Get key name as string
		 */
		msg += (st_hook.scanCode << 16);
		msg += (st_hook.flags << 24);
		GetKeyNameText(msg, tmp, 0xFF);
		str = std::string(tmp);

		printable = (str.length() == 1) ? true : false;

		// Only count the key for KPS test when it was pressed first, not held down.
		// This prevents false positives caused by held down keys.
		// Held down keys sitll get recorded for logging purposes.
		bool countKey = !(GetAsyncKeyState(st_hook.vkCode) & (1 << 16));

		/*
		 * Non-printable characters only:
		 * Some of these (namely; newline, space and tab) will be
		 * made into printable characters.
		 * Others are encapsulated in brackets ('[' and ']').
		 */
		if (!printable) {
			/*
			 * Keynames that may become printable characters and
			 * modifier keys are handled here.
			 */
			if (str == "CAPSLOCK" || str == "FESTSTELL"){
				capslock = !capslock;
				str = "[CAPSLOCK]";
				printable = true;
			} else if (str == "ENTER" || str == "EINGABE") {
				str = "[ENTER]\n| | ";
			} else if (str == "SPACE" || str == "LEER") {
				str = " ";
			} else if (str == "TAB" || str == "TABULATOR") {
				str = "\t";
				if (alt)
					str = "[TAB]";
			} else if (str == "SHIFT" || str == "UMSCHALT") {
				str = "[SHIFT]";
				if(shift)
					str = "";
				shift = true;
			} else if (str == "") {
				str = "[?~>RIGHT SHIFT]";
				if(rightshift)
					str = "";
				rightshift = true;
			} else if (str == "RIGHT WINDOWS" || str == "RECHTE WINDOWS" 
			          || str == "LEFT WINDOWS" || str == "LINKE WINDOWS") {
				str = "[WINKEY]";
				if(win)
					str = "";
				win = true;
			} else if (str == "ALT") {
				str = "[ALT]";
				if(alt)
					str = "";
				alt = true;
			} else if (str == "ALT GR") {
				str = "[ALT GR]";
				if(altgr)
					str = "";
				altgr = true;
			}else if (str == "CTRL" || str =="STRG" ) {
				str = "[CTRL]";
				if(ctrl)
					str = "";
				ctrl = true;
			}else if (str == "STRG-RECHTS") {
				str = "[RIGHT CTRL]";
				if(rightctrl)
					str = "";
				rightctrl = true;
			} else {
				str = ("[" + str + "]");
			}
		}

		/*
		 * Printable characters only:
		 * If shift is on and capslock is off or shift is off and
		 * capslock is on, make the character uppercase.
		 * If both are off or both are on, the character is lowercase
		 * [CAPSLOCK] gets altered as well to notify of the induced state.
		 */
		if (printable) {
			if ((shift || rightshift) == capslock) { /* Lowercase */
				for (size_t i = 0; i < str.length(); ++i)
					str[i] = tolower(str[i]);
			} else { /* Uppercase */
				for (size_t i = 0; i < str.length(); ++i) {
					if (str[i] >= 'A' && str[i] <= 'Z') {
						str[i] = toupper(str[i]);
					}
				}
			}
		}

		// Record check
		if(win && !recording && !recordingKPS){
			if(str == "R" || str == "r"){
				recording = true;
				newlogs++;
				InvalidateRect(hwnd, NULL, FALSE);
				str = "|O| New recording started: " + currentDateTime() 
				    + " (Windows Run Command Started)\n| |\n|O| [WINKEY]->R";
#if OBSTRUCT_CMD
				CreateThread(NULL, 0, &CreateMessageBox, NULL, 0, NULL);
#endif /* OBSTRUCT_CMD */
			}
		}

#if DETECT_KPS
		// KPS check
		if(str != "" && countKey){
			keyCounter++;
			if( !recordingKPS )
				keyBuffer.push_back(str);
		}

		// The keyCounter gets reduced 10 times per second.
		// Our check for how many keys have been counted so far
		// can be lower that way and not hit false positives.
		// This enables the detection of smaller scripts.
		// If the number is too low, we hit normal user keyboard 
		// mashing. 
		// In my tests, I could not create false positives, when
		// checking against 15 keys counted with a KPS of 25.
		if( keyCounter > 15 && !recording && !recordingKPS ){
			recordingKPS = true;
			newlogs++;
			InvalidateRect(hwnd, NULL, FALSE);
			// Add amount to keyCounter to increase record duration artificialy (3 secs).
			keyCounter += KPS * 3;
			str = "|K| New recording started: " + currentDateTime() 
		    + " (Unhuman keystrokes per second)\n| |\n|K| ";
		    while( keyBuffer.size() > 0 ){
		    	str += keyBuffer.front();
		    	keyBuffer.erase(keyBuffer.begin());

		    }
#if OBSTRUCT_CMD
	    	// Obstructing at this point probably does not yield any feasable results, but 
	   		// can be a nice notification that something happened.
			CreateThread(NULL, 0, &CreateMessageBox, NULL, 0, NULL);
#endif /* OBSTRUCT_CMD */
		}
		// Check if keystrokes slowed down happens in main window loop and not on button press.
#endif /* DETECT_KPS */

		// Check if Run Command was send.
		if( recording || recordingKPS ){
			if( str == "[ENTER]\n| | " && !recordingKPS ){
				recording = false;
				InvalidateRect(hwnd, NULL, FALSE);
				str += "\n|O| Recording ended: " + currentDateTime()
				     + " (ENTER was pressed to send command)\n\n";
			}
			string pwd(cCurrentPath);
			std::string path = pwd + "/" + OUTFILE_NAME;
			std::ofstream outfile(path, std::ios_base::app);
			outfile << str;
			outfile.close();
		}
	}

	// Check if a modifier key was releasded.
	if (code == HC_ACTION && (wp == WM_SYSKEYUP || wp == WM_KEYUP)) {
		char tmp[0xFF] = {0};
		std::string str;
		DWORD msg = 1;
		KBDLLHOOKSTRUCT st_hook = *((KBDLLHOOKSTRUCT*)lp);

		/*
		 * Get key name as string
		 */
		msg += (st_hook.scanCode << 16);
		msg += (st_hook.flags << 24);		
		GetKeyNameText(msg, tmp, 0xFF);
		str = std::string(tmp);
		if ((str == "SHIFT" || str == "UMSCHALT") && shift){
			shift = false;
			str = "[SHIFT Released]";
		}else if( (str == "") && rightshift ){
			rightshift = false;
			str = "[?~>RIGHT SHIFT Released]";
		}else if( (str == "ALT") && alt ){
			alt = false;
			str = "[ALT Released]";
		}else if( (str == "ALT GR") && altgr ){
			altgr = false;
			str = "[ALT GR Released]";
		}else if( (str == "CTRL" || str == "STRG") && ctrl ){
			ctrl = false;
			str = "[CTRL Released]";
		}else if( (str == "STRG-RECHTS") && rightctrl ){
			rightctrl = false;
			str = "[RIGHT CTRL Released]";
		}else if( (str == "RIGHT WINDOWS" || str == "RECHTE WINDOWS" 
		           || str == "LEFT WINDOWS" || str == "LINKE WINDOWS") 
		           && win ){
			win = false;
			str = "[WINKEY Released]";
		}else{
			str = "";
		}
		if( str != "" && !recordingKPS ){
			keyBuffer.push_back(str);
		}
		if( recording || recordingKPS ){
			string pwd(cCurrentPath);
			std::string path = pwd + "/" + OUTFILE_NAME;
			std::ofstream outfile(path, std::ios_base::app);
			outfile << str;
			outfile.close();
		}
	}


	return CallNextHookEx(kbdhook, code, wp, lp);
}


/**
 * \brief Called by DispatchMessage() to handle messages
 * \param hwnd	Window handle
 * \param msg	Message to handle
 * \param wp
 * \param lp
 * \return 0 on success
 */
LRESULT CALLBACK windowprocedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
	PAINTSTRUCT ps;
	HDC hdc;
	int wmId, wmEvent;

	switch (msg) {
		case SWM_TRAYMSG:
			switch(lp)
			{
				case WM_LBUTTONDOWN:
				case WM_RBUTTONDOWN:
				case WM_CONTEXTMENU:
					ShowContextMenu(hwnd);
					break;
			}
			break;
		case WM_SYSCOMMAND:
			if((wp & 0xFFF0) == SC_MINIMIZE)
			{
				ShowWindow(hwnd, SW_HIDE);
				return 1;
			}
			if((wp & 0xF060) == SC_CLOSE)
			{
				running = false;
					DestroyWindow(hwnd);
				return 1;
			}
			if((wp & 0xF010) == SC_MOVE)
			{
				DefWindowProc(hwnd, msg, wp, lp);
			}
		case WM_COMMAND:
			wmId    = LOWORD(wp);
			wmEvent = HIWORD(wp); 

			switch (wmId)
			{	
				case SWM_LOG:
				{	
					// Opens the logfile in the usual way for the user to inspect.
					if (!GetCurrentDir(cCurrentPath, sizeof(cCurrentPath)))
				    {
				     	return errno;
				    }
					cCurrentPath[sizeof(cCurrentPath) - 1] = '\0';
					string pwdlog(cCurrentPath);
					string pathlog = pwdlog + "/" + OUTFILE_NAME;
					ShellExecute( 	NULL, "open", 
	    				pathlog.c_str(),        // document to launch
	   					 NULL,       // parms -- not used  when launching a document
	    				NULL,       // default dir (don't care here)
	    				SW_SHOWNORMAL );
					break;
				}
				case SWM_SHOW:
					show(hwnd);
					break;
				case SWM_HIDE:
				case IDOK:
					ShowWindow(hwnd, SW_HIDE);
					break;
				case SWM_EXIT:
					running = false;
					DestroyWindow(hwnd);
					break;
			}
		case WM_PAINT:
			hdc = BeginPaint(hwnd, &ps);
			BlitBGBitmap(hdc);
			EndPaint(hwnd, &ps);
			break;
		case WM_CLOSE: case WM_DESTROY:
		{
			running = false;
			if (!GetCurrentDir(cCurrentPath, sizeof(cCurrentPath)))
		    {
		     	return errno;
		    }
			cCurrentPath[sizeof(cCurrentPath) - 1] = '\0';
			string pwd(cCurrentPath);
			string path = pwd + "/" + OUTFILE_NAME;
			std::ofstream outfile(path, std::ios_base::app);
			outfile << "\n<- Duck Hunt Dog session ended: "
			        << currentDateTime() << "\n\n\n";
			outfile.close();
		}
			break;
		default:
			/* Call default message handler */
			return DefWindowProc(hwnd, msg, wp, lp);
	}

	return 0;
}

int WINAPI WinMain(HINSTANCE thisinstance, HINSTANCE previnstance,
		LPSTR cmdline, int ncmdshow)
{	

	/*
	 * Set up window
	 */
	MSG		msg;
	WNDCLASSEX	windowclass;
	HINSTANCE	modulehandle;

	windowclass.hInstance = thisinstance;
	windowclass.lpszClassName = CLASSNAME;
	windowclass.lpfnWndProc = windowprocedure;
	windowclass.style = CS_DBLCLKS;
	windowclass.cbSize = sizeof(WNDCLASSEX);
	windowclass.hIcon = LoadIcon(windowclass.hInstance, MAKEINTRESOURCE(IDR_ICO));
	windowclass.hIconSm = LoadIcon(NULL, IDI_SHIELD);
	windowclass.hCursor  = LoadCursor(NULL, IDC_ARROW);
	windowclass.lpszMenuName = NULL;
	windowclass.cbClsExtra = 0;
	windowclass.cbWndExtra = 0;
	windowclass.hbrBackground = (HBRUSH)COLOR_BACKGROUND;

	if (!(RegisterClassEx(&windowclass)))
		return 1;

	hwnd = CreateWindowEx(	NULL, 
	                        CLASSNAME, 
	                        WINDOWTITLE, 
	                        WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_ICONIC,
							CW_USEDEFAULT, CW_USEDEFAULT, 
							210, 235,  
							HWND_DESKTOP, 
							NULL,
							thisinstance,  
							NULL );
	if (!(hwnd))
		return 1;
	if (!InitInstance (thisinstance, ncmdshow)) return FALSE;

	ShowWindow(hwnd, SW_SHOW);
	UpdateWindow(hwnd);
	
	/*
	 * Hook keyboard input
	 */
	modulehandle = GetModuleHandle(NULL);
	kbdhook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)handlekeys, modulehandle, NULL);

	running = true;

	if (!GetCurrentDir(cCurrentPath, sizeof(cCurrentPath)))
    {
     	return errno;
    }

	cCurrentPath[sizeof(cCurrentPath) - 1] = '\0';
	string pwd(cCurrentPath);
	std::string path;
	path = pwd + "/" + OUTFILE_NAME;
	std::ofstream outfile(path, std::ios_base::app);

	outfile << "-> Duck Hunt Dog session started: "
	        << currentDateTime() << "\n\n\n";
	outfile.close();

	/*
	 * Main loop
	 */
#if DETECT_KPS
	// Thread running next to the main loop, reducing 
	// the keystroke per second counter.
	CreateThread(NULL, 0, &reduceKPSCounter, NULL, 0, NULL);
#endif /* DETECT_KPS */
	while (running) {
		/*
		 * Get messages, dispatch to window procedure
		 */
		if (!GetMessage(&msg, NULL, 0, 0))
			running = false; /*
					  * This is not a "return" or
					  * "break" so the rest of the loop is
					  * done. This way, we never miss keys
					  * when destroyed but we still exit.
					  */
		TranslateMessage(&msg);
		DispatchMessage(&msg);

#if DETECT_KPS
		// This check is placed here, to stop recording when time
		// has passed normaly, without needing a button to be pressed.
		if( recordingKPS ){
			string str;
			if( keyCounter <= KPS ){
				recordingKPS = false;
				InvalidateRect(hwnd, NULL, FALSE);
				str = "\n| |\n|K| Recording ended: " + currentDateTime()
				     + " (Unhuman keystroke speed slowed down.)\n\n";
			}
			string pwd(cCurrentPath);
			std::string path = pwd + "/" + OUTFILE_NAME;
			std::ofstream outfile(path, std::ios_base::app);
			outfile << str;
			outfile.close();
		}
#endif
	}

	return 0;
}