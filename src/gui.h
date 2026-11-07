#ifndef _GUI_H
#define _GUI_H

/*
 * The window that opens when the program is started without options (a double
 * click), or with --gui. Returns when the window is closed.
 */
int gui_run(const char *version);

/*
 * The program is built as a window program, so a double click opens no console. Started from a
 * shell it joins the shell's console (and, when its output is not redirected, prints there).
 * Returns 1 when there is a console to print to, 0 when there is none: it was started by
 * Explorer or by another program without one.
 */
int console_attach(void);

#endif
