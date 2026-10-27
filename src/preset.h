#ifndef _PRESET_H
#define _PRESET_H

/*
 * Replaces every "--preset <name>" (or "--preset=<name>") in argv with the
 * options that preset stands for. Returns the new argument list and updates
 * *argc, or returns NULL after printing the problem (unknown name, missing name).
 */
char **preset_expand(int *argc, char **argv);

#endif
