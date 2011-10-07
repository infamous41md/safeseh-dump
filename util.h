#ifndef _UTIL_H_
#define _UTIL_H_

//
extern int opterr;		/* error => print message */
extern int optind;		/* next argv[] index */
extern int optopt;		/* Set for unknown arguments */
extern char *optarg;		/* option parameter if any */

//
int getopt(int argc, char * const argv[], const char *optstring);


#endif