#ifndef FT_GETOPT_H
#define FT_GETOPT_H

#include <unistd.h>
#include <string.h>

typedef struct  s_option {
    const char  name[64];
    int         has_arg;
}               t_option;

extern char *ft_optarg;
extern int  ft_optind;

int ft_getopt(int argc, char *const argv[], const char *optstring);
int ft_getopt_long(int argc, char *const argv[], t_option longopts[], int len_longopts);

#endif