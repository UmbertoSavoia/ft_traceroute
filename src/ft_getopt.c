#include "ft_getopt.h"

char *ft_optarg = 0;
int  ft_optind = 1;

int     ft_getopt(int argc, char *const argv[], const char *optstring)
{
    char *ptr = 0;
    ft_optarg = 0;

    if (!argv || !optstring || ft_optind > argc || argc == ft_optind)
        return -1;

    if (argv[ft_optind][0] == '-') {
        if ((ptr = strchr(optstring, argv[ft_optind][1]))) {
            if (*(ptr + 1) == ':') {
                if (argv[ft_optind][2] == 0) {
                    ft_optarg = argv[ft_optind+1];
                    ++ft_optind;
                } else {
                    ft_optarg = argv[ft_optind] + 2;
                }
            }
            ++ft_optind;
            return *ptr;
        } else {
            ++ft_optind;
            return '?';
        }
    }
    return -1;
}

int     ft_getopt_long(int argc, char *const argv[], t_option longopts[], int len_longopts)
{
    t_option *ptr = 0;
    ft_optarg = 0;
    int i = 0;

    if (!argv || !longopts || ft_optind > argc || argc == ft_optind)
        return -1;

    if (argv[ft_optind][0] == '-') {
        for (i = 0; i < len_longopts; ++i) {
            if (!memcmp(&(argv[ft_optind][1]), longopts[i].name, strlen(&(argv[ft_optind][1])))) {
                ptr = &(longopts[i]);
                break;
            }
        }
        if (ptr) {
            if (ptr->has_arg) {
                ++ft_optind;
                ft_optarg = argv[ft_optind];
            }
            ++ft_optind;
            return i;
        } else {
            ++ft_optind;
            return -2;
        }
    }
    return -1;
}
