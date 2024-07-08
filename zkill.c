/* This unhides a few necessary function definitions. */
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <limits.h>
#include <getopt.h>

/* If PATH_MAX is not defined in the limits.h header. */
#ifndef PATH_MAX
# define PATH_MAX      (4098)
#endif

#define COMM_MAXLEN    (256)
#define STATE_MAXREAD  (50)

/* If __inline compiler extension is not available
   ignore the function inlining. */
#ifndef __inline
# define __inline
#endif

#if defined (__GNUC__) || defined (__clang__)
# define do_unreachable    __builtin_unreachable()
# define do_noreturn       __attribute__((noreturn))
#else
# define do_unreachable
# define do_noreturn
#endif

/* A lookup table for various signals. */
struct signal_body {
	char *signal;
	int sig;
};

/* Getopt options. */
struct opts {
	int pflag;
	int nflag;
	int rflag;
	int eflag;
	int lflag;
	int xflag;
	int yflag;
	int sflag;
	int aflag;
};

/* Test if a character is a digit. */
static __inline int zkill_isdigit(int c)
{
	return (c >= '0' && c <= '9');
}

/* Test if a character is an alphabetic value. */
static __inline int zkill_isalpha(int c)
{
        return ((c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z'));
}

/* Test if a string contains all numerical value. */
static int zkill_is_strnum(const char *s)
{
	for (; *s; s++) {
		if (!zkill_isdigit(*s))
			return (0);
	}
	return (1);
}

/* Get the basename of a given path. */
static char *zkill_basename(const char *s)
{
        size_t len;

	/* Safely return a string to avoid any
	   accidental crash. */
	if (s == NULL)
		return ("(null)");

	len = strlen(s);
        for (; len > 0; len--) {
		if (s[len] == '/')
			return ((char *)s + len + 1);
	}

	return ((char *)s);
}

/* Convert a string to an integer. */
static int zkill_toint(const char *s)
{
        char *eptr;
        long ret;

	errno = 0;
        ret = strtol(s, &eptr, 10);
	if (errno != 0)
		err(EXIT_FAILURE, "strtol()");

	/* Check for overflows and underflows. */
        if (ret > INT32_MAX)
		errx(EXIT_FAILURE, "resulted PID overflow INT32_MAX");
	if (ret < INT32_MIN)
		errx(EXIT_FAILURE, "resulted PID underflow INT32_MIN");

	if (eptr == s)
		errx(EXIT_FAILURE, "invalid PID '%s' was supplied.", s);

	return ((int)ret);
}

/* Kill a process by providing its PID. */
static void zkill_by_pid(pid_t pid, const char *signal)
{
	int sig;
	size_t i;

	/* Thanks,
	 * https://faculty.cs.niu.edu/~hutchins/csci480/signals.htm
	 * https://man7.org/linux/man-pages/man7/signal.7.html */
	struct signal_body sigb[] = {
		{ "SIGHUP",     SIGHUP    },  { "SIGINT",    SIGINT    },
		{ "SIGQUIT",    SIGQUIT   },  { "SIGILL",    SIGILL    },
		{ "SIGTRAP",    SIGTRAP   },  { "SIGABRT",   SIGABRT   },
		{ "SIGIOT",     SIGIOT    },  { "SIGBUS",    SIGBUS    },
		{ "SIGFPE",     SIGFPE    },  { "SIGKILL",   SIGKILL   },
		{ "SIGUSR1",    SIGUSR1   },  { "SIGSEGV",   SIGSEGV   },
		{ "SIGUSR2",    SIGUSR2   },  { "SIGPIPE",   SIGPIPE   },
		{ "SIGALRM",    SIGALRM   },  { "SIGTERM",   SIGTERM   },
		{ "SIGCHILD",   SIGCHLD   },  { "SIGCONT",   SIGCONT   },
		{ "SIGSTOP",    SIGSTOP   },  { "SIGTSTP",   SIGTSTP   },
		{ "SIGTTIN",    SIGTTIN   },  { "SIGTTOU",   SIGTTOU   },
		{ "SIGURG",     SIGURG    },  { "SIGXCPU",   SIGXCPU   },
		{ "SIGXFSZ",    SIGXFSZ   },  { "SIGVTALRM", SIGVTALRM },
		{ "SIGPROF",    SIGPROF   },  { "SIGWINCH",  SIGWINCH  },
		{ "SIGIO",      SIGIO     },  { "SIGPOLL",   SIGPOLL   },
		{ "SIGPWR",     SIGPWR    },  { "SIGSYS",    SIGSYS    },

			/* For Alpha and MIPS only. */ 
#if defined (__alpha__) || defined (__mips__)
		{ "SIGEMT",     SIGEMT    },
#endif

#if defined (__alpha__)
			/* Availability is not guaranteed. */
		{ "SIGINFO",    SIGINFO   },  { "SIGLOST",    SIGLOST   },
#endif
			/* May or may not present in HP/UX or PA-RISCV. */
#if defined (__x86_64__) || defined (__hppa__)
		{ "SIGSTKFLT",  SIGSTKFLT },
#endif
	};

	sig = SIGTERM;
	for (i = 0; i < sizeof(sigb) / sizeof(sigb[0]); i++) {
		if (strcasecmp(signal, sigb[i].signal) == 0) {
		        sig = sigb[i].sig;
			break;
		}
	}

        if (kill(pid, sig) == -1) {
		/* Handle possible errors. */
		switch (errno) {
		case EINVAL:
		case EPERM:
		case ESRCH:
			errx(EXIT_FAILURE,
			     "PID(%d): %s", pid, strerror(errno));
		default:
			err(EXIT_FAILURE, "kill()");
		}
	}
}

/* Get the state of the process. */
static char zkill_get_state(const char *pid_name)
{
	char path[PATH_MAX];
	char state[STATE_MAXREAD];
	char *p;
	int fd, lim;

	snprintf(path, sizeof(path), "/proc/%s/stat", pid_name);
	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(EXIT_FAILURE, "open()");

	read(fd, state, sizeof(state));
	close(fd);

	p = state;
	lim = 0;
	while (lim != 2) {
		if (*p++ == ' ')
			lim++;
	}

	/* Get the status of the process.
	   Status characters are R, S, D, Z, T, t, W, X, I. */ 
	if (zkill_isalpha(*p))
		return (*p);
	else
		return ('\0');
}

/* List all process names, including kernel threads. */
static void zkill_list_process(int show_state, int ignore_args)
{
	DIR *dir;
	struct dirent *den;
	int fd;
	char path[PATH_MAX];
	char cmdline[PATH_MAX];
	char comm[COMM_MAXLEN];
	char *ap;
	size_t len;

	dir = opendir("/proc/");
	if (dir == NULL)
		err(EXIT_FAILURE, "opendir()");

	/* if enabled also show the process "STATE". */
	if (show_state)
	        fputs("\tPID\tSTATE\tPROCESS\n", stdout);
	else
	        fputs("\tPID\tPROCESS\n", stdout);

	while ((den = readdir(dir)) != NULL) {
		if (strncmp(den->d_name, ".", 1) == 0 ||
		    strncmp(den->d_name, "..", 2) == 0)
			continue;

		/* Check if the file is a PID or not. */
		if (zkill_is_strnum(den->d_name) == 0)
			continue;

		snprintf(path, sizeof(path), "/proc/%s/cmdline",
			 den->d_name);

	        fd = open(path, O_RDONLY);
		if (fd == -1) {
			/* Ignore if no pseudo PID directory is found
			   with the name. Depending on the implementation
			   if readdir() read that the directory is there,
			   it will add it to the queue. But it may not exists
			   when we will reach here, which will result an
			   unexpected error. */
			if (errno == ENOENT)
				continue;
			else
				err(EXIT_FAILURE, "open()");
		}

		read(fd, cmdline, sizeof(cmdline));
		close(fd);

	        len = strlen(cmdline);
		/* If we do not have anything in the cmdline buffer,
		   we'll try to read the /proc/<pid>/comm pseudo file. */
		if (len == 0) {
			snprintf(path, sizeof(path), "/proc/%s/comm",
				 den->d_name);

			fd = open(path, O_RDONLY);
			if (fd == -1) {
				/* See the above comment. */
				if (errno == ENOENT)
					continue;
				else
					err(EXIT_FAILURE, "open()");
			}

			read(fd, comm, sizeof(comm));
			close(fd);

			comm[strlen(comm) - 1] = '\0';
			ap = comm;
			if (show_state)
				fprintf(stdout, "%11s%8c\t%s\n", den->d_name,
					zkill_get_state(den->d_name),
					ignore_args ? strsep(&ap, " ") : ap);
			else
				fprintf(stdout, "%11s\t%s\n", den->d_name,
					ignore_args ? strsep(&ap, " ") : ap);

			memset(comm, '\0', sizeof(comm));
		} else {
			cmdline[len] = '\0';
		        ap = cmdline;
		        if (show_state)
				fprintf(stdout, "%11s%8c\t%s\n", den->d_name,
					zkill_get_state(den->d_name),
					ignore_args ? strsep(&ap, " ") : ap);
			else
				fprintf(stdout, "%11s\t%s\n", den->d_name,
					ignore_args ? strsep(&ap, " ") : ap);

			memset(cmdline, '\0', sizeof(cmdline));
		}
	}
	closedir(dir);
}

/* Find a process by its name, and then kill it. */
static void zkill_by_name(const char *pname, const char *signal, int rec, int exact)
{
	DIR *dir;
	struct dirent *den;
	char path[PATH_MAX];
	char cmdline[PATH_MAX];
	char comm[COMM_MAXLEN];
	char *farg, *sep;
	int fd, has_one;
	size_t len;

	dir = opendir("/proc");
	if (dir == NULL)
		err(EXIT_FAILURE, "opendir()");

	has_one = 0;
	memset(comm, '\0', sizeof(comm));
	while ((den = readdir(dir)) != NULL) {
		if (strncmp(den->d_name, ".", 1) == 0 ||
		    strncmp(den->d_name, "..", 2) == 0)
			continue;

		/* Check if the file is a PID or not. */
		if (zkill_is_strnum(den->d_name) == 0)
			continue;

		snprintf(path, sizeof(path), "/proc/%s/cmdline",
			 den->d_name);
		fd = open(path, O_RDONLY);
		if (fd == -1) {
			if (errno == ENOENT)
				continue;
			else
				err(EXIT_FAILURE, "open()");
		}

		read(fd, cmdline, sizeof(cmdline));
		close(fd);

	        len = strlen(cmdline);
		/* if we don't have anything in the cmdline buffer,
		   we'll try to read the comm pseudo file. */
		if (len == 0) {
			snprintf(path, sizeof(path), "/proc/%s/comm",
				 den->d_name);

			fd = open(path, O_RDONLY);
			if (fd == -1) {
				if (errno == ENOENT)
					continue;
				else
					err(EXIT_FAILURE, "open()");
			}

			read(fd, comm, sizeof(comm));
			close(fd);

			comm[strlen(comm) - 1] = '\0';

			if (exact) {
				/* Look for exact match. */
				if (strcmp(comm, pname) == 0) {
					has_one = 1;
					zkill_by_pid(zkill_toint(den->d_name), signal);
					if (rec == 0)
						break;
				}
			} else {					
				/* Look up to find if pname has similar
				   characters as comm. */
				if (strstr(comm, pname) != NULL) {
					has_one = 1;
					zkill_by_pid(zkill_toint(den->d_name), signal);
					if (rec == 0)
						break;
				}
			}

			memset(comm, '\0', sizeof(comm));
		} else {
			cmdline[len] = '\0';
		        farg = cmdline;
		        sep = strsep(&farg, " ");

			if (exact) {
				if (strcmp(zkill_basename(sep), pname) == 0) {
					has_one = 1;
					zkill_by_pid(zkill_toint(den->d_name), signal);
					if (rec == 0)
						break;
				}
			} else {				
				/* Look up to find if pname has similar characters
				   as separated basename. */
				if (strstr(zkill_basename(sep), pname) != NULL) {
					has_one = 1;
					zkill_by_pid(zkill_toint(den->d_name), signal);
					if (rec == 0)
						break;
				}
			}

			memset(cmdline, '\0', sizeof(cmdline));
		}
	}

	closedir(dir);
	if (has_one == 0)
	        errx(EXIT_FAILURE,
		     "no process was found with name '%s'.", pname);
}

/* Print the meaning of a status code. */
static void zkill_print_status(const char code)
{
	const char *msg;

        switch (code) {
	case 'R':
		msg = "Running process";
		break;
	case 'S':
		msg = "Sleeping in an interrupt-able wait";
	        break;
	case 'D':
		msg = "Waiting in an uninterrupt-able disk sleep";
		break;
	case 'Z':
		msg = "Zombie process";
		break;
	case 'T':
		msg = "Stopped process or Trace stopped (before Linux 2.6.33)";
		break;
	case 't':
		msg = "Tracing stop";
		break;
	case 'W':
		msg = "Paging (Only before Linux 2.6.0)\n"
			"Waking (Linux 2.6.33 to 3.13 only)";
		break;
	case 'X':
		msg = "Dead process";
		break;
	case 'x':
		msg = "Dead process (Linux 2.6.33 to 3.13 only)";
	        break;
	case 'K':
		msg = "Wakekill (Linux 2.6.33 to 3.13 only)";
		break;
	case 'P':
		msg = "Parked (Linux 3.9 to 3.13 only)";
		break;
	case 'I':
		msg = "Idle (Linux 4.14 onward)";
		break;
        default:
	        msg = "Unknown state";
		break;
	}

	fprintf(stdout, "%s\n", msg);
}

/* Print the meaning of every status codes. */
static void zkill_print_status_all(void)
{
	fputs("R = Running\n"
	      "S = Sleeping in an interrupt-able wait\n"
	      "D = Waiting in an uninterrupt-able disk sleep\n"
	      "Z = Zombie\n"
	      "T = Stopped (on a signal) or trace stopped"
	      "(before Linux 2.6.33)\n"
	      "t = Tracing stop (Linux 2.6.33 onward)\n"
	      "W = Paging (only before Linux 2.6.0)\n"
	      "X = Dead (from Linux 2.6.0 onward)\n"
	      "x = Dead (Linux 2.6.33 to 3.13 only)\n"
	      "K = Wakekill (Linux 2.6.33 to 3.13 only)\n"
	      "W = Waking (Linux 2.6.33 to 3.13 only)\n"
	      "P = Parked (Linux 3.9 to 3.13 only)\n"
	      "I = Idle (Linux 4.14 onward)\n",
	      stdout);
}

/* Print usage. */
do_noreturn
static void zkill_print_usage(int status)
{
	fputs("zkill\n"
	      "usage:\n"
	      "  --pid/-p       <pid>   - terminate a process by its PID\n"
	      "  --name/-n      <name>  - terminate a process by its name\n"
	      "  --exact/-e     <name>  - match with exact name only\n"
	      "  --list/-l              - list all process names\n"
	      "  --status/-y[y] <code>  - display the meaning of status code(s)\n"
	      "  --help/-h              - print this help menu\n\n"

	      "options:\n"
	      "  --signal/-s <signal>   - name of the signal to send\n"
	      "  --rec/-r               - recursive search of a process name\n"
	      "  --noargs/-a            - split and ignore the process arguments\n"
	      "  --exact/-e             - match with exact name as an option\n",
	      status == EXIT_SUCCESS ? stdout : stderr);

	exit(status);
}

int main(int argc, char **argv)
{
	int c, i;
        struct opts opts;
	const struct option lopts[] = {
		{ "pid",    no_argument, NULL, 'p' },
		{ "name",   no_argument, NULL, 'n' },
		{ "signal", no_argument, NULL, 's' },
		{ "rec",    no_argument, NULL, 'r' },
		{ "exact",  no_argument, NULL, 'e' },
		{ "list",   no_argument, NULL, 'l' },
		{ "state",  no_argument, NULL, 'x' },
		{ "status", no_argument, NULL, 'y' },
		{ "noargs", no_argument, NULL, 'a' },
		{ "help",   no_argument, NULL, 'h' },
		{ NULL,     0,           NULL,  0  },
	};
	const char *signal;

	if (argc < 2)
	        zkill_print_usage(EXIT_FAILURE);

	/* Check if the first argument is only contains '-'
	   and nothing else. */
	if (argv[1][0] == '-' && argv[1][1] == '\0')
		errx(EXIT_FAILURE, "no valid option was provided.");

        signal = "SIGTERM";

	/* Iterate over the arguments only. */
	if (argv[1][0] != '-') {
		for (i = 1; argv[i] != NULL; i++)
			zkill_by_name(argv[i], signal, 1, 0);

		exit(EXIT_SUCCESS);
	}

	memset(&opts, '\0', sizeof(opts));
        opterr = 0;
	while ((c = getopt_long(argc, argv, "pnrelsxyah", lopts, NULL)) != -1) {
		switch (c) {
		case 'p':
		        opts.pflag = 1;
		        break;
		case 'n':
			opts.nflag = 1;
		        break;
		case 'r':
		        opts.rflag = 1;
			break;
		case 'e':
			opts.eflag = 1;
		        break;
		case 'l':
			opts.lflag = 1;
			break;
		case 's':
			signal = optarg;
		        opts.sflag = 1;
		        break;
		case 'x':
			opts.xflag = 1;
			break;
		case 'y':
			opts.yflag = 1;
			break;
		case 'a':
			opts.aflag = 1;
			break;
		case 'h':
		        zkill_print_usage(EXIT_SUCCESS);
			do_unreachable;
		case '?':
			errx(EXIT_FAILURE, "invalid option");
			do_unreachable;
	        default:
		        exit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;

	/* Option: -p */
	if (opts.pflag && opts.nflag == 0 && opts.lflag == 0 && opts.yflag == 0) {
		if (opts.eflag)
			errx(EXIT_FAILURE,
			     "option '-p/--pid' ignores the '-e/--exact' flag.");

		if (*argv == NULL)
			errx(EXIT_FAILURE, "no PID was supplied.");
		for (; *argv != NULL; argv++)
			zkill_by_pid(zkill_toint(*argv), signal);
	}

	/* Option: -n */
	else if (opts.nflag && opts.pflag == 0 && opts.lflag == 0 && opts.yflag == 0) {
		if (*argv == NULL)
			errx(EXIT_FAILURE, "no process name was supplied.");
		for (; *argv != NULL; argv++)
			zkill_by_name(*argv, signal, opts.rflag, opts.eflag);
        }

	else if (opts.yflag && opts.pflag == 0 && opts.nflag == 0 && opts.lflag == 0) {
		if (argv[-1][2] != '\0') {
			zkill_print_status_all();
		} else {
			if (*argv == NULL)
				errx(EXIT_FAILURE,
				     "no status code was supplied.");
			zkill_print_status(**argv);
		}
	}

        /* Option: -l */
        else if (opts.lflag && opts.nflag == 0 && opts.pflag == 0 &&
		 opts.yflag == 0) {
		zkill_list_process(opts.xflag, opts.aflag);
	}

	/* Option: none */
	else if (opts.pflag == 0 && opts.nflag == 0 && opts.lflag == 0 &&
		 opts.yflag == 0) {
	        if (opts.rflag && opts.eflag == 0)
			errx(EXIT_FAILURE,
			     "option '-r/--rec' cannot be used in standalone.");
		if (opts.sflag)
			errx(EXIT_FAILURE,
			     "option '-s/--signal' cannot be used in standalone.");
		if (opts.xflag)
			errx(EXIT_FAILURE,
			     "option '-x/--state' cannot be used in standalone.");
		if (opts.aflag)
			errx(EXIT_FAILURE,
			     "option '-a/--noargs' cannot be used in standalone.");

		if (opts.eflag) {
			if (*argv == NULL)
				errx(EXIT_FAILURE, "no process name was supplied.");
			for (; *argv != NULL; argv++)
				zkill_by_name(*argv, signal, opts.rflag, opts.eflag);
		}
	}

	/* Any other arguments means of a combination of multiple flags. */
        else {
		errx(EXIT_FAILURE, "cannot combine multiple flags together.");
	}

	exit(EXIT_SUCCESS);
}
