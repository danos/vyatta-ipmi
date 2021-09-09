/*
 * Copyright (c) 2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define IPMI_DEV_COUNT_MAX	(4)
#define BMC_HEALTH_CHECK_INTERVAL (60)
#define DEF_CMD_TIMEOUT	(15)
#define DEF_TERM_TIMEOUT (2)

#ifndef EXIT_EXEC_FAILED
#define EXIT_EXEC_FAILED 126
#endif

int debug;
long interval = BMC_HEALTH_CHECK_INTERVAL;
long timeout = DEF_CMD_TIMEOUT;
bool done;

static const char *ipmi_devs[] =
    { "/dev/ipmi0", "/dev/ipmi/0", "/dev/ipmidev/0", NULL };
extern char **environ;

static char * const ipmi_cmd[] = { "ipmitool", "bmc", "info", NULL };

static int dbg(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

static int dbg(const char *fmt, ...)
{
	int n;
	va_list args;

	if (debug <= 1)
		return 0;

	va_start(args, fmt);
	n = vfprintf(stderr, fmt, args);
	va_end(args);
	return n;
}

static bool ischardev(const char *fname)
{
	struct stat st;

	if (lstat(fname, &st) == -1) {
		dbg("cannot stat %s:%m\n", fname);
		return false;
	}
	if ((st.st_mode & S_IFMT) == S_IFCHR)
		return true;

	return false;
}

static const char *find_ipmi_dev()
{
	const char **p = &ipmi_devs[0];

	for(; *p != NULL; ++p) {
		if (ischardev(*p))
			return *p;
	}
	return NULL;
}

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGTERM:
		if (debug > 1)
			dbg("Got SIGTERM");
		done = true;
		break;
	default:
		if (debug > 1)
			dbg("Ignore received signal %d", sig);
		break;
	}

}

static int setup_signals(void)
{
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);

	sa.sa_handler = signal_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		syslog(LOG_ERR, "cannot set handler for SIGTERM: %s",
		       strerror(errno));
		return -1;
	}
	return 0;
}

static int wait_for_child(pid_t pid, int *status,
			  const struct timespec *cmd_timeout,
			  const struct timespec *term_timeout)
{
	bool child_done = false;
	int termsig = SIGTERM;
	bool terminate = false;
	int sig;
	int r;
	sigset_t mask;
	siginfo_t info;
	struct timespec def_term_timeout = { DEF_TERM_TIMEOUT, 0 };
	const struct timespec *ts = cmd_timeout;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigaddset(&mask, SIGTERM);

	do {
		/* do a sigtimedwait for SIGCHLD */
		if (ts == NULL)
			sig = sigwaitinfo(&mask, &info);
		else
			sig = sigtimedwait(&mask, &info, ts);

		switch (sig) {
		case SIGCHLD:
			child_done = info.si_pid == pid &&
			    (info.si_code == CLD_EXITED
			     || info.si_code == CLD_KILLED
			     || info.si_code == CLD_DUMPED);
			break;
		case SIGTERM:
			/* Clean up child on term signal */
			done = true;
			terminate = true;
			break;
		case -1:
			if (errno == EINVAL)
				return -1;

			if (errno == EAGAIN) {
				/* Timed out */
				terminate = true;
				syslog(LOG_ERR,
				       "%s: pid %d timed out, sending signal %d",
				       __func__, pid, termsig);
			}
			break;
		default:
			/* Shouldn't be here: ignore  */
			syslog(LOG_ERR, "%s:spurious signal %d", __func__, sig);
			break;
		}

		if (terminate) {
			terminate = false;
			kill(pid, termsig);
			termsig = SIGKILL;
			if (term_timeout != NULL)
				ts = term_timeout;
			else
				ts = &def_term_timeout;
		}
	} while(!child_done);

	r = waitpid(pid, status, WNOHANG);
	if (r != pid) {
		syslog(LOG_ERR, "failed to get exit status for pid %d: %m",
		       pid);
		return 0;
	}
	return pid;
}

static int start_cmd(char *const argv[])
{
	pid_t cpid;
	int r;
	sigset_t mask;
	int outfd;

	cpid = fork();
	if (cpid != 0) {
		if (cpid < 0)
			syslog(LOG_ERR, "%s: failed to start command %s:%m",
			       __func__, argv[0]);
		return cpid;
	}

	/* child */
	/* stdin: close
	 * stdout: /dev/null
	 * stderr: inherit..
	 */
	close(STDIN_FILENO);
	outfd = open("/dev/null", O_WRONLY);
	dup2(outfd, STDOUT_FILENO);
	close(outfd);

	/* unmask previously blocked signals */
	sigprocmask(SIG_BLOCK, NULL, &mask);
	sigdelset(&mask, SIGTERM);
	sigdelset(&mask, SIGCHLD);
	sigprocmask(SIG_SETMASK, &mask, NULL);

	r = execvp(argv[0], argv);
	if (r < 0) {
		syslog(LOG_ERR, "exec %s failed:%m", argv[0]);
		exit(EXIT_EXEC_FAILED);
	}
	exit(0);		/* Not reached */
}

static int execute_cmd(char *const argv[], int *status,
		       const struct timespec *cmd_timeout,
		       const struct timespec *term_timeout)
{
	/* Block signals */
	sigset_t mask, oldmask;
	pid_t cpid;
	int rc;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigaddset(&mask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &mask, &oldmask) < 0) {
		syslog(LOG_ERR, "%s: sigprocmask failed %m", __func__);
		return -1;
	}

	cpid = start_cmd(argv);
	if (cpid <= 0)
		rc = -1;
	else
		rc = wait_for_child(cpid, status, cmd_timeout, term_timeout);

	sigprocmask(SIG_SETMASK, &oldmask, NULL);
	return rc;
}

static void ipmi_health_check(char *const argv[])
{
	struct timespec cmd_timeout = { timeout, 0 };
	struct timespec term_timeout = { DEF_TERM_TIMEOUT, 0 };
	int status;
	int rc;
	const char *fail_msg = "BMC Health check failed";

	if (find_ipmi_dev() == NULL) {
		syslog(LOG_WARNING, "%s: No ipmi device found", fail_msg);
	}

	dbg("%s:Interval = %ld, timeout=%ld\n", __func__,
		cmd_timeout.tv_sec, term_timeout.tv_sec);

	rc = execute_cmd(argv, &status, &cmd_timeout, &term_timeout);
	if (rc > 0) {
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			syslog(LOG_DEBUG, "BMC health check succeeded.");
		else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			syslog(LOG_WARNING, "%s: command %s exit code %d.",
			       fail_msg, argv[0], WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			syslog(LOG_WARNING, "%s: command %s exit code %d.",
			       fail_msg, argv[0], WTERMSIG(status));
		else
			syslog(LOG_WARNING, "%s: command %s wait status 0x%x.",
			       fail_msg, argv[0], status);
	} else if (rc < 0)
		syslog(LOG_WARNING, "%s: Failed to start command", fail_msg);
	else if (rc == 0)
		syslog(LOG_WARNING,
		       "%s: Failed to get exit status of command %s", fail_msg,
		       argv[9]);
}

static struct option hc_options[] = {
	{"verbose", no_argument, 0, 'v'},
	{"interval", required_argument, 0, 'i'},
	{"timeout", required_argument, 0, 't'},
	{0, 0, 0, 0},
};

const char *usage_fmt =
    "Usage: %s [--interval] [--timeout] [--verbose] [cmd args..]\n";

int main(int argc, char *argv[])
{
	int option_index = 0;
	int c;
	char *endptr;
	char * const *check_cmd;

	openlog(NULL, LOG_PID, LOG_DAEMON);
	setlogmask(setlogmask(0) & ~LOG_MASK(LOG_DEBUG));
	dbg("Starting %s", argv[0]);

	if (setup_signals() < 0)
		exit(1);

	while(1) {
		c = getopt_long(argc, argv, "vi:t:", hc_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'i':
			interval = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				fprintf(stderr, usage_fmt, argv[0]);
				exit(1);
			}
			break;
		case 't':
			timeout = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				fprintf(stderr, usage_fmt, argv[0]);
				exit(1);
			}
			break;
		case 'v':
			if (!debug++)
				setlogmask(setlogmask(0) | LOG_MASK(LOG_DEBUG));
			break;
		default:
			fprintf(stderr, usage_fmt, argv[0]);
			exit(1);
		}
	}

	if (optind >= argc)
		check_cmd = ipmi_cmd;
	else
		check_cmd = &argv[optind];

	while(!done) {
		ipmi_health_check(check_cmd);
		if (!done)
			sleep(interval);

	}
	syslog(LOG_INFO, "Terminating %s", argv[0]);
	closelog();
	exit(0);
}
