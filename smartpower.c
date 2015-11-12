/*
 * @file smartpower.c: ODROID Smart Power data logger
 *
 * @author: Aliaksei Katovich <aliaksei.katovich@gmail.com>
 *
 * Copyright (C) 2013  Aliaksei Katovich
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <linux/types.h>
#include <linux/input.h>
#include <linux/hidraw.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#define err(fmt, args...) { \
	fprintf(stderr, "(ee) "fmt, ##args); \
	fprintf(stderr, "(ii) %s:%d: %s, %d\n", __func__, __LINE__, \
		strerror(errno), errno); \
}

#define msg(fmt, args...) fprintf(stderr, "(==) "fmt, ##args)

#define MAX_BUF		65
#define MAX_SLEEP	100 /* us */

#define	FLG_DATA	0x37
#define FLG_STARTSTOP	0x80
#define FLG_STATUS	0x81
#define FLG_ONOFF	0x82
#define FLG_VERSION	0x83

const char *bus_str(int bus)
{
	switch (bus) {
	case BUS_USB:
		return "USB";
		break;
	case BUS_HIL:
		return "HIL";
		break;
	case BUS_BLUETOOTH:
		return "Bluetooth";
		break;
	case BUS_VIRTUAL:
		return "Virtual";
		break;
	default:
		return "Other";
		break;
	}
}

static int smartp_open(const char *dev)
{
	int fd;

	fd = open(dev, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		err("%s: unable to open device\n", dev);

		if (errno == 13) {
			msg("become root or escalate priviledge\n");
			exit(errno);
		}

		return -errno;
	}

	return fd;
}

static int csv;
static char sep;
static int ts_style;
static double ts_start;

static void smartp_printd(const unsigned char *data)
{
	struct timeval tv;
	double ts;
	unsigned long long ts_sec, ts_usec;

	if (ts_start == 0.0) {
		gettimeofday(&tv, NULL);
		ts_start = (double) tv.tv_sec + (double) tv.tv_usec / 1000000.0;
		if (ts_style == 0)
			printf("0.0%c%s\n", sep, data);
		else
			printf("[%5u.%06u] %s\n", 0, 0, data);
		return;
	}

	gettimeofday(&tv, NULL);
	ts = (double) tv.tv_sec + (double) tv.tv_usec / 1000000.0 - ts_start;
	if (ts_style == 0) {
		printf("%f%c%s\n", ts, sep, data);
	} else {
		ts_sec = ts;
		ts_usec = (ts - (unsigned long long) ts) * 1000000.0;
		printf("[%5u.%06u] %s\n", (unsigned int) ts_sec,
			(unsigned int) ts_usec, data);
	}
}

static void smartp_csv(unsigned char *data, size_t len, unsigned int start)
{
	int i, space = 0;
	unsigned char *ptr;

	for (i = 0, ptr = &data[start]; *ptr != '\0'; ptr++) {
		if (*ptr == ' ' && space == 0) {
			data[i] = ',';
			space++;
			i++;
		} else if (*ptr == '.' || (*ptr >= 0x30 && *ptr <= 0x39)) {
			data[i] = *ptr;
			space = 0;
			i++;
		}
	}
	data[i] = '\0';
}

#define SMARTP_READ_MAX 100000

static int smartp_read(int fd, unsigned char *buf, size_t len)
{
	int rc = -1;
	int i;

	memset(buf, 0, len);

	for (i = 0; i < SMARTP_READ_MAX; i++) {
		rc = read(fd, buf, len);
		if (rc >= 0)
			break;
	}

	if (rc < 0) {
		err("failed to read %lu bytes\n", (unsigned long)len);
		return rc;
	}

	switch (buf[0]) {
	case 0x37:
		if (!csv) {
			smartp_printd(&buf[2]);
		} else {
			smartp_csv(buf, len, 2);
			smartp_printd(buf);
		}
		break;
	case 0x81:
		printf("Power %s, record %s\n",
			buf[2] == 0 ? "off" : "on",
			buf[1] == 0 ? "off" : "on");
		break;
	case 0x83:
		printf("Version: %s\n", buf);
		break;
	default:
		printf("????:");
		for (i = 0; i < rc; i++)
			printf("%hhx ", buf[i]);
		printf("\n");
	}

	return rc;
}

static int smartp_send(int fd, unsigned char *buf, size_t len)
{
	int rc;

	rc = write(fd, buf, len);
	if (rc < 0) {
		err("cmd=%02x\n", buf[1]);
		return rc;
	}

	return rc;
}

static int smartp_toggle_record(int fd)
{
	int rc;
	unsigned char cmd[2] = { 0x00, FLG_STARTSTOP, };
	unsigned char buf[3];

	rc = smartp_send(fd, cmd, sizeof(cmd));
	if (rc < 0)
		return rc;

	/* update status */
	cmd[1] = FLG_STATUS;
	rc = smartp_send(fd, cmd, sizeof(cmd));
	if (rc < 0)
		return rc;

	return smartp_read(fd, buf, sizeof(buf));
}

static int smartp_toggle_power(int fd)
{
	int rc;
	unsigned char cmd[2] = { 0x00, FLG_ONOFF, };
	unsigned char buf[3];

	rc = smartp_send(fd, cmd, sizeof(cmd));
	if (rc < 0)
		return rc;

	/* update status */
	cmd[1] = FLG_STATUS;
	rc = smartp_send(fd, cmd, sizeof(cmd));
	if (rc < 0)
		return rc;

	usleep(100000); /* wait status update; time gained experimentally */
	return smartp_read(fd, buf, sizeof(buf));
}

#define MAX_VERSION 17

static int smartp_version(int fd)
{
	int rc;
	unsigned char buf[MAX_VERSION];
	unsigned char cmd[2] = { 0x00, FLG_VERSION, };

	rc = smartp_send(fd, cmd, sizeof(cmd));
	if (rc < 0)
		return rc;

	memset(buf, 0, sizeof(buf));
	return smartp_read(fd, buf, sizeof(buf));
}

#define MAX_DATA 34

static int smartp_getdata(int fd)
{
	int rc;
	unsigned char buf[MAX_DATA];
	unsigned char cmd[2] = { 0x00, FLG_DATA, };

	rc = smartp_send(fd, cmd, sizeof(cmd));
	if (rc < 0)
		return rc;

	memset(buf, 0, sizeof(buf));
	return smartp_read(fd, buf, sizeof(buf));
}

#define SMARTP_VENDOR	0x04d8
#define SMARTP_PRODUCT	0x003f

#define HIDRAW_CLASS	"/sys/class/hidraw"

static int smartp_probe(void)
{
	int i = 0;
	int rc;
	int fd = -1;
	struct hidraw_devinfo info;
	char name[80];
	DIR *dir;
	struct dirent *dentry;

	dir = opendir(HIDRAW_CLASS);
	if (!dir) {
		err(HIDRAW_CLASS": failed to open directory\n");
		msg("try to enable CONFIG_HIDRAW in kernel config\n");
		return -errno;
	}

	while ((dentry = readdir(dir))) {
		if (dentry->d_name[0] == '.')
			continue;
		i++;
		snprintf(name, sizeof(name), "/dev/%s", dentry->d_name);
		fd = smartp_open(name);
		if (fd < 0)
			continue;
		rc = ioctl(fd, HIDIOCGRAWINFO, &info);
		if (rc < 0)
			continue;
		if (info.vendor == SMARTP_VENDOR && info.product == SMARTP_PRODUCT) {
			msg("Detected smartp at %s\n", name);
			break;
		}
	}
	closedir(dir);

	if (i == 0)
		msg("smart power device is not connected\n");

	return fd;
}

static int smartp_verbose(int fd, const char *dev)
{
	int rc;
	unsigned char buf[256];
	struct hidraw_devinfo info;

	memset(&info, 0x0, sizeof(info));
	memset(buf, 0x0, sizeof(buf));

	/* Get Raw Name */
	rc = ioctl(fd, HIDIOCGRAWNAME(256), buf);
	if (rc < 0) {
		err("%s: failed to get raw name\n", dev);
		return -errno;
	}
	printf("Raw name: %s\n", buf);

	/* Get Physical Location */
	rc = ioctl(fd, HIDIOCGRAWPHYS(256), buf);
	if (rc < 0) {
		err("%s: failed to get physical location\n", dev);
		return -errno;
	}
	printf("Raw phys: %s\n", buf);

	/* Get Raw Info */
	rc = ioctl(fd, HIDIOCGRAWINFO, &info);
	if (rc < 0) {
		err("%s: failed to get raw info\n", dev);
		return -errno;
	}
	printf("Raw info: bustype %d (%s), vendor 0x%04hx, product 0x%04hx\n",
		info.bustype, bus_str(info.bustype), info.vendor, info.product);
	return 0;
}

static int signal_caught;

void signal_handler(int signum)
{
	signal_caught = signum;
}

static void help(const char *name)
{
	printf("Usage: %s [options]\n", name);
	printf("Options:\n");
	printf("  -h, --help         print this message\n");
	printf("  -p, --power        toggle power supply on/off\n");
	printf("  -r, --record       toggle power consumption recording\n");
	printf("  -v, --verbose      print hidraw details\n");
	printf("  -k, --kernel	     dmesg like time stamps\n");
	printf("  -c, --csv          produce csv output (default raw)\n");
	printf("  -s, --samples <n>  take n samples and exit\n");
	printf("  -d, --dev <dev>    path to hidraw device node\n");
}

static int opt(const char *arg, const char *args, const char *argl)
{
	return (strcmp(arg, args) == 0 || strcmp(arg, argl) == 0);
}

int main(int argc, char **argv)
{
	int fd;
	int i, samples = 0;
	const char *dev = NULL;
	const char *arg;
	int power = 0, record = 0, verbose = 0;

	for (i = 0; i < argc; i++) {
		arg = argv[i];
		if (opt(arg, "-d", "--dev")) {
			i++;
			dev = argv[i];
			continue;
		}
		if (opt(arg, "-s", "--samples")) {
			i++;
			samples = atoi(argv[i]);
			continue;
		}
		if (opt(arg, "-p", "--power")) {
			power = 1;
			continue;
		}
		if (opt(arg, "-r", "--record")) {
			record = 1;
			continue;
		}
		if (opt(arg, "-v", "--verbose")) {
			verbose = 1;
			continue;
		}
		if (opt(arg, "-k", "--kernel")) {
			ts_style = 1;
			csv = 0;
			sep = ' ';
			continue;
		}
		if (opt(arg, "-c", "--csv")) {
			csv = 1;
			sep = ',';
			ts_style = 0;
			continue;
		}
		if (opt(arg, "-h", "--help")) {
			help(argv[0]);
			return 0;
		}
	}

	if (dev)
		fd = smartp_open(dev);
	else
		fd = smartp_probe();

	if (fd < 0)
		return fd;

	if (verbose == 1) {
		smartp_verbose(fd, dev);
		smartp_version(fd);
	}

	if (record == 1)
		return smartp_toggle_record(fd);

	if (power == 1)
		return smartp_toggle_power(fd);

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	if (samples == 0) {
		while (!signal_caught)
			smartp_getdata(fd);
	} else {
		for (i = 0; i < samples && !signal_caught; i++)
			smartp_getdata(fd);
	}

	close(fd);
	return 0;
}
