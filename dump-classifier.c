/*
 * Copyright (c) 2018, Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <argp.h>
#include <inttypes.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NSEC_TO_SEC 1e9

#define NUM_FILTERS 8
#define NUM_ENTRIES 64

enum traffic_flags {
	TRAFFIC_FLAGS_TXTIME,
};

struct tc_filter {
	char *name;
	struct bpf_program prog;
	unsigned int flags;
};

struct sched_entry {
	uint8_t command;
	uint32_t gatemask;
	uint32_t interval;
};

struct schedule {
	struct sched_entry entries[NUM_ENTRIES];
	uint64_t base_time;
	size_t current_entry;
	size_t num_entries;
	uint64_t cycle_time;
};

static struct argp_option options[] = {
	{"sched-file", 's', "SCHED_FILE", 0, "File containing the schedule" },
	{"dump-file", 'd', "DUMP_FILE", 0, "File containing the tcpdump dump" },
	{"filters-file", 'f', "FILTERS_FILE", 0, "File containing the classfication filters" },
	{"base-time", 'b', "TIME", 0, "Timestamp indicating when the schedule starts" },
	{ 0 }
};

static struct tc_filter traffic_filters[NUM_FILTERS];
static FILE *sched_file, *dump_file, *filters_file;
static struct schedule schedule;
static uint64_t base_time;

static error_t parser(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'd':
		dump_file = fopen(arg, "r");
		if (!dump_file) {
			perror("Could not open file, fopen");
			exit(EXIT_FAILURE);
		}
		break;
	case 's':
		sched_file = fopen(arg, "r");
		if (!sched_file) {
			perror("Could not open file, fopen");
			exit(EXIT_FAILURE);
		}
		break;
	case 'f':
		filters_file = fopen(arg, "r");
		if (!filters_file) {
			perror("Could not open file, fopen");
			exit(EXIT_FAILURE);
		}
		break;
	case 'b':
		base_time = strtoull(arg, NULL, 0);
		break;
	}

	return 0;
}

static struct argp argp = { options, parser };

static void usage(void)
{
	fprintf(stderr, "dump-classifier -s <sched-file> -d <dump-file> -f <filters-file> -b <base-time>\n");
}

static int parse_schedule(FILE *file, struct schedule *schedule,
			  size_t max_entries, uint64_t base_time)
{
	uint32_t interval, gatemask;
	size_t i = 0;

	while (fscanf(file, "%*s %x %" PRIu32 "\n",
		      &gatemask, &interval) != EOF)  {
		struct sched_entry *entry;

		if (i >= max_entries)
			return -EINVAL;

		entry = &schedule->entries[i];

		entry->gatemask = gatemask;
		entry->interval = interval;

		i++;
	}

	schedule->base_time = base_time;
	schedule->current_entry = 0;
	schedule->num_entries = i;

	return i;

}

static int parse_filters(pcap_t *handle, FILE *file,
			 struct tc_filter *filters, size_t num_filters)
{
	char *name, *expression;
	size_t i = 0;
	int err;

	while (i < num_filters && fscanf(file, "%ms :: %m[^\n]s\n",
					 &name, &expression) != EOF)  {
		struct tc_filter *filter = &filters[i];

		filter->name = name;

		err = pcap_compile(handle, &filter->prog, expression,
				   1, PCAP_NETMASK_UNKNOWN);
		if (err < 0) {
			pcap_perror(handle, "pcap_compile");
			return -EINVAL;
		}

		i++;
	}

	return i;
}

/* libpcap re-uses the timeval struct for nanosecond resolution when
 * PCAP_TSTAMP_PRECISION_NANO is specified.
 */
static uint64_t tv_to_nanos(const struct timeval *tv)
{
	return tv->tv_sec * NSEC_TO_SEC + tv->tv_usec;
}

static struct sched_entry *next_entry(struct schedule *schedule)
{
	schedule->current_entry++;

	if (schedule->current_entry >= schedule->num_entries)
		schedule->current_entry = 0;

	return &schedule->entries[schedule->current_entry];
}

static struct sched_entry *first_entry(struct schedule *schedule)
{
	schedule->current_entry = 0;

	return &schedule->entries[0];
}

static struct sched_entry *advance_until(struct schedule *schedule,
					 uint64_t ts, uint64_t *now)
{
	struct sched_entry *first, *entry;
	uint64_t cycle = 0;
	uint64_t n;

	entry = first = first_entry(schedule);

	if (!schedule->cycle_time) {
		do {
			cycle += entry->interval;
			entry = next_entry(schedule);
		} while (entry != first);

		schedule->cycle_time = cycle;
	}

	cycle = schedule->cycle_time;

	n = (ts - schedule->base_time) / cycle;
	*now = schedule->base_time + (n * cycle);

	do {
		if (*now + entry->interval > ts)
			break;

		*now += entry->interval;
		entry = next_entry(schedule);
	} while (true);

	return entry;
}

static int match_packet(const struct tc_filter *filters, int num_filters,
			const struct pcap_pkthdr *hdr,
			const uint8_t *frame)
{
	int err;
	int i;

	for (i = 0; i < num_filters; i++) {
		const struct tc_filter *f = &filters[i];

		err = pcap_offline_filter(&f->prog, hdr, frame);
		if (!err) {
			/* The filter for traffic class 'i' doesn't
			 * match the packet
			 */
			continue;
		}

		return i;
	}

	/* returning 'num_filters' means that the packet matches none
	 * of the filters, so it's a Best Effort packet.
	 */
	return num_filters;
}

static int classify_frames(pcap_t *handle, const struct tc_filter *tc_filters,
			   int num_filters, struct schedule *schedule)
{
	struct sched_entry *entry;
	struct pcap_pkthdr *hdr;
	const uint8_t *frame;
	uint64_t now, ts;
	int err;

	now = schedule->base_time;

	/* Ignore frames until we get to the base_time of the
	 * schedule. */
	do {
		err = pcap_next_ex(handle, &hdr, &frame);
		if (err < 0) {
			pcap_perror(handle, "pcap_next_ex");
			return -EINVAL;
		}

		ts = tv_to_nanos(&hdr->ts);
	} while (ts <= now);

	do {
		const char *name, *ontime;
		int64_t offset;
		int tc;

		ts = tv_to_nanos(&hdr->ts);

		entry = advance_until(schedule, ts, &now);

		tc = match_packet(tc_filters, num_filters, hdr, frame);

		if (tc < num_filters)
			name = tc_filters[tc].name;
		else
			name = "BE";

		if (entry->gatemask & (1 << tc))
			ontime = "ontime";
		else
			ontime = "late";

		offset = ts - now;

		/* XXX: what more information might we need? */
		printf("%" PRIu64 " %" PRIu64 " \"%s\" \"%s\" %" PRId64 " %#x\n",
		       ts, now, name, ontime, offset, entry->gatemask);
	} while (pcap_next_ex(handle, &hdr, &frame) >= 0);

	return 0;
}

static void free_filters(struct tc_filter *filters, int num_filters)
{
	int i;

	for (i = 0; i < num_filters; i++) {
		struct tc_filter *f = &filters[i];

		free(f->name);
	}
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int err, num;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);

	if (!dump_file || !sched_file || !filters_file || !base_time) {
		usage();
		exit(EXIT_FAILURE);
	}

	err = parse_schedule(sched_file, &schedule, NUM_ENTRIES, base_time);
	if (err <= 0) {
		fprintf(stderr, "Could not parse schedule file (or file empty)\n");
		exit(EXIT_FAILURE);
	}

	handle = pcap_fopen_offline_with_tstamp_precision(
		dump_file, PCAP_TSTAMP_PRECISION_NANO, errbuf);
	if (!handle) {
		fprintf(stderr, "Could not parse dump file\n");
		exit(EXIT_FAILURE);
	}

	num = parse_filters(handle, filters_file,
			    traffic_filters, NUM_FILTERS);
	if (err < 0) {
		fprintf(stderr, "Could not filters file\n");
		exit(EXIT_FAILURE);
	}

	err = classify_frames(handle, traffic_filters, num, &schedule);
	if (err < 0) {
		fprintf(stderr, "Could not classify frames\n");
		exit(EXIT_FAILURE);
	}

	free_filters(traffic_filters, num);

	pcap_close(handle);

	return 0;
}
