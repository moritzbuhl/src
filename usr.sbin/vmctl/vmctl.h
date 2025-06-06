/*	$OpenBSD: vmctl.h,v 1.40 2025/05/12 17:23:41 dv Exp $	*/

/*
 * Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef VMCTL_PARSER_H
#define VMCTL_PARSER_H

#define VMCTL_CU	"/usr/bin/cu"

enum actions {
	NONE,
	CMD_CONSOLE,
	CMD_CREATE,
	CMD_LOAD,
	CMD_LOG,
	CMD_RELOAD,
	CMD_RESET,
	CMD_START,
	CMD_STATUS,
	CMD_STOP,
	CMD_STOPALL,
	CMD_WAITFOR,
	CMD_PAUSE,
	CMD_UNPAUSE,
	CMD_SEND,
	CMD_RECEIVE,
};

struct ctl_command;

struct parse_result {
	enum actions		 action;
	uint32_t		 id;
	char			*name;
	char			*path;
	char			*isopath;
	size_t			 size;
	int			 nifs;
	char			**nets;
	int			 nnets;
	size_t			 ndisks;
	char			**disks;
	int			*disktypes;
	int			 verbose;
	char			*instance;
	unsigned int		 flags;
	unsigned int		 mode;
	unsigned int		 bootdevice;
	struct ctl_command	*ctl;
};

struct ctl_command {
	const char		*name;
	enum actions		 action;
	int			(*main)(struct parse_result *, int, char *[]);
	const char		*usage;
	int			 has_pledge;
};

extern struct imsgbuf	*ibuf;

/* main.c */
int	 vmmaction(struct parse_result *);
int	 parse_ifs(struct parse_result *, char *, int);
int	 parse_network(struct parse_result *, char *);
void	 parse_size(struct parse_result *, char *, const char *);
int	 parse_disktype(const char *, const char **);
int	 parse_disk(struct parse_result *, char *, int);
int	 parse_vmid(struct parse_result *, char *, int);
int	 parse_instance(struct parse_result *, char *);
void	 parse_free(struct parse_result *);
int	 parse(int, char *[]);
__dead void
	 ctl_openconsole(const char *);

/* vmctl.c */
int	 open_imagefile(int, const char *, int,
	    struct virtio_backing *, off_t *);
int	 create_imagefile(int, const char *, const char *, uint64_t, const char **);
int	 vm_start(uint32_t, const char *, size_t, int, char **, int,
	    char **, int *, char *, char *, char *, unsigned int);
int	 vm_start_complete(struct imsg *, int *, int);
void	 terminate_vm(uint32_t, const char *, unsigned int);
int	 terminate_vm_complete(struct imsg *, int *, unsigned int);
void	 waitfor_vm(uint32_t, const char *);
void	 pause_vm(uint32_t, const char *);
int	 pause_vm_complete(struct imsg *, int *);
void	 unpause_vm(uint32_t, const char *);
int	 unpause_vm_complete(struct imsg *, int *);
void	 send_vm(uint32_t, const char *);
void	 vm_receive(uint32_t, const char *);
int	 check_info_id(const char *, uint32_t);
void	 get_info_vm(uint32_t, const char *, enum actions, unsigned int);
int	 add_info(struct imsg *, int *);
const char
	*vm_state(unsigned int);
int	 print_vm_info(struct vmop_info_result *, size_t);
void	 terminate_all(struct vmop_info_result *, size_t, unsigned int);
__dead void
	 vm_console(struct vmop_info_result *, size_t);

/* XXX remove once vmctl is cleaned up of imsg shenanigans. */
#define IMSG_SIZE_CHECK(imsg, p) do {					\
	if (IMSG_DATA_SIZE(imsg) < sizeof(*p))				\
	fatalx("bad length imsg received (%s)", #p);			\
} while (0)
#define IMSG_DATA_SIZE(imsg)	((imsg)->hdr.len - IMSG_HEADER_SIZE)

#endif /* VMCTL_PARSER_H */
