#	$OpenBSD: Makefile,v 1.58 2024/01/19 20:06:00 miod Exp $

FS=		floppy${OSrev}.img
FSSIZE=		2880
FSDISKTYPE=	floppy
MOUNT_POINT=	/mnt
MTREE=		${UTILS}/mtree.conf
RAMDISK=	RAMDISKU1

LISTS=		${.CURDIR}/list
UTILS=		${.CURDIR}/../../miniroot

MRDISKTYPE=	rdroot
MRMAKEFSARGS=	-o disklabel=${MRDISKTYPE},minfree=0,density=4096

all: ${FS}

${FS}: bsd.gz
	dd if=/dev/zero of=${FS} bs=512 count=${FSSIZE}
	vnconfig -v -t ${FSDISKTYPE} ${FS} > vnd
	echo '/ *' | disklabel -wAT- `cat vnd`
	newfs -O 1 -m 0 -o space -i 524288 -c ${FSSIZE} -b 4096 -f 512 /dev/r`cat vnd`a
	mount /dev/`cat vnd`a ${MOUNT_POINT}
	install -c -m 555 -o root -g wheel \
	    ${DESTDIR}/usr/mdec/ofwboot ${MOUNT_POINT}/ofwboot
	installboot -v -r ${MOUNT_POINT} `cat vnd` \
	    ${DESTDIR}/usr/mdec/bootblk ${MOUNT_POINT}/ofwboot
	install -c -m 555 -o root -g wheel bsd.gz ${MOUNT_POINT}/bsd
	df -i ${MOUNT_POINT}
	umount ${MOUNT_POINT}
	vnconfig -u `cat vnd`
	rm -f vnd

bsd.gz: bsd.rd
	objcopy -S -R .comment -R .SUNW_ctf \
	    -K rd_root_size -K rd_root_image \
	    bsd.rd bsd.strip
	gzip -9cn bsd.strip > bsd.gz

bsd.rd: mr.fs
	cp bsd bsd.rd
	rdsetroot bsd.rd mr.fs

bsd:
	cd ${.CURDIR}/../../../sys/arch/${MACHINE}/compile/${RAMDISK} && \
	    su ${BUILDUSER} -c '${MAKE} config && ${MAKE} clean && exec ${MAKE} ${MFLAGS}'
	cp -p ${.CURDIR}/../../../sys/arch/${MACHINE}/compile/${RAMDISK}/obj/bsd bsd

mr.fs: instbin bsd
	rm -rf $@.d
	install -d -o root -g wheel $@.d
	mtree -def ${MTREE} -p $@.d -u
	CURDIR=${.CURDIR} OBJDIR=${.OBJDIR} OSrev=${OSrev} \
	    TARGDIR=$@.d UTILS=${UTILS} RELEASEDIR=${RELEASEDIR} \
	    sh ${UTILS}/runlist.sh ${LISTS}
	rm $@.d/instbin
	makefs ${MRMAKEFSARGS} $@ $@.d

instbin.mk instbin.cache instbin.c: instbin.conf
	crunchgen -E -D ${.CURDIR}/../../.. -L ${DESTDIR}/usr/lib \
	    -c instbin.c -e instbin -m instbin.mk instbin.conf

instbin: instbin.mk instbin.cache instbin.c
	${MAKE} ${MFLAGS} -f instbin.mk SRCLIBDIR=${.CURDIR}/../../../lib all

instbin.conf: ${LISTS}
	awk -f ${UTILS}/makeconf.awk  ${LISTS} > instbin.conf

unconfig:
	-umount -f ${MOUNT_POINT}
	-[ -f vnd ] && vnconfig -u `cat vnd` && rm -f vnd

.ifdef RELEASEDIR
install:
	cp ${FS} ${RELEASEDIR}
.endif

clean cleandir:
	rm -f *.core mr.fs instbin instbin.mk instbin.cache \
	    lib*.a lib*.olist instbin.map instbin.conf \
	    *.o *.lo *.c bsd bsd.rd bsd.strip bsd.gz ${FS}
	rm -rf mr.fs.d

.include <bsd.obj.mk>
