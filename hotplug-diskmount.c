/*
 * Modified by jpz4085
 * Written by Alexey Vatchenko <av@bsdua.org>.
 * Public domain.
 */
#include <sys/types.h>
#include <sys/param.h>

#include <sys/disklabel.h>
#include <sys/dkio.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_VOL_ROOT	"/media"
#define DEFAULT_VOL_DB		"/.db"
#define DB_LOCK			".lock"
#define DEV_ROOT		"/dev"
#define DISKNAME_SIZE		32
#define CHECK_MEDIA_TIMEOUT	2

static uid_t mp_uid = 0;	/* default owner of mountpoint */
static gid_t mp_gid = 0;	/* default group of mountpoint */
/* default access permissions of mountpoint */
#define DEFAULT_PERM	(S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
static mode_t mp_perm = DEFAULT_PERM;
static int ignore_umask = 0;
static int readonly_flag = 0;	/* 0 - rw, 1 - ro all fs, 2 - ro for dirty fs */
static int fsck_flag = 1;	/* 0 - never, 1 - always, 2 - on dirty fs */
static int has_ntfs3g = 0;
static int has_ntfs_label = 0;
static int has_exfat_fuse = 0;
static int has_exfat_label = 0;
static int use_fuse = 1;	/* use FUSE by-default */
static volatile sig_atomic_t quit_flag = 0;
static int lockdb_fd = -1;
static pid_t mounter_pid[MAXPARTITIONS];
static char vol_root[MAXPATHLEN] = DEFAULT_VOL_ROOT;
static char vol_db[MAXPATHLEN] = DEFAULT_VOL_ROOT DEFAULT_VOL_DB;
static char vol_lock[MAXPATHLEN] = DEFAULT_VOL_ROOT DEFAULT_VOL_DB "/" DB_LOCK;

void	usage(const char *prog);
void	sig_term(int sig);
int	get_disk_label(const char *devname, char **dev,
	    struct disklabel *label);
void	lock_db(void);
void	unlock_db(void);
void	prepare_disk_name(char *dskname, const char *packname);
int	compose_mp(const char *dskname, char **mp, int multi, int cnt);
int	create_mp(const char *dskname, char **mp, int multi, int cnt);
int	save_mp_info(const char *devname, int pi, const char *mp);
int	do_mountany(int idx, const char *dev, const char *mp, int rd,
	    u_int8_t fstype);
int	do_mount(const char *dev, const char *mp, int rd);
int	do_fsck(const char *dev);
int	check_ntfs3g(void);
int	check_exfat(void);
int	do_ntfs3g(int idx, const char *dev, const char *mp, int rd);
int	do_exfatm(int idx, const char *dev, const char *mp, int rd);
int	get_ntfs3g_label(const char *dev, char *diskname);
int	get_exfat_label(const char *dev, char *diskname);
int	get_part_label (const char *dev, char *partlabel);
int	kill_mounter(pid_t pid, int forceifbusy);
void	mount_part(int idx, const char *dev, const char *mp, u_int8_t fstype);
void	mount_disk(const char *devname, char *dev, const char *dskname,
	    struct disklabel *label);
int	perm_str2val(const char *str, mode_t *mode);
int	remove_mount_points(const char *devname, int umnt, int forceifbusy);
int	create_root(void);

void
usage(const char *prog)
{
	printf("Usage:\n"
	    "%s [-d dir] attach [options] device\n"
	    "%s [-d dir] init\n"
	    "%s [-d dir] cleanup device\n"
	    "\nAttach options:\n"
	    "\t -u user         - change owner of mount point\n"
	    "\t -g group        - change group of mount point\n"
	    "\t -m mode         - change mode of mount point\n"
	    "\t -r all|dirty    - mount filesystem readonly\n"
	    "\t -f never|dirty  - fsck filesystem\n"
	    "\t -F              - disable FUSE\n",
	    prog, prog, prog);
}

void
sig_term(int sig)
{
	quit_flag = 1;
}

int
get_disk_label(const char *devname, char **dev, struct disklabel *label)
{
	int fd;
	int error, rv;
	size_t sz;

	sz = sizeof(DEV_ROOT) + strlen(devname) + 1 + 1;
	*dev = (char *)malloc(sz);
	if (*dev == NULL)
		return (ENOMEM);
	strlcpy(*dev, DEV_ROOT, sz);
	strlcat(*dev, "/", sz);
	strlcat(*dev, devname, sz);
	strlcat(*dev, "c", sz);

	fd = open(*dev, O_RDONLY);
	rv = errno;
	if (fd == -1) {
		free(*dev);
		return (rv);
	}

	error = ioctl(fd, DIOCGDINFO, label);
	rv = errno;
	close(fd);
	if (error == -1) {
		free(*dev);
		return (rv);
	}

	return (0);
}

void
lock_db(void)
{
	/*
	 * FUSE fs process inherits locked file descriptor and even after close
	 * another instance of mounter cannot lock. We use O_CLOEXEC to close
	 * this descriptor for newly execed processes.
	 */
	lockdb_fd = open(vol_lock, O_CREAT | O_RDONLY | O_CLOEXEC);
	if (lockdb_fd == -1)
		return;

	if (flock(lockdb_fd, LOCK_EX) == -1) {
		/* Most likely, filesystem doesn't support locking */
		close(lockdb_fd);
		lockdb_fd = -1;
	}
}

void
unlock_db(void)
{
	if (lockdb_fd != -1) {
		close(lockdb_fd);
		lockdb_fd = -1;
	}
}

void
prepare_disk_name(char *dskname, const char *packname)
{
	int i, j, st, sz;

	/* Skip leading spaces */
	for (i = 0; i < DISKNAME_SIZE - 1; i++) {
		if (!isspace(packname[i]))
			break;
	}

	/* Skip trailing spaces */
	st = i;
	for (i = DISKNAME_SIZE - 1; i > st; i--) {
		if (!isspace(packname[i - 1]) && packname[i - 1] != '\0')
			break;
	}
	sz = i;

	for (i = st, j = 0; i < sz; i++, j++) {
		if (packname[i] == '/')
			dskname[j] = '_';
		else
			dskname[j] = packname[i];
	}
	dskname[j] = '\0';

	if (*dskname == '\0')
		strlcpy(dskname, "NONAME", DISKNAME_SIZE);
	if (*dskname == '.')
		*dskname = '_';	/* unhide mount points */
}

int
compose_mp(const char *dskname, char **mp, int multi, int cnt)
{
	size_t sz, dsklen, cntsz;
	int i, div;

	dsklen = strlen(dskname);
	sz = strlen(vol_root) + 1 + dsklen + 1;
	if (multi) {
		/* /vol/NameOfDisk-p1 */
		cntsz = 1;
		div = cnt;
		while ((div /= 10) > 0)
			cntsz++;

		sz += cntsz + 2;
	}

	*mp = (char *)malloc(sz);
	if (*mp == NULL)
		return (ENOMEM);
	*(*mp + sz - 1) = '\0';

	strlcpy(*mp, vol_root, sz);
	strlcat(*mp, "/", sz);
	strlcat(*mp, dskname, sz);

	if (multi) {
		strlcat(*mp, "-p", sz);
		div = cnt;
		for (i = sz - 2; i > sz - cntsz - 2; i--) {
			(*mp)[i] = '0' + div % 10;
			div /= 10;
		}
	}

	return (0);
}

int
create_mp(const char *dskname, char **mp, int multi, int cnt)
{
	int error;
	int i;
	char *p;
	size_t mpsz;
	mode_t old_umask;
	int old_errno;

	error = compose_mp(dskname, mp, multi, cnt);
	if (error != 0)
		return (error);

	mpsz = strlen(*mp);
	p = NULL;

	for (i = 1; i < 1000; i++) {
		if (ignore_umask)
			old_umask = umask(0);

		error = mkdir(*mp, mp_perm);
		old_errno = errno;

		if (error == -1 && errno == EEXIST) {
			error = rmdir(*mp);
			if (error == 0) {
				error = mkdir(*mp, mp_perm);
				old_errno = errno;
			}
		}
		if (error != -1)
			chown(*mp, mp_uid, mp_gid);

		if (ignore_umask)
			umask(old_umask);

		errno = old_errno;
		if (error != -1 || errno != EEXIST) {
			error = (error == -1) ? errno : 0;
			break;
		}

		if (p == NULL) {
			/* ' #NNN' */
			p = (char *)realloc(*mp, mpsz + 5 + 1);
			if (p == NULL) {
				error = ENOMEM;
				break;
			}
		}

		snprintf(p + mpsz, 5 + 1, " #%u", i);
		*mp = p;

		error = EEXIST;
	}

	if (error != 0)
		free(*mp);
	return (error);
}

int
save_mp_info(const char *devname, int pi, const char *mp)
{
	char *lnk;
	size_t sz;
	int error, rv;

	sz = strlen(vol_db) + 1 + strlen(devname) + 1 + 1;
	lnk = (char *)malloc(sz);
	if (lnk == NULL)
		return (ENOMEM);
	snprintf(lnk, sz, "%s/%s%c", vol_db, devname, 'a' + pi);
	unlink(lnk);
	error = symlink(mp, lnk);
	rv = (error == -1) ? errno : 0;
	free(lnk);
	return (rv);
}

/*
 * Return Values:
 * 	0		- OK
 * 	ECANCELED	- %MOUNT% command exited with non-zero exit code
 * 	other values
 */
int
do_mountany(int idx, const char *dev, const char *mp, int rd, u_int8_t fstype)
{
	int rv;

	if (fstype == FS_NTFS) {
	    if (has_ntfs3g && has_ntfs_label)
		rv = do_ntfs3g(idx, dev, mp, rd);
	    if (has_exfat_fuse && has_exfat_label)
		rv = do_exfatm(idx, dev, mp, rd);
	} else
		rv = do_mount(dev, mp, rd);
	return (rv);
}

/*
 * Return Values:
 * 	0		- OK
 * 	ECANCELED	- /sbin/mount exited with non-zero exit code
 * 	other values	- fork() returned with error
 */
int
do_mount(const char *dev, const char *mp, int rd)
{
	int pid;
	char opt[22]; /* -onodev,nosuid,rdonly */
	int status, error;

	strlcpy(opt, "-onodev,nosuid", sizeof(opt));
	if (rd)
		strlcat(opt, ",rdonly", sizeof(opt));

	pid = fork();
	if (pid == 0) {
		setsid();
		execl("/sbin/mount", "mount", opt, dev, mp, NULL);
		exit(errno);
	}

	error = ((pid > 0) ? 0 : errno);
	if (error == 0) {
		pid = waitpid(pid, &status, 0);
		if (pid == -1)
			error = errno;
		else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			error = ECANCELED;
	}

	return (error);
}

/*
 * Return Values:
 * 	0		- OK
 * 	ECANCELED	- /sbin/fsck exited with non-zero exit code
 * 	other values	- fork() returned with error
 */
int
do_fsck(const char *dev)
{
	int pid;
	int status, error;

	pid = fork();
	if (pid == 0) {
		setsid();
		execl("/sbin/fsck", "fsck", "-y", "-p", dev, NULL);
		exit(errno);
	}

	error = ((pid > 0) ? 0 : errno);
	if (error == 0) {
		pid = waitpid(pid, &status, 0);
		if (pid == -1)
			error = errno;
		else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			error = ECANCELED;
	}

	return (error);
}

int
check_ntfs3g(void)
{
	struct stat sb;

	return (stat("/usr/local/bin/ntfs-3g", &sb) == 0);
}

int
check_exfat(void)
{
	struct stat sb;

	return (stat("/usr/local/sbin/mount.exfat-fuse", &sb) == 0);
}

/*
 * Return Values:
 * 	0		- OK
 * 	ECANCELED	- /usr/local/bin/ntfs-3g exited with non-zero exit code
 * 	other values	- fork() returned with error
 */
int
do_ntfs3g(int idx, const char *dev, const char *mp, int rd)
{
	pid_t pid;
	char opt[57];
	int status, error;

	snprintf(opt, sizeof(opt), "-ono_detach,uid=%u,gid=%u,umask=%.3o%s",
		 mp_uid, mp_gid, mp_perm ^ 0777, rd ? ",ro" : "");

	mounter_pid[idx] = fork();
	if (mounter_pid[idx] == 0) {
		setsid();
		execl("/usr/local/bin/ntfs-3g", "ntfs-3g", opt, dev, mp, NULL);
		exit(errno);
	}

	error = ((mounter_pid[idx] > 0) ? 0 : errno);
	if (error == 0) {
		pid = waitpid(mounter_pid[idx], &status, WNOHANG);
		if (pid == -1)
			error = errno;
		else if (pid != 0)
			error = ECANCELED;
	}

	if (error != 0)
		mounter_pid[idx] = -1;
	return (error);
}

/*
 * Return Values:
 * 	0		- OK
 * 	ECANCELED	- /usr/local/sbin/mount.exfat-fuse exited with non-zero exit code
 * 	other values	- fork() returned with error
 */
int
do_exfatm(int idx, const char *dev, const char *mp, int rd)
{
	pid_t pid;
	char opt[57];
	int status, error;

	snprintf(opt, sizeof(opt), "-ouid=%u,gid=%u,umask=%.3o%s",
		 mp_uid, mp_gid, mp_perm ^ 0777, rd ? ",ro" : "");

	mounter_pid[idx] = fork();
	if (mounter_pid[idx] == 0) {
		setsid();
		execl("/usr/local/sbin/mount.exfat-fuse", "mount.exfat-fuse", opt, dev, mp, NULL);
		exit(errno);
	}

	error = ((mounter_pid[idx] > 0) ? 0 : errno);
	if (error == 0) {
		pid = waitpid(mounter_pid[idx], &status, WNOHANG);
		if (pid == -1)
			error = errno;
		else if (pid != 0)
			error = ECANCELED;
	}

	if (error != 0)
		mounter_pid[idx] = -1;
	return (error);
}

int
get_ntfs3g_label(const char *dev, char *diskname)
{
	int pid;
	char buf[DISKNAME_SIZE], *p;
	int fds[2];
	int status, error;
	ssize_t sz;

	if (pipe(fds) == -1)
		return (errno);

	pid = fork();
	if (pid == 0) {
		dup2(fds[1], 1);
		execl("/usr/local/sbin/ntfslabel", "ntfslabel", dev, NULL);
		exit(errno);
	} else if (pid < 0) {
		close(fds[0]);
		close(fds[1]);
		return (errno);
	}

	close(fds[1]);
	memset(buf, 0, sizeof(buf));
	sz = read(fds[0], buf, sizeof(buf) - 1);
	close(fds[0]);
	if (sz < 1) {
		error = errno;
		close(fds[0]);
		return (error);
	}

	p = strchr(buf, '\n');
	if (p != NULL)
		*p = '\0';
	if (*buf != '\0')
		memcpy(diskname, buf, sizeof(buf));

	return ((waitpid(pid, &status, 0) == pid) ? 0 : errno);
}

int
get_exfat_label(const char *dev, char *diskname)
{
	int pid;
	char buf[DISKNAME_SIZE], *p;
	int fds[2];
	int status, error;
	ssize_t sz;

	if (pipe(fds) == -1)
		return (errno);

	pid = fork();
	if (pid == 0) {
		dup2(fds[1], 1);
		execl("/usr/local/sbin/exfatlabel", "exfatlabel", dev, NULL);
		exit(errno);
	} else if (pid < 0) {
		close(fds[0]);
		close(fds[1]);
		return (errno);
	}

	close(fds[1]);
	memset(buf, 0, sizeof(buf));
	sz = read(fds[0], buf, sizeof(buf) - 1);
	close(fds[0]);
	if (sz < 1) {
		error = errno;
		close(fds[0]);
		return (error);
	}

	p = strchr(buf, '\n');
	if (p != NULL)
		*p = '\0';
	if (*buf != '\0')
		memcpy(diskname, buf, sizeof(buf));

	return ((waitpid(pid, &status, 0) == pid) ? 0 : errno);
}

int
get_part_label (const char *dev, char *partlabel)
{
	int fd, rv;
	int has_fat_label = 0;
	char *type_buff = alloca(8);
	char *name_buff = alloca(11);

	fd = open(dev, O_RDONLY);
	rv = errno;
	if (fd == -1) {
		close(fd);
		return (rv);
	}

	lseek(fd, 54, SEEK_SET);
    	read(fd, type_buff, 8);
    	if (!memcmp(type_buff, "FAT12   ", 8) ||
        	!memcmp(type_buff, "FAT16   ", 8)) {
        	lseek(fd, 43, SEEK_SET);
        	read(fd, name_buff, 11);
		has_fat_label = 1;
    	}
    
    	lseek(fd, 82, SEEK_SET);
    	read(fd, type_buff, 8);
    	if (!memcmp(type_buff, "FAT32   ", 8)) {
        	lseek(fd, 71, SEEK_SET);
        	read(fd, name_buff, 11);
		has_fat_label = 1;
    	}

	if (has_fat_label && *name_buff != '\0') {
		memset(partlabel, 0, DISKNAME_SIZE);
		memcpy(partlabel, name_buff, 11);
		close(fd);
		return (1);
	} else {
		close(fd);
		return (0);
	}
}

int
kill_mounter(pid_t pid, int forceifbusy)
{
	pid_t wpid;

	wpid = waitpid(pid, NULL, WNOHANG);
	if (wpid == pid)
		return (0);

	kill(pid, SIGTERM);
	sleep(1);
	wpid = waitpid(pid, NULL, WNOHANG);
	if (wpid == pid)
		return (0);
	if (forceifbusy) {
		kill(pid, SIGKILL);
		sleep(1);
		waitpid(pid, NULL, 0);
		return (0);
	}
	return (errno);
}

/*
 * fsck\readonly            rw    ro    ro-dirty
 * never                    1     2     3
 * always                   4     5     6
 * dirty                    7     8     9
 * 1. mount(rw)
 *      error -> return
 * 2. mount(ro)
 *      error -> return
 * 3. mount(rw)
 *      error -> mount(ro)
 * 4. fsck
 *      error -> return
 *    mount(rw)
 * 5. fsck
 *      error -> return
 *    mount(ro)
 * 6. rf = 0
 *    fsck
 *      error -> rf = 1
 *    mount(rf)
 * 7. mount(rw)
 *      error -> fsck
 *        error -> return
 *      mount(rw)
 *  8. mount(ro)
 *       error -> fsck
 *       mount(ro)
 *  9. mount(rw)
 *       error -> rf = 0
 *         fsck
 *           error -> rf = 1
 *         mount(rf)
 */
void
mount_part(int idx, const char *dev, const char *mp, u_int8_t fstype)
{
	int error, rf;

	rf = (readonly_flag == 1);

	if (fsck_flag == 1)
		do_fsck(dev);

	error = do_mountany(idx, dev, mp, rf, fstype);
	if (error == ECANCELED) {
		if (fsck_flag == 2)
			do_fsck(dev);

		if (fsck_flag == 2 || readonly_flag == 2) {
			if (fsck_flag == 2 &&
			    (readonly_flag == 0 || readonly_flag == 2))
				rf = 0;
			else
				rf = 1;
			error = do_mountany(idx, dev, mp, rf, fstype);
			if (error == ECANCELED && fsck_flag == 2 &&
			    readonly_flag == 2)
				do_mountany(idx, dev, mp, 1, fstype);
		}
	}
}

void
mount_disk(const char *devname, char *dev, const char *dskname,
    struct disklabel *label)
{
	int i, np, pi;
	char partname[DISKNAME_SIZE];
	char othername[DISKNAME_SIZE];
	char ntfslabel[DISKNAME_SIZE];
	char exfatlabel[DISKNAME_SIZE];
	char *mp, *dev_part;
	int is_ntfs_exfat;
	int ignore_c, error;

	np = 0;
	is_ntfs_exfat = 0;
	for (i = 0; i < label->d_npartitions; i++) {
		if (label->d_partitions[i].p_fstype != FS_UNUSED &&
		    label->d_partitions[i].p_fstype != FS_SWAP &&
		    label->d_partitions[i].p_fstype != FS_RAID)
			np++;
		if (label->d_partitions[i].p_fstype == FS_NTFS)
			is_ntfs_exfat = 1;
	}

	if (np == 0)
		return;

	if (use_fuse) {
		if (is_ntfs_exfat) {
			has_ntfs3g = check_ntfs3g();
			has_exfat_fuse = check_exfat();
		}
	}

	/*
	 * Sometimes, "c" partition points to the same data as another
	 * partition. So we should exclude "c" partition.
	 */
	ignore_c = 0;
	if (np > 1 && label->d_npartitions > 2 &&
	    label->d_partitions[2].p_fstype != FS_UNUSED) {
		ignore_c = 1;
		np--;
	}

	dev_part = dev + strlen(dev) - 1;
	pi = 1;
	for (i = 0; i < label->d_npartitions; i++) {
		if (label->d_partitions[i].p_fstype != FS_UNUSED &&
		    label->d_partitions[i].p_fstype != FS_SWAP &&
		    label->d_partitions[i].p_fstype != FS_RAID &&
		    !(i == 2 && ignore_c)) {
			*dev_part = 'a' + i;
			if (label->d_partitions[i].p_fstype == FS_NTFS) {
			    if (has_ntfs3g &&
				get_ntfs3g_label(dev, ntfslabel) == 0) {
				    prepare_disk_name(othername, ntfslabel);
				    has_ntfs_label = 1;
				}
			    if (has_exfat_fuse &&
				get_exfat_label(dev, exfatlabel) == 0) {
				    prepare_disk_name(othername, exfatlabel);
				    has_exfat_label = 1;
				}	
			    error = create_mp(othername, &mp, 0, 0);
			} else if (get_part_label(dev, partname) == 1) {
				  prepare_disk_name(othername, partname);
				  error = create_mp(othername, &mp, 0, 0);
			} else
			    error = create_mp(dskname, &mp, (np > 1), pi);

			if (error == 0) {
				save_mp_info(devname, i, mp);
				mount_part(i, dev, mp,
				    label->d_partitions[i].p_fstype);
				free(mp);
			}
			pi++;
		}
	}
}

int
perm_str2val(const char *str, mode_t *mode)
{
	size_t i, len;
	mode_t md;

	len = strlen(str);
	if (len != 3 && len != 4)
		return (-1);

	md = 0;
	for (i = len; i > 0; i--) {
		if (str[i - 1] < '0' || str[i - 1] > '7')
			return (-1);
		md |= (str[i - 1] - '0') << (3 * (len - i));
	}

	*mode = md;
	return (0);
}

int
remove_mount_points(const char *devname, int umnt, int forceifbusy)
{
	char mp[MAXPATHLEN + 1];
	char *lnk;
	size_t sz;
	int i;
	int error, rv;

	sz = strlen(vol_db) + 1 + strlen(devname) + 1 + 1;
	lnk = (char *)malloc(sz);
	if (lnk == NULL)
		return (ENOMEM);
	snprintf(lnk, sz, "%s/%s%c", vol_db, devname, 'a');

	rv = 0;
	for (i = 0; i < MAXPARTITIONS; i++) {
		lnk[sz - 2] = 'a' + i;
		memset(mp, 0, sizeof(mp));
		error = readlink(lnk, mp, sizeof(mp) - 1);
		if (error != -1) {
			if (mounter_pid[i] != -1) {
				if (kill_mounter(mounter_pid[i],
				    forceifbusy) == 0)
					mounter_pid[i] = -1;
				else
					rv = EBUSY;
			} else if (umnt) {
				error = unmount(mp, 0);
				if (error == -1 && errno == EBUSY) {
					if (forceifbusy) {
						error = unmount(mp, MNT_FORCE);
						if (error == -1 &&
						    errno == EBUSY)
							rv = EBUSY;
					} else
						rv = EBUSY;
				}
			}
			rmdir(mp);
		}
		unlink(lnk);
	}

	return (rv);
}

int
create_root(void)
{
	int error, saved_errno;
	char *errstr;

	error = mkdir(vol_root, DEFAULT_PERM);
	if (error != 0 && errno != EEXIST) {
		saved_errno = errno;
		errstr = strerror(saved_errno);
		fprintf(stderr, "Cannot create directory: %s\n", errstr);
		return (saved_errno);
	}

	error = mkdir(vol_db, S_IRWXU);
	if (error != 0 && errno != EEXIST) {
		saved_errno = errno;
		errstr = strerror(saved_errno);
		fprintf(stderr, "Cannot create directory: %s\n", errstr);
		return (saved_errno);
	}

	return (0);
}

int
main(int argc, char * const *argv)
{
	struct disklabel label;
	const char *arg_cmd, *arg_devname;
	const char *progname;
	char diskname[DISKNAME_SIZE], *dev;
	struct passwd *pwent;
	struct group *grent;
	int succeed, error;
	int i, ch;
	mode_t mode;
	size_t len;

	arg_devname = NULL;
	progname = argv[0];
	for (i = 0; i < MAXPARTITIONS; i++)
		mounter_pid[i] = -1;

	while ((ch = getopt(argc, argv, "d:")) != -1) {
		switch (ch) {
		case 'd':
			len = strlcpy(vol_root, optarg, sizeof(vol_root));
			if (len >= sizeof(vol_root)) {
				fprintf(stderr, "%s: path is too long\n",
				    progname);
				exit(1);
			}

			/*
			 * Remove trailing slash but allow user to specify root
			 * directory "/".
			 */
			for (i = len; i > 1; i--) {
				if (vol_root[i - 1] == '/')
					vol_root[i - 1] = '\0';
				else
					break;
			}

			/*
			 * Empty string is not allowed. Otherwise, mount points
			 * will be created in root diriectory.
			 */
			if (*vol_root == '\0') {
				fprintf(stderr, "%s: path is invalid\n",
				    progname);
				exit(1);
			}

			/* change vol_db path */
			strlcpy(vol_db, vol_root, sizeof(vol_db));
			len = strlcat(vol_db, DEFAULT_VOL_DB, sizeof(vol_db));
			if (len >= sizeof(vol_db)) {
				fprintf(stderr, "%s: path is too long\n",
				    progname);
				exit(1);
			}

			break;
		default:
			usage(progname);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;
	optreset = 1;

	if (argc < 1) {
		usage(progname);
		return (1);
	}

	arg_cmd = argv[0];

	if (strcmp(arg_cmd, "attach") == 0) {
		while ((ch = getopt(argc, argv, "Ff:g:m:r:u:")) != -1) {
			switch (ch) {
			case 'F':
				use_fuse = 0;
				break;
			case 'f':
				if (strcasecmp(optarg, "never") == 0)
					fsck_flag = 0;
				else if (strcasecmp(optarg, "dirty") == 0)
					fsck_flag = 2;
				else {
					fprintf(stderr,
					    "%s: invalid argument of fsck "
					    "option is specified\n",
					    progname);
					exit(1);
				}
				break;
			case 'g':
				grent = getgrnam(optarg);
				if (grent == NULL) {
					fprintf(stderr, "%s: "
					    "specified group is not found\n",
					    progname);
					exit(1);
				}
				mp_gid = grent->gr_gid;
				break;
			case 'm':
				error = perm_str2val(optarg, &mode);
				if (error != 0) {
					fprintf(stderr,
					    "%s: invalid mode is specified\n",
					    progname);
					exit(1);
				}
				mp_perm = mode;
				ignore_umask = 1;
				break;
			case 'r':
				if (strcasecmp(optarg, "all") == 0)
					readonly_flag = 1;
				else if (strcasecmp(optarg, "dirty") == 0)
					readonly_flag = 2;
				else {
					fprintf(stderr,
					    "%s: invalid argument of readonly "
					    "option is specified\n",
					    progname);
					exit(1);
				}
				break;
			case 'u':
				pwent = getpwnam(optarg);
				if (pwent == NULL) {
					fprintf(stderr,
					    "%s: specified user is not found\n",
					    progname);
					exit(1);
				}
				mp_uid = pwent->pw_uid;
				break;
			default:
				usage(progname);
				exit(1);
			}
		}

		argc -= optind;
		argv += optind;

		if (argc < 1) {
			usage(progname);
			exit(1);
		}

		arg_devname = argv[0];
	} else if (strcmp(arg_cmd, "init") == 0) {
		/* nothing */
	} else if (strcmp(arg_cmd, "cleanup") == 0) {
		if (argc < 2) {
			usage(progname);
			exit(1);
		}

		arg_devname = argv[1];
	} else {
		usage(progname);
		exit(1);
	}

	if (strcmp(arg_cmd, "attach") == 0) {
		error = daemon(0, 0);
		if (error != 0) {
			fprintf(stderr,
			    "Cannot detach from controlling terminal\n");
			exit(1);
		}

		signal(SIGTERM, sig_term);
		succeed = 0;
		for (;;) {
			if (quit_flag) {
				if (succeed) {
					for (i = 0; i < 5; i++) {
						error = remove_mount_points(
						    arg_devname, 1, 0);
						if (error != EBUSY)
							break;
						sleep(1);
					}
				}
				exit(0);
			}

			error = get_disk_label(arg_devname, &dev, &label);
			if (error == ENOMEDIUM) {
				/*
				 * If the media were removed from the
				 * device, cleanup mount points.
				 */
				if (succeed) {
					remove_mount_points(arg_devname, 0, 0);
					succeed = 0;
				}
			} else if (error == EBUSY) {
				/*
				 * The device is mounted.
				 */
				/* NOTHING */
			} else if (error == ENXIO) {
				/*
				 * The device with FUSE-mounted filesystem were
				 * removed. We need to unmount it because it's
				 * left mounted.
				 */
				if (succeed)
					remove_mount_points(arg_devname, 1, 1);
				exit(0);
			} else if (error == 0 && succeed) {
				/*
				 * Someone umounted CD/DVD...
				 * wait for eject/insert.
				 */
				/* NOTHING */
			} else if (error == 0) {
				lock_db();
				prepare_disk_name(diskname, label.d_packname);
				mount_disk(arg_devname, dev, diskname, &label);
				unlock_db();
				free(dev);
				succeed = 1;
			} else {
				if (succeed)
					remove_mount_points(arg_devname, 0, 0);
				exit(0);
			}

			sleep(CHECK_MEDIA_TIMEOUT);
		}
		/* NOTREACHED */
	} else if (strcmp(arg_cmd, "init") == 0) {
		error = create_root();
		exit(error != 0);
	} else if (strcmp(arg_cmd, "cleanup") == 0) {
		error = remove_mount_points(arg_devname, 0, 0);
		exit(error != 0);
	}

	usage(progname);
	exit(1);
}
