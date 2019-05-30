#define FUSE_USE_VERSION 26
#define _DEFAULT_SOURCE
// necessary for Raspbian build
#define _BSD_SOURCE
// necessary for pread
#define _XOPEN_SOURCE 500

#include "tools.h"
#include "shell.h"

#include <fuse.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <syslog.h>

#define TOOL_NAME   	fs
#define LOCKFILE_NAME 	".lock"

static gchar *opt_mountpoint;
static gchar *opt_mountoptions;
static gboolean opt_log_unimplemented;
static gchar *opt_tempbase;
static gchar *temp_folder_path;
static GFile *temp_folder;

static gchar *mountpoint_path;
static struct mega_session *s;

#define Q(x) #x
#define QUOTE(x) Q(x)

// append multiple -o or --options values, separated by comma
static gboolean opt_mountoptions_callback(const gchar *option_name, const gchar *value, gpointer data, GError **error)
{
	if (value) {
		if (!opt_mountoptions)
			opt_mountoptions = g_strdup(value);
		else
			opt_mountoptions = g_strconcat(opt_mountoptions, 
									(strlen(opt_mountoptions) > 0 ? "," : ""), value, NULL);

		return TRUE;
	}

	return FALSE;
}

static GOptionEntry entries[] = {
	{ "options", 'o', 0, G_OPTION_ARG_CALLBACK, opt_mountoptions_callback, "FUSE mount options", "<options>" },
	{ "tempdir", 't', 0, G_OPTION_ARG_STRING, &opt_tempbase, "Temporary folder", "<folder>" },
	{ "log-unimplemented", 'l', 0, G_OPTION_ARG_NONE, &opt_log_unimplemented, "Log unimplemented FUSE function calls in syslog", NULL },
	{ NULL },
};

// {{{ Initialization and destruction

static void *mega_init(struct fuse_conn_info *conn)
{
	GError *local_err = NULL;

	if (mega_debug & MEGA_DEBUG_APP)
		syslog(LOG_INFO, QUOTE(TOOL_NAME) ": Initializing remote file system for mega user '%s' at mountpoint %s", mega_session_get_user_name(s), mountpoint_path);

	gc_free gchar* lock_file_path = g_build_filename(temp_folder_path, LOCKFILE_NAME, NULL);
	gc_object_unref GFile *lock_file = g_file_new_for_path(lock_file_path);

	// create the lock file and write the current process ID to it
	gc_object_unref GFileOutputStream *fos = g_file_create(lock_file, G_FILE_CREATE_NONE, NULL, &local_err);
	if (!fos) {
		syslog(LOG_ERR, QUOTE(TOOL_NAME) ": Can't create lock file %s: %s\n", lock_file_path, local_err->message);
		g_clear_error(&local_err);
		exit(local_err->code);
		return NULL;
	}

	gsize bytes_written;
	if (!g_output_stream_printf((GOutputStream*)fos, &bytes_written, NULL, &local_err, "%d", getpid())) {
		syslog(LOG_ERR, QUOTE(TOOL_NAME) ": Can't write to lock file %s: %s\n", lock_file_path, local_err->message);
		g_clear_error(&local_err);
		exit(local_err->code);
		return NULL;
	}

	if (!g_output_stream_close((GOutputStream*)fos, NULL, &local_err)) {
		syslog(LOG_ERR, QUOTE(TOOL_NAME) ": Error closing lock file %s: %s\n", lock_file_path, local_err->message);
		g_clear_error(&local_err);
		exit(local_err->code);
		return NULL;
	}

	return NULL;
}

static void mega_destroy(void *private_data)
{
	GError *local_err = NULL;

	if (mega_debug & MEGA_DEBUG_APP)
		syslog(LOG_INFO, QUOTE(TOOL_NAME) ": Taking down remote file system for mega user '%s' at mountpoint %s", mega_session_get_user_name(s), opt_mountpoint);

	gc_free gchar* lock_file_path = g_build_filename(temp_folder_path, LOCKFILE_NAME, NULL);
	gc_object_unref GFile *lock_file = g_file_new_for_path(lock_file_path);

	// delete the lock file
	if (!g_file_delete(lock_file, NULL, &local_err)) {
		syslog(LOG_ERR, QUOTE(TOOL_NAME) ": Can't delete lock file %s: %s\n", lock_file_path, local_err->message);
		g_clear_error(&local_err);
	}
}

// }}}

// {{{ Read file/dir attributes

static int mega_getattr(const char *path, struct stat *st)
{
	memset(st, 0, sizeof(struct stat));

	// set owner and group to those of the user who started the tool
	st->st_uid = geteuid();
	st->st_gid = getegid();

	if (strcmp(path, "/") == 0) 
	{
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 1;
		return 0;
	} 
	else
	{
		struct mega_node* n = mega_session_stat(s, path);

		if (n)
		{
			st->st_mode = n->type == MEGA_NODE_FILE ? S_IFREG | 0444 : S_IFDIR | 0755;
			st->st_nlink = 1;
			st->st_size = n->size;
			// support local timestamp if available
			if (n->local_ts > 0)
				st->st_atime = st->st_mtime = st->st_ctime = n->local_ts;
			else
				st->st_atime = st->st_mtime = st->st_ctime = n->timestamp;
			return 0;
		}
	} 

	return -ENOENT;
}

static int mega_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	GSList* l = mega_session_ls(s, path, FALSE), *i;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	for (i = l; i; i = i->next)
	{
		struct stat st;
		struct mega_node* n = i->data;

		memset(&st, 0, sizeof(st));
		st.st_mode = n->type == MEGA_NODE_FILE ? S_IFREG | 0644 : S_IFDIR | 0755;
		st.st_nlink = 1;
		st.st_size = n->size;
		// support local timestamp if available
		if (n->local_ts > 0)
			st.st_atime = st.st_mtime = st.st_ctime = n->local_ts;
		else
			st.st_atime = st.st_mtime = st.st_ctime = n->timestamp;

		if (filler(buf, n->name, &st, 0))
			break;
	}

	g_slist_free(l);
	return 0;
}
/*
static int mega_releasedir(const char * c, struct fuse_file_info *fi) {
	if (opt_log_unimplemented)
		syslog(LOG_INFO, "Call to unimplemented function releasedir: file %s", c);
	return -ENOTSUP;
}
*/

// }}}
// {{{ Create/remove directories
/*
static int mega_mkdir(const char *path, mode_t mode)
{
	if (opt_log_unimplemented)
		syslog(LOG_INFO, "Call to unimplemented function mkdir: file %s", path);
	return -ENOTSUP;
}

static int mega_rmdir(const char *path)
{
	if (opt_log_unimplemented)
		syslog(LOG_INFO, "Call to unimplemented function rmdir: file %s", path);
	return -ENOTSUP;
}

// }}}
// {{{ Create/read symlinks

static int mega_symlink(const char *from, const char *to)
{
	if (opt_log_unimplemented)
		syslog(LOG_INFO, "Call to unimplemented function symlink: file %s", from);
	return -ENOTSUP;
}

static int mega_readlink(const char *path, char *buf, size_t size)
{
	if (opt_log_unimplemented)
		syslog(LOG_INFO, "Call to unimplemented function readlink: file %s", path);
	return -ENOTSUP;
}

static int mega_link(const char *from, const char *to)
{
	if (opt_log_unimplemented)
		syslog(LOG_INFO, "Call to unimplemented function link: file %s", from);
	return -ENOTSUP;
}

// }}}
// {{{ Remove files

static int mega_unlink(const char *path)
{
	if (opt_log_unimplemented)
		syslog(LOG_INFO, "Call to unimplemented function unlink: file %s", path);
	return -ENOTSUP;
}

// }}}
// {{{ Rename files

static int mega_rename(const char *from, const char *to)
{
	if (opt_log_unimplemented)
		syslog(LOG_INFO, "Call to unimplemented function rename: file %s", from);
	return -ENOTSUP;
}

// }}}
// {{{ File access operations

static int mega_truncate(const char *path, off_t size)
{
	if (opt_log_unimplemented)
		syslog(LOG_INFO, "Call to unimplemented function truncate: file %s", path);
	return -ENOTSUP;
}
*/

static int mega_open(const char *path, struct fuse_file_info *fi)
{
	GError *local_err = NULL;

	if (opt_log_unimplemented)
		syslog(LOG_INFO, "Call to function open: file %s", path);

	gc_free gchar* real_path = g_build_filename(temp_folder_path, path, NULL);
	syslog(LOG_INFO, "Real path: %s", real_path);

	// find the node in the Mega tree
	struct mega_node* n = mega_session_stat(s, path);

	// node not found?
	if (!n)
		return -ENOENT;

    syslog(LOG_INFO, "Node found");

    // get effective timestamp
    long int timestamp = (n->local_ts > 0 ? n->local_ts : n->timestamp);

	gc_object_unref GFile* real_file = g_file_new_for_path(real_path);
	// get temporary file information
	GStatBuf st;
	if (g_stat(real_path, &st) != 0) {
        if (errno != ENOENT) {
            syslog(LOG_ERR, "Failed to stat: %s: %s", real_path, g_strerror(errno));
            return -errno;
        }
    } else {
		// compare size
 		syslog(LOG_INFO, "Comparing sizes: %zu (local) vs. %zu (remote)", (size_t)st.st_size, (size_t)n->size);
		gboolean do_replace = (st.st_size != n->size);

		if (!do_replace) {
			// compare timestamp
			syslog(LOG_INFO, "Comparing timestamps: %lu (local) vs. %lu (remote)", st.st_mtime, timestamp);
			do_replace = (timestamp != st.st_mtime);
		}

		if (do_replace) {
			syslog(LOG_INFO, "Deleting: %s", real_path);
/*
            // this code introduces a delay of 50 seconds if fuse_main is run without option "debug"
			if (!g_file_delete(real_file, NULL, &local_err)) {
				syslog(LOG_ERR, "Can't delete temporary file %s: %s", real_path, local_err->message);
				int code = local_err->code;
				g_clear_error(&local_err);
				return -1 * code;
*/
            if (unlink(real_path) != 0) {
                syslog(LOG_ERR, "Can't delete temporary file %s: %s", real_path, g_strerror(errno));
                int code = errno;
                return -1 * code;
            } else {
                syslog(LOG_INFO, "Successfully deleted: %s", real_path);
            }
		}
	}

    syslog(LOG_INFO, "Checking file existence: %s", real_path);

	// does the file not yet exist?
	if (!g_file_query_exists(real_file, NULL)) {
        // ensure that the path exists
        syslog(LOG_INFO, "Checking/creating folder for: %s", real_path);
        gc_object_unref GFile *real_folder = g_file_get_parent(real_file);
        if (!g_file_make_directory_with_parents(real_folder, NULL, &local_err) && local_err->code != G_IO_ERROR_EXISTS) {
            syslog(LOG_ERR, "Can't create target directory of %s: %s", real_path, local_err->message);
            int code = local_err->code;
            g_clear_error(&local_err);
            return -1 * code;
        }
        g_clear_error(&local_err);

        // need to download the file

        syslog(LOG_INFO, "Checking space on temporary file system: %s", temp_folder_path);
        // check space on temp folder fs
        struct statvfs stfs;
        if (statvfs(temp_folder_path, &stfs) != 0) {
            syslog(LOG_ERR, "Error in statvfs: %d", errno);
            return -EIO;
        }

        long int free_bytes = stfs.f_bavail * stfs.f_bsize;
        syslog(LOG_INFO, "Available space in temporary folder: %lu bytes", free_bytes);

        if (free_bytes < n->size) {
            long int diff = n->size - free_bytes;
            syslog(LOG_ERR, "Not enough space in temp folder %s for %s, %lu bytes short", temp_folder_path, path, diff);
            return -ENOSPC;
        }

        syslog(LOG_INFO, "Downloading: %s (%zu bytes)", path, (size_t)n->size);
        if (!mega_session_get_compat(s, real_path, path, &local_err)) {
            syslog(LOG_ERR, "Download failed for %s: %s", path, local_err->message);
            int code = local_err->code;
            g_clear_error(&local_err);
            return -1 * code;
        }

        // set timestamp
        if (timestamp > 0) {
            struct utimbuf timbuf;
            timbuf.actime = timestamp;
            timbuf.modtime = timestamp;
            if (utime(real_path, &timbuf)) {
                syslog(LOG_ERR, "Failed to set file times on %s: %s", real_path, g_strerror(errno));
            }
        }

        syslog(LOG_INFO, "File successfully downloaded: %s", path);
	} else {
        syslog(LOG_INFO, "Opening file in temporary folder: %s", real_path);        
    }

    // open the file
    int retstat = 0;
    int fd;
    
    fd = open(real_path, fi->flags);
    if (fd < 0) {
        syslog(LOG_ERR, "Unable to open file %s: %s", real_path, g_strerror(errno));
        retstat = errno;
    } else {
        fi->fh = fd;
        syslog(LOG_INFO, "File handle %d created for: %s", fd, path);
    }

    return retstat;
}
/*
static int mega_read_buf(const char * path, struct fuse_bufvec **bufp, size_t size, off_t offset, struct fuse_file_info *fi) {
    if (mega_debug & MEGA_DEBUG_APP)
        syslog(LOG_INFO, "mega_read_buf: file %s at offset %lu (size %ld)", path, offset, size);

    struct fuse_bufvec *src;
    src = malloc(sizeof(struct fuse_bufvec));
    if (src == NULL)
        return -ENOMEM;

    *src = FUSE_BUFVEC_INIT(size);
    src->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    src->buf[0].fd = fi->fh;
    src->buf[0].pos = offset;

    int retstat = 0;
    
    retstat = pread(fi->fh, src->buf, size, offset);
    if (retstat < 0) {
        retstat = -errno;
        gc_free gchar* real_path = g_build_filename(temp_folder_path, path, NULL);
        syslog(LOG_ERR, "Unable to read file %s: %s", real_path, g_strerror(errno));
    }

    *bufp = src;

    return retstat;
}
*/

static int mega_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	if (mega_debug & MEGA_DEBUG_APP)
		syslog(LOG_INFO, "mega_read: file %s at offset %jd (size %zu)", path, offset, size);

    int retstat = 0;

    retstat = pread(fi->fh, buf, size, offset);
    if (retstat < 0) {
        gc_free gchar* real_path = g_build_filename(temp_folder_path, path, NULL);
        syslog(LOG_ERR, "Unable to read file %s: %s", real_path, g_strerror(errno));
        return -errno;
    }

    return retstat;
}
/*
static int mega_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	if (opt_log_unimplemented)
		syslog(LOG_INFO, "Call to unimplemented function write: file %s", path);
	return -ENOTSUP;
}
*/
static int mega_release(const char *path, struct fuse_file_info *fi)
{
	if (mega_debug & MEGA_DEBUG_APP)
		syslog(LOG_INFO, "mega_release: file %s", path);

    close(fi->fh);

	return -errno;
}

// }}}
// {{{ Ops structure

#define RETVAL(cond) RETVAL_ ## cond
#define RETVAL_int return -ENOTSUP;
#define RETVAL_void

#define CONCAT(a, b) a##b

#define UNIMPLEMENTED(rettype, fn, ...) \
static rettype CONCAT(mega_, fn) (__VA_ARGS__) \
{ \
	if (opt_log_unimplemented) \
		syslog(LOG_INFO, "Call to unimplemented function " #fn); \
	RETVAL(rettype) \
}
/*
UNIMPLEMENTED(int, mknod, const char * c, mode_t m, dev_t d)

UNIMPLEMENTED(int, chmod, const char * c, mode_t m)

UNIMPLEMENTED(int, chown, const char * c, uid_t u, gid_t g)

// UNIMPLEMENTED(int, statfs, const char * c, struct statvfs *s)

//UNIMPLEMENTED(int, flush, const char * c, struct fuse_file_info *fi)

UNIMPLEMENTED(int, fsync, const char * c, int i, struct fuse_file_info *fi)

UNIMPLEMENTED(int, setxattr, const char * c, const char * c1, const char * c2, size_t size, int i)
 
UNIMPLEMENTED(int, getxattr, const char * c, const char * c1, char * c2, size_t size)

UNIMPLEMENTED(int, listxattr, const char * c, char * c1, size_t size)
 
UNIMPLEMENTED(int, removexattr, const char * c, const char * c1)

//UNIMPLEMENTED(int, opendir, const char * c, struct fuse_file_info *fi)
 
UNIMPLEMENTED(int, fsyncdir, const char * c, int i, struct fuse_file_info *fi)
 
UNIMPLEMENTED(int, access, const char * c, int i)
 
UNIMPLEMENTED(int, create, const char * c, mode_t m, struct fuse_file_info *fi)
 
//UNIMPLEMENTED(int, lock, const char * c, struct fuse_file_info *fi, int cmd, struct flock *fl)
 
UNIMPLEMENTED(int, utimens, const char * c, const struct timespec tv[2])
 
UNIMPLEMENTED(int, bmap, const char * c, size_t blocksize, uint64_t *idx)
 
UNIMPLEMENTED(int, ioctl, const char * c, int cmd, void *arg, struct fuse_file_info *fi, unsigned int flags, void *data)
 
UNIMPLEMENTED(int, poll, const char * c, struct fuse_file_info *fi, struct fuse_pollhandle *ph, unsigned *reventsp)
 
UNIMPLEMENTED(int, write_buf, const char * c, struct fuse_bufvec *buf, off_t off, struct fuse_file_info *fi)
 
UNIMPLEMENTED(int, flock, const char * c, struct fuse_file_info *fi, int op)
 
UNIMPLEMENTED(int, fallocate, const char * c, int i, off_t o1, off_t o2, struct fuse_file_info *fi)
 
//UNIMPLEMENTED(ssize_t, copy_file_range, const char *path_in, struct fuse_file_info *fi_in, off_t offset_in, const char *path_out, struct fuse_file_info *fi_out, off_t offset_out, size_t size, int flags)
*/
static struct fuse_operations mega_oper = {
	.getattr	= mega_getattr,
//	.readlink	= mega_readlink,
//	.mknod      = mega_mknod,
//	.mkdir		= mega_mkdir,
//	.unlink		= mega_unlink,
//	.rmdir		= mega_rmdir,
//	.symlink	= mega_symlink,
//	.rename		= mega_rename,
//	.link		= mega_link,
//	.chmod      = mega_chmod,
//	.chown      = mega_chown,
//	.truncate	= mega_truncate,
	.open		= mega_open,
	.read		= mega_read,
//	.write		= mega_write,
//	.statfs     = mega_statfs,
//	.flush      = mega_flush,
	.release	= mega_release,
//	.fsync      = mega_fsync,
//	.setxattr   = mega_setxattr,
//	.getxattr   = mega_getxattr,
//	.listxattr  = mega_listxattr,
//	.removexattr = mega_removexattr,
//    .opendir    = mega_opendir,
	.readdir	= mega_readdir,
//		.releasedir = mega_releasedir,
//	.fsyncdir   = mega_fsyncdir,
	.init       = mega_init,
	.destroy    = mega_destroy,
//	.access     = mega_access,
//	.create     = mega_create,
//	.lock       = mega_lock,
//	.utimens    = mega_utimens,
//	.bmap       = mega_bmap,
//	.ioctl      = mega_ioctl,
//	.poll       = mega_poll,
//	.write_buf  = mega_write_buf,
//	.read_buf   = mega_read_buf,
//	.flock      = mega_flock,
//	.fallocate  = mega_fallocate,
};

// }}}
// {{{ main()

int fs_main(int ac, char* av[])
{
	GError *local_err = NULL;
	GFileType file_type;

	tool_init(&ac, &av, "mount_directory - mount files stored at mega.nz", entries,
			TOOL_INIT_AUTH);

	if (ac < 2) {
		g_printerr("ERROR: You must specify a local mount directory\n");
		return 1;
	}

	opt_mountpoint = g_strdup(av[1]);

	// check whether the mountpoint exists
	gc_object_unref GFile* mountpoint_file = g_file_new_for_path(opt_mountpoint);
	mountpoint_path = g_file_get_path(mountpoint_file);
	file_type = g_file_query_file_type(mountpoint_file, G_FILE_QUERY_INFO_NONE, NULL);

	if (file_type != G_FILE_TYPE_DIRECTORY) {
		g_printerr("ERROR: Mount point %s does not exist or is not a directory\n", mountpoint_path);
		return FALSE;
	}

	s = tool_start_session(TOOL_SESSION_OPEN);
	if (!s)
		return 1;

	// temporary directory
	if (!opt_tempbase)
		opt_tempbase = g_strdup(g_get_tmp_dir());

	// check that temporary folder exists and is a writable directory
	gc_free gchar *tempbase_path = g_build_filename(opt_tempbase, "megatools", NULL);
	gc_object_unref GFile *tempbase_folder = g_file_new_for_path(tempbase_path);
	file_type = g_file_query_file_type(tempbase_folder, G_FILE_QUERY_INFO_NONE, NULL);

	if (file_type == G_FILE_TYPE_UNKNOWN) {
		// create temporary base directory
		if (!g_file_make_directory(tempbase_folder, NULL, &local_err)) {
			g_printerr("ERROR: Can't create temporary directory %s: %s\n", tempbase_path,
					local_err->message);
			g_clear_error(&local_err);
			return FALSE;
		}
	} else if (file_type != G_FILE_TYPE_DIRECTORY) {
			g_printerr("ERROR: Temporary file location %s exists but is not a directory\n", tempbase_path);
			return FALSE;
	}

	// check login-specific temporary folder
	gc_free gchar *temp_path = g_build_filename(tempbase_path, mega_session_get_user_name(s), NULL);
	gc_object_unref GFile *temp_folder = g_file_new_for_path(temp_path);
	file_type = g_file_query_file_type(temp_folder, G_FILE_QUERY_INFO_NONE, NULL);

	if (file_type == G_FILE_TYPE_UNKNOWN) {
		// create temporary base directory
		if (!g_file_make_directory(temp_folder, NULL, &local_err)) {
			g_printerr("ERROR: Can't create temporary directory %s: %s\n", temp_path,
					local_err->message);
			g_clear_error(&local_err);
			return FALSE;
		}
	} else if (file_type != G_FILE_TYPE_DIRECTORY) {
			g_printerr("ERROR: Temporary file location %s exists but is not a directory\n", temp_path);
			return FALSE;
	}

	gc_free gchar* lock_file_path = g_build_filename(temp_path, LOCKFILE_NAME, NULL);
	gc_object_unref GFile *lock_file = g_file_new_for_path(lock_file_path);

	// check the lock file
	if (g_file_query_exists(lock_file, NULL)) {
		// read lock file
		gc_free gchar *lock_data;
		gsize length;
		if (!g_file_get_contents(lock_file_path, &lock_data, &length, &local_err)) {
			g_printerr("ERROR: Unable to read lock file %s: %s\n", lock_file_path, local_err->message);
			g_clear_error(&local_err);
			return 1;
		}

		// parse lock file content to process ID
		errno = 0;
		gchar *error_location;
		long int procID = strtol(lock_data, &error_location, 10);
		if (errno != 0 || error_location[0] != '\0') {
			g_printerr("ERROR: Unable to parse lock file data: %s\n", lock_file_path);
			return 1;
		}
		
		// check whether the process is still running
		gc_free gchar *process_path = g_build_filename("/proc", lock_data, "cmdline", NULL);
		gc_object_unref GFile *process_file = g_file_new_for_path(process_path);
		if (g_file_query_exists(process_file, NULL)) {
			// TODO check whether the process is a megatools-fs process?
			g_printerr("ERROR: The process with ID %s is locking the temporary folder %s\n", lock_data, temp_path);
			return 1; 
		}

		// delete the lock file
		if (!g_file_delete(lock_file, NULL, &local_err)) {
			g_printerr("ERROR: Can't delete obsolete lock file %s: %s\n", lock_file_path, local_err->message);
			g_clear_error(&local_err);
			return 1; 
		}
	}

	// create the lock file and delete it again to check whether we can write to the tmpdir
	gc_object_unref GFileOutputStream *fos = g_file_create(lock_file, G_FILE_CREATE_NONE, NULL, &local_err);
	if (!fos) {
		g_printerr("ERROR: Can't create lock file %s: %s\n", lock_file_path, local_err->message);
		g_clear_error(&local_err);
		return 1; 
	}

	// delete the lock file
	if (!g_file_delete(lock_file, NULL, &local_err)) {
		g_printerr("ERROR: Can't delete lock file %s: %s\n", lock_file_path, local_err->message);
		g_clear_error(&local_err);
		return 1; 
	}

	temp_folder_path = g_strdup(temp_path);

	// pass mount options as argument to fuse_main
	struct fuse_args args = FUSE_ARGS_INIT(ac, av);
	fuse_opt_parse(&args, NULL, NULL, NULL);

	// add default mount options
#define DEFAULT_MOUNTOPTIONS "ro,allow_root,default_permissions,fsname=mega_fs,auto_unmount"
	gchar *mountoptions = g_strconcat("-o" DEFAULT_MOUNTOPTIONS, (opt_mountoptions ? "," : ""), opt_mountoptions, NULL);
	fuse_opt_add_arg(&args, mountoptions);

	if (mega_debug & MEGA_DEBUG_APP)
		g_printf("Mounting mega filesystem; temp folder is: %s\n", temp_folder_path);

	int rs = fuse_main(args.argc, args.argv, &mega_oper, NULL);

	tool_fini(s);
	return rs;
}

// }}}

const struct shell_tool shell_tool_fs = {
	.name = "fs",
	.main = fs_main,
	.usages = (char*[]){
		NULL
	},
};

