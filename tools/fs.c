
#define FUSE_USE_VERSION 26
#define _DEFAULT_SOURCE

#include <fuse.h>
#include <errno.h>
#include <sys/stat.h>
#include <syslog.h>
#include "tools.h"
#include "shell.h"

static gchar *opt_mountoptions;
static gboolean opt_quiet;

static struct mega_session *s;

static GOptionEntry entries[] = {
	{ "options", 'o', 0, G_OPTION_ARG_STRING, &opt_mountoptions, "FUSE mount options", "options" },
	{ "quiet", 'q', 0, G_OPTION_ARG_NONE, &opt_quiet, "Output warnings and errors only", NULL },
	{ NULL }
};

// {{{ Read file/dir attributes

static int mega_getattr(const char *path, struct stat *stbuf)
{
  syslog(LOG_INFO, "Call to mega_getattr: file %s", path);

  memset(stbuf, 0, sizeof(struct stat));
/*
  char *source = "/home/leo/megatools/mount/Root/Leo";
  char *fullpath_source = NULL;
	
    fullpath_source = realpath(source, NULL);
    if (!fullpath_source) {
	    syslog(LOG_ERR, "could not resolve full path for source %s [%d]",
		    source, -errno);
    }
*/
  //stbuf->st_uid = geteuid();

  if (strcmp(path, "/") == 0) 
  {
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 1;
    return 0;
  } 
  else
  {
    struct mega_node* n = mega_session_stat(s, path);

    if (n)
    {
      stbuf->st_mode = n->type == MEGA_NODE_FILE ? S_IFREG | 0644 : S_IFDIR | 0755;
      stbuf->st_nlink = 1;
      stbuf->st_size = n->size;
      stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = n->timestamp;
      return 0;
    }
  } 

  return -ENOENT;
}

static int mega_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
  syslog(LOG_INFO, "Call to mega_readdir: file %s", path);

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
    st.st_atime = st.st_mtime = st.st_ctime = n->timestamp;

    if (filler(buf, n->name, &st, 0))
      break;
  }

  g_slist_free(l);
  return 0;
}

// }}}
// {{{ Create/remove directories

static int mega_mkdir(const char *path, mode_t mode)
{
  GError *local_err = NULL;

  if (!mega_session_mkdir(s, path, &local_err))
  {
    g_clear_error(&local_err);
    return -ENOENT;
  }

  return 0;
}

static int mega_rmdir(const char *path)
{
  GError *local_err = NULL;

  if (!mega_session_rm(s, path, &local_err))
  {
    g_clear_error(&local_err);
    return -ENOENT;
  }

  return 0;
}

// }}}
// {{{ Create/read symlinks

static int mega_symlink(const char *from, const char *to)
{
  syslog(LOG_ERR, "Call to unimplemented mega_symlink: file %s", from);
  return -ENOTSUP;
}

static int mega_readlink(const char *path, char *buf, size_t size)
{
  syslog(LOG_ERR, "Call to unimplemented mega_readlink: file %s", path);
  return -ENOTSUP;
}

static int mega_link(const char *from, const char *to)
{
  syslog(LOG_ERR, "Call to unimplemented mega_link: file %s", from);
  return -ENOTSUP;
}

// }}}
// {{{ Remove files

static int mega_unlink(const char *path)
{
  GError *local_err = NULL;

  if (!mega_session_rm(s, path, &local_err))
  {
    g_clear_error(&local_err);
    return -ENOENT;
  }

  return 0;
}

// }}}
// {{{ Rename files

static int mega_rename(const char *from, const char *to)
{
  syslog(LOG_ERR, "Call to unimplemented mega_rename: file %s", from);
  return -ENOTSUP;
}

// }}}
// {{{ File access operations

static int mega_truncate(const char *path, off_t size)
{
  syslog(LOG_ERR, "Call to unimplemented mega_truncate: file %s", path);
  return -ENOTSUP;
}

static int mega_open(const char *path, struct fuse_file_info *fi)
{
  syslog(LOG_ERR, "Call to unimplemented mega_open: handle %ld", fi->fh);
  return -ENOTSUP;
}

static int mega_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  syslog(LOG_ERR, "Call to unimplemented mega_read: file %s", path);
  return -ENOTSUP;
}

static int mega_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  syslog(LOG_ERR, "Call to unimplemented mega_write: file %s", path);
  return -ENOTSUP;
}

static int mega_release(const char *path, struct fuse_file_info *fi)
{
  syslog(LOG_ERR, "Call to unimplemented mega_release: file %s", path);
  return 0;
}

static void *mega_init(struct fuse_conn_info *conn)
{
  syslog(LOG_ERR, "Call to unimplemented mega_init");
  return NULL;
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
  syslog(LOG_ERR, "Call to unimplemented function " #fn); \
  RETVAL(rettype) \
}

UNIMPLEMENTED(int, mknod, const char * c, mode_t m, dev_t d)

UNIMPLEMENTED(int, chmod, const char * c, mode_t m)

UNIMPLEMENTED(int, chown, const char * c, uid_t u, gid_t g)

UNIMPLEMENTED(int, statfs, const char * c, struct statvfs *s)

UNIMPLEMENTED(int, flush, const char * c, struct fuse_file_info *fi)

UNIMPLEMENTED(int, fsync, const char * c, int i, struct fuse_file_info *fi)

UNIMPLEMENTED(int, setxattr, const char * c, const char * c1, const char * c2, size_t size, int i)
 
UNIMPLEMENTED(int, getxattr, const char * c, const char * c1, char * c2, size_t size)

UNIMPLEMENTED(int, listxattr, const char * c, char * c1, size_t size)
 
UNIMPLEMENTED(int, removexattr, const char * c, const char * c1)

//UNIMPLEMENTED(int, opendir, const char * c, struct fuse_file_info *fi)
 
UNIMPLEMENTED(int, releasedir, const char * c, struct fuse_file_info *fi)
 
UNIMPLEMENTED(int, fsyncdir, const char * c, int i, struct fuse_file_info *fi)
 
UNIMPLEMENTED(void, destroy, void *private_data)
 
UNIMPLEMENTED(int, access, const char * c, int i)
 
UNIMPLEMENTED(int, create, const char * c, mode_t m, struct fuse_file_info *fi)
 
UNIMPLEMENTED(int, lock, const char * c, struct fuse_file_info *fi, int cmd, struct flock *fl)
 
UNIMPLEMENTED(int, utimens, const char * c, const struct timespec tv[2])
 
UNIMPLEMENTED(int, bmap, const char * c, size_t blocksize, uint64_t *idx)
 
UNIMPLEMENTED(int, ioctl, const char * c, int cmd, void *arg, struct fuse_file_info *fi, unsigned int flags, void *data)
 
UNIMPLEMENTED(int, poll, const char * c, struct fuse_file_info *fi, struct fuse_pollhandle *ph, unsigned *reventsp)
 
UNIMPLEMENTED(int, write_buf, const char * c, struct fuse_bufvec *buf, off_t off, struct fuse_file_info *fi)
 
UNIMPLEMENTED(int, read_buf, const char * c, struct fuse_bufvec **bufp, size_t size, off_t off, struct fuse_file_info *fi)
 
UNIMPLEMENTED(int, flock, const char * c, struct fuse_file_info *fi, int op)
 
UNIMPLEMENTED(int, fallocate, const char * c, int i, off_t o1, off_t o2, struct fuse_file_info *fi)
 
//UNIMPLEMENTED(ssize_t, copy_file_range, const char *path_in, struct fuse_file_info *fi_in, off_t offset_in, const char *path_out, struct fuse_file_info *fi_out, off_t offset_out, size_t size, int flags)

static struct fuse_operations mega_oper = {
	.getattr	= mega_getattr,
	.readlink	= mega_readlink,
    .mknod      = mega_mknod,
	.mkdir		= mega_mkdir,
	.unlink		= mega_unlink,
	.rmdir		= mega_rmdir,
	.symlink	= mega_symlink,
	.rename		= mega_rename,
	.link		= mega_link,
    .chmod      = mega_chmod,
    .chown      = mega_chown,
	.truncate	= mega_truncate,
//	.open		= mega_open,
	.read		= mega_read,
	.write		= mega_write,
    .statfs     = mega_statfs,
    .flush      = mega_flush,
	.release	= mega_release,
    .fsync      = mega_fsync,
    .setxattr   = mega_setxattr,
    .getxattr   = mega_getxattr,
    .listxattr  = mega_listxattr,
    .removexattr = mega_removexattr,
//    .opendir    = mega_opendir,
	.readdir	= mega_readdir,
    .releasedir = mega_releasedir,
    .fsyncdir   = mega_fsyncdir,
    .init       = mega_init,
    .destroy    = mega_destroy,
    .access     = mega_access,
    .create     = mega_create,
    .lock       = mega_lock,
    .utimens    = mega_utimens,
    .bmap       = mega_bmap,
    .ioctl      = mega_ioctl,
    .poll       = mega_poll,
    .write_buf  = mega_write_buf,
    .read_buf   = mega_read_buf,
    .flock      = mega_flock,
    .fallocate  = mega_fallocate,
};

// }}}
// {{{ main()

int fs_main(int ac, char* av[])
{
  GError *local_err = NULL;

  // tool_allow_unknown_options = TRUE;
  
  tool_init(&ac, &av, "mount_directory - mount files stored at mega.nz", entries,
		  TOOL_INIT_AUTH);

  if (ac < 2) {
    g_printerr("ERROR: You must specify a local mount directory\n");
    return 1;
  }

  s = tool_start_session(TOOL_SESSION_OPEN);
  if (!s)
    return 1;

  // pass mount options as arguments to fuse_main
  char** mountoptions = av;
  if (opt_mountoptions) {
    ac += 2;
    mountoptions = malloc(ac * sizeof(char*));
    for (int i = 0; i < ac - 2; i++)
      mountoptions[i] = av[i];
    mountoptions[ac - 2] = "-o";
    mountoptions[ac - 1] = opt_mountoptions;
  }

  int rs = fuse_main(ac, mountoptions, &mega_oper, NULL);

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

