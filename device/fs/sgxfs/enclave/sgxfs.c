// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include "linux-sgx/common/inc/sgx_tprotected_fs.h"
// clang-format on

/* ATTN: use elibc within SGX code. */
#include <errno.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>

#define FS_MAGIC 0x4a335f60
#define FILE_MAGIC 0x8d7e422f
#define DIR_MAGIC 0xc1bfdfa4

typedef struct _fs
{
    struct _oe_device base;
    uint32_t magic;
    uint32_t mount_flags;
} fs_t;

typedef struct _file
{
    struct _oe_device base;
    uint32_t magic;
    SGX_FILE* stream;
} file_t;

static fs_t* _cast_fs(const oe_device_t* device)
{
    fs_t* fs = (fs_t*)device;

    if (fs == NULL || fs->magic != FS_MAGIC)
        return NULL;

    return fs;
}

OE_INLINE bool _is_rdonly(const fs_t* fs)
{
    return fs->mount_flags & OE_MOUNT_RDONLY;
}

static char* _strrchr(const char* s, char c)
{
    char* ret = NULL;

    while (*s)
    {
        if (*s == c)
            ret = (char*)s;

        s++;
    }

    return ret;
}

static file_t* _cast_file(const oe_device_t* device)
{
    file_t* file = (file_t*)device;

    if (file == NULL || file->magic != FILE_MAGIC)
        return NULL;

    return file;
}

static int _split_path(
    const char* path,
    char dirname[OE_PATH_MAX],
    char basename[OE_PATH_MAX])
{
    int ret = -1;
    char* slash;

    /* Reject paths that are too long. */
    if (oe_strlen(path) >= OE_PATH_MAX)
        goto done;

    /* Reject paths that are not absolute */
    if (path[0] != '/')
        goto done;

    /* Handle root directory up front */
    if (oe_strcmp(path, "/") == 0)
    {
        oe_strlcpy(dirname, "/", OE_PATH_MAX);
        oe_strlcpy(basename, "/", OE_PATH_MAX);
        ret = 0;
        goto done;
    }

    /* This cannot fail (prechecked) */
    if (!(slash = _strrchr(path, '/')))
        goto done;

    /* If path ends with '/' character */
    if (!slash[1])
        goto done;

    /* Split the path */
    {
        if (slash == path)
        {
            oe_strlcpy(dirname, "/", OE_PATH_MAX);
        }
        else
        {
            int64_t index = slash - path;
            oe_strlcpy(dirname, path, OE_PATH_MAX);

            if (index < OE_PATH_MAX)
                dirname[index] = '\0';
            else
                dirname[OE_PATH_MAX - 1] = '\0';
        }

        oe_strlcpy(basename, slash + 1, OE_PATH_MAX);
    }

    ret = 0;

done:
    return ret;
}

static int _sgxfs_mount(
    oe_device_t* dev,
    const char* source,
    const char* target,
    uint32_t flags)
{
    int ret = -1;
    fs_t* fs = _cast_fs(dev);

    OE_UNUSED(source);
    OE_UNUSED(flags);

    if (!fs || !target)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    fs->mount_flags = flags;

    ret = 0;

done:
    return ret;
}

static int _sgxfs_unmount(oe_device_t* dev, const char* target)
{
    int ret = -1;
    fs_t* fs = _cast_fs(dev);

    if (!fs || !target)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    ret = 0;

done:
    return ret;
}

static int _sgxfs_clone(oe_device_t* device, oe_device_t** new_device)
{
    int ret = -1;
    fs_t* fs = _cast_fs(device);
    fs_t* new_fs = NULL;

    if (!fs || !new_device)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    if (!(new_fs = oe_calloc(1, sizeof(fs_t))))
    {
        oe_errno = OE_ENOMEM;
        goto done;
    }

    oe_memcpy(new_fs, fs, sizeof(fs_t));

    *new_device = &new_fs->base;
    ret = 0;

done:
    return ret;
}

static int _sgxfs_release(oe_device_t* device)
{
    int ret = -1;
    fs_t* fs = _cast_fs(device);

    if (!fs)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    oe_memset(fs, 0xDD, sizeof(fs_t));
    oe_free(fs);
    ret = 0;

done:
    return ret;
}

static int _sgxfs_shutdown(oe_device_t* device)
{
    int ret = -1;
    fs_t* fs = _cast_fs(device);

    if (!fs)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    ret = 0;

done:
    return ret;
}

static oe_device_t* _sgxfs_open(
    oe_device_t* fs_,
    const char* pathname,
    int flags,
    mode_t mode)
{
    oe_device_t* ret = NULL;
    fs_t* fs = _cast_fs(fs_);
    file_t* file = NULL;
    const char* fopen_mode = NULL;
    SGX_FILE* stream = NULL;

    oe_errno = 0;

    (void)mode;

    /* Check parameters */
    if (!fs || !pathname)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs) && oe_get_open_access_mode(flags) != OE_O_RDONLY)
    {
        oe_errno = OE_EPERM;
        goto done;
    }

    /* Nonblocking I/O is unsupported. */
    if ((flags & OE_O_NONBLOCK))
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    /* Convert the flags to an fopen-mode string. */
    switch ((flags & 0x00000003))
    {
        case OE_O_RDONLY:
        {
            fopen_mode = "r";
            break;
        }
        case OE_O_RDWR:
        {
            if (flags & OE_O_CREAT)
            {
                if (flags & OE_O_TRUNC)
                {
                    fopen_mode = "w+";
                }
                else if (flags & OE_O_APPEND)
                {
                    fopen_mode = "a+";
                }
                else
                {
                    oe_errno = OE_EINVAL;
                    goto done;
                }
            }
            else
            {
                fopen_mode = "r+";
            }
            break;
        }
        case OE_O_WRONLY:
        {
            if (flags & OE_O_CREAT)
            {
                if (flags & OE_O_TRUNC)
                {
                    fopen_mode = "w";
                }
                else if (flags & OE_O_APPEND)
                {
                    fopen_mode = "a";
                }
                else
                {
                    oe_errno = OE_EINVAL;
                    goto done;
                }
            }
            else
            {
                fopen_mode = "w";
            }
            break;
        }
        default:
        {
            oe_errno = OE_EINVAL;
            goto done;
        }
    }

    /* Open the protected file. */
    if (!(stream = sgx_fopen_auto_key(pathname, fopen_mode)))
    {
        oe_errno = errno;
        goto done;
    }

    /* Allocate and initialize file struct. */
    {
        if (!(file = oe_calloc(1, sizeof(file_t))))
        {
            oe_errno = OE_ENOMEM;
            goto done;
        }

        file->base.type = OE_DEVICETYPE_FILE;
        file->base.size = sizeof(file_t);
        file->magic = FILE_MAGIC;
        file->base.ops.fs = fs->base.ops.fs;
        file->stream = stream;
    }

    ret = &file->base;
    file = NULL;
    stream = NULL;

done:

    if (file)
    {
        oe_memset(file, 0xDD, sizeof(file_t));
        oe_free(file);
    }

    if (stream)
        sgx_fclose(stream);

    return ret;
}

static ssize_t _sgxfs_read(oe_device_t* file_, void* buf, size_t count)
{
    ssize_t ret = -1;
    size_t n;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file || (count && !buf))
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    if ((n = sgx_fread(buf, 1, count, file->stream)) == 0)
    {
        if (!sgx_feof(file->stream))
        {
            oe_errno = sgx_ferror(file->stream);
            goto done;
        }
    }

    ret = (ssize_t)n;

done:
    return ret;
}

static ssize_t _sgxfs_write(oe_device_t* file_, const void* buf, size_t count)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file || (count && !buf))
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    if (sgx_fwrite(buf, 1, count, file->stream) != count)
    {
        oe_errno = sgx_ferror(file->stream);
        goto done;
    }

    ret = (ssize_t)count;

done:
    return ret;
}

static off_t _sgxfs_lseek(oe_device_t* file_, off_t offset, int whence)
{
    off_t ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    if (sgx_fseek(file->stream, offset, whence) != 0)
    {
        oe_errno = errno;
        goto done;
    }

    ret = sgx_ftell(file->stream);

done:
    return ret;
}

static int _sgxfs_close(oe_device_t* file_)
{
    int ret = -1;
    file_t* file = _cast_file(file_);

    oe_errno = 0;

    if (!file)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    if (sgx_fclose(file->stream) != 0)
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    oe_memset(file, 0xDD, sizeof(file_t));
    oe_free(file);

    ret = 0;

done:
    return ret;
}

static int _sgxfs_ioctl(oe_device_t* file, unsigned long request, oe_va_list ap)
{
    /* Unsupported */
    oe_errno = OE_ENOTTY;
    (void)file;
    (void)request;
    (void)ap;
    return -1;
}

static oe_device_t* _sgxfs_opendir(oe_device_t* fs_, const char* name)
{
    oe_device_t* hostfs = oe_fs_get_hostfs();
    oe_device_t* dir = NULL;

    OE_UNUSED(fs_);

    if (!hostfs)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    dir = (*hostfs->ops.fs->opendir)(hostfs, name);

done:
    return dir;
}

static struct oe_dirent* _sgxfs_readdir(oe_device_t* dir)
{
    struct oe_dirent* ret = NULL;

    if (!dir)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    ret = (*dir->ops.fs->readdir)(dir);

done:
    return ret;
}

static int _sgxfs_closedir(oe_device_t* dir)
{
    int ret = -1;

    if (!dir)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    ret = (*dir->ops.fs->closedir)(dir);

done:
    return ret;
}

static int _sgxfs_stat(
    oe_device_t* fs_,
    const char* pathname,
    struct oe_stat* buf)
{
    int ret = -1;
    SGX_FILE* stream = NULL;
    oe_device_t* hostfs = oe_fs_get_hostfs();

    OE_UNUSED(fs_);

    if (!hostfs)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    if (hostfs->ops.fs->stat(hostfs, pathname, buf) != 0)
        goto done;

    /* Recalculate the size to omit the metadata headers. */
    if (!OE_S_ISDIR(buf->st_mode))
    {
        int64_t offset;

        if (!(stream = sgx_fopen_auto_key(pathname, "r")))
            goto done;

        if (sgx_fseek(stream, 0L, SEEK_END) != 0)
            goto done;

        if ((offset = sgx_ftell(stream)) < 0)
            goto done;

        buf->st_size = (off_t)offset;
    }

    ret = 0;

done:

    if (stream)
        sgx_fclose(stream);

    return ret;
}

static int _sgxfs_link(
    oe_device_t* fs_,
    const char* oldpath,
    const char* newpath)
{
    fs_t* fs = _cast_fs(fs_);
    int ret = -1;
    SGX_FILE* in = NULL;
    SGX_FILE* out = NULL;
    char buf[OE_BUFSIZ];
    size_t n;

    if (!fs || !oldpath || !newpath)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = OE_EPERM;
        goto done;
    }

    /* Open the input file. */
    if (!(in = sgx_fopen_auto_key(oldpath, "r")))
    {
        oe_errno = errno;
        goto done;
    }

    /* Open the output file. */
    if (!(out = sgx_fopen_auto_key(newpath, "w")))
    {
        oe_errno = errno;
        goto done;
    }

    /* Copy the file. */
    while ((n = sgx_fread(buf, 1, sizeof(buf), in)) > 0)
    {
        if (sgx_fwrite(buf, 1, n, out) != n)
        {
            oe_errno = sgx_ferror(out);
            goto done;
        }
    }

    ret = 0;

done:

    if (in)
        sgx_fclose(in);

    if (out)
        sgx_fclose(out);

    return ret;
}

static int _sgxfs_unlink(oe_device_t* fs_, const char* pathname)
{
    int ret = -1;
    oe_device_t* hostfs = oe_fs_get_hostfs();
    fs_t* fs = _cast_fs(fs_);

    if (!fs || !hostfs)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = OE_EPERM;
        goto done;
    }

    ret = hostfs->ops.fs->unlink(hostfs, pathname);

done:
    return ret;
}

static int _sgxfs_rename(
    oe_device_t* fs_,
    const char* oldpath,
    const char* newpath)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    SGX_FILE* in = NULL;
    SGX_FILE* out = NULL;
    char buf[OE_BUFSIZ];
    size_t n;
    oe_device_t* hostfs = oe_fs_get_hostfs();

    if (!fs || !hostfs || !oldpath || !newpath)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = OE_EPERM;
        goto done;
    }

    /* Open the input file. */
    if (!(in = sgx_fopen_auto_key(oldpath, "r")))
    {
        oe_errno = errno;
        goto done;
    }

    /* Open the output file. */
    if (!(out = sgx_fopen_auto_key(newpath, "w")))
    {
        oe_errno = errno;
        goto done;
    }

    /* Copy the file. */
    while ((n = sgx_fread(buf, 1, sizeof(buf), in)) > 0)
    {
        if (sgx_fwrite(buf, 1, n, out) != n)
        {
            oe_errno = sgx_ferror(out);
            goto done;
        }
    }

    /* Delete the original file. */
    if (hostfs->ops.fs->unlink(hostfs, oldpath) != 0)
    {
        goto done;
    }

    ret = 0;

done:

    if (in)
        sgx_fclose(in);

    if (out)
        sgx_fclose(out);

    return ret;
}

static int _sgxfs_truncate(oe_device_t* fs_, const char* path, off_t length)
{
    int ret = -1;
    fs_t* fs = _cast_fs(fs_);
    size_t remaining = (size_t)length;
    char dirname[OE_PAGE_SIZE];
    char basename[OE_PAGE_SIZE];
    char tmp_file[OE_PAGE_SIZE];
    SGX_FILE* in = NULL;
    SGX_FILE* out = NULL;
    size_t n;
    char buf[OE_BUFSIZ];
    bool remove_tmp_file = false;

    if (!fs || !path || length < 0)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = OE_EPERM;
        goto done;
    }

    /* Form the name of a temporary file. */
    {
        const size_t n = sizeof(tmp_file);

        if (_split_path(path, dirname, basename) != 0)
        {
            oe_errno = OE_EINVAL;
            goto done;
        }

        if (oe_strlcpy(tmp_file, dirname, n) >= n)
        {
            oe_errno = OE_EINVAL;
            goto done;
        }

        if (oe_strlcat(tmp_file, "/.", n) >= n)
        {
            oe_errno = OE_EINVAL;
            goto done;
        }

        if (oe_strlcat(tmp_file, basename, n) >= n)
        {
            oe_errno = OE_EINVAL;
            goto done;
        }

        if (oe_strlcat(tmp_file, ".sgxfs.truncate", n) >= n)
        {
            oe_errno = OE_EINVAL;
            goto done;
        }
    }

    /* Create a temporary copy of this file. */
    if (_sgxfs_link(fs_, path, tmp_file) != 0)
    {
        remove_tmp_file = true;
        goto done;
    }

    /* Open the input file. */
    if (!(in = sgx_fopen_auto_key(tmp_file, "r")))
    {
        oe_errno = errno;
        goto done;
    }

    /* Open and truncate the output file. */
    if (!(out = sgx_fopen_auto_key(path, "w")))
    {
        oe_errno = errno;
        goto done;
    }

    /* Copy length bytes from the input file to the output file. */
    while (remaining && (n = sgx_fread(buf, 1, sizeof(buf), in)) > 0)
    {
        if (n > remaining)
            n = remaining;

        if (sgx_fwrite(buf, 1, n, out) != n)
        {
            oe_errno = sgx_ferror(out);
            goto done;
        }

        remaining -= n;
    }

    ret = 0;

done:

    if (remove_tmp_file)
        _sgxfs_unlink(fs_, tmp_file);

    if (in)
        sgx_fclose(in);

    if (out)
        sgx_fclose(out);

    return ret;
}

static int _sgxfs_mkdir(oe_device_t* fs_, const char* pathname, mode_t mode)
{
    int ret = -1;
    oe_device_t* hostfs = oe_fs_get_hostfs();
    fs_t* fs = _cast_fs(fs_);

    if (!fs || !hostfs)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = OE_EPERM;
        goto done;
    }

    if (hostfs->ops.fs->mkdir(hostfs, pathname, mode) != 0)
        goto done;

    ret = 0;

done:
    return ret;
}

static int _sgxfs_rmdir(oe_device_t* fs_, const char* pathname)
{
    int ret = -1;
    oe_device_t* hostfs = oe_fs_get_hostfs();
    fs_t* fs = _cast_fs(fs_);

    if (!fs || !hostfs)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    /* Fail if attempting to write to a read-only file system. */
    if (_is_rdonly(fs))
    {
        oe_errno = OE_EPERM;
        goto done;
    }

    if (hostfs->ops.fs->rmdir(hostfs, pathname) != 0)
        goto done;

    ret = 0;

done:
    return ret;
}

static oe_fs_ops_t _ops = {
    .base.clone = _sgxfs_clone,
    .base.release = _sgxfs_release,
    .base.shutdown = _sgxfs_shutdown,
    .base.ioctl = _sgxfs_ioctl,
    .mount = _sgxfs_mount,
    .unmount = _sgxfs_unmount,
    .open = _sgxfs_open,
    .base.read = _sgxfs_read,
    .base.write = _sgxfs_write,
    .lseek = _sgxfs_lseek,
    .base.close = _sgxfs_close,
    .opendir = _sgxfs_opendir,
    .readdir = _sgxfs_readdir,
    .closedir = _sgxfs_closedir,
    .stat = _sgxfs_stat,
    .link = _sgxfs_link,
    .unlink = _sgxfs_unlink,
    .rename = _sgxfs_rename,
    .truncate = _sgxfs_truncate,
    .mkdir = _sgxfs_mkdir,
    .rmdir = _sgxfs_rmdir,
};

static fs_t _sgxfs = {
    .base.type = OE_DEVICETYPE_FILESYSTEM,
    .base.size = sizeof(fs_t),
    .base.ops.fs = &_ops,
    .magic = FS_MAGIC,
};

oe_device_t* oe_fs_get_sgxfs(void)
{
    return &_sgxfs.base;
}

int oe_register_sgxfs_device(void)
{
    int ret = -1;

    /* Allocate the device id. */
    if (oe_allocate_devid(OE_DEVID_SGXFS)  != OE_DEVID_SGXFS)
        goto done;

    /* Add the sgxfs device to the device table. */
    if (oe_set_devid_device(OE_DEVID_SGXFS, oe_fs_get_sgxfs()) != 0)
        goto done;

    /* Check that the above operation was successful. */
    if (oe_get_devid_device(OE_DEVID_SGXFS) != oe_fs_get_sgxfs())
        goto done;

    ret = 0;

done:
    return ret;
}
