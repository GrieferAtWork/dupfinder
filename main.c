/* Copyright (c) 2022 Griefer@Work                                            *
 *                                                                            *
 * This software is provided 'as-is', without any express or implied          *
 * warranty. In no event will the authors be held liable for any damages      *
 * arising from the use of this software.                                     *
 *                                                                            *
 * Permission is granted to anyone to use this software for any purpose,      *
 * including commercial applications, and to alter it and redistribute it     *
 * freely, subject to the following restrictions:                             *
 *                                                                            *
 * 1. The origin of this software must not be misrepresented; you must not    *
 *    claim that you wrote the original software. If you use this software    *
 *    in a product, an acknowledgement (see the following) in the product     *
 *    documentation is required:                                              *
 *    Portions Copyright (c) 2022 Griefer@Work                                *
 * 2. Altered source versions must be plainly marked as such, and must not be *
 *    misrepresented as being the original software.                          *
 * 3. This notice may not be removed or altered from any source distribution. *
 */
#ifndef GUARD_DUPFINDER_MAIN_C
#define GUARD_DUPFINDER_MAIN_C
#define _KOS_SOURCE 1
#define _AT_SOURCE 1
#define _USE_64BIT_TIME_T 1
#define _TIME_T_BITS 64
#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef TARGET_NT
#ifdef _WIN32
#define TARGET_NT
#endif /* _WIN32 */

#ifdef TARGET_NT
#include <Windows.h>
#include <direct.h>
#include <io.h>
#include <locale.h>
#include <wchar.h>

#undef SetCurrentDirectory
#define SetCurrentDirectory SetCurrentDirectoryW
#undef MoveFile
#define MoveFile MoveFileW
#undef CreateHardLink
#define CreateHardLink CreateHardLinkW
#undef DeleteFile
#define DeleteFile DeleteFileW
#define S_SetCurrentDirectory L"SetCurrentDirectory"
#define S_MoveFile            L"MoveFile"
#define S_CreateHardLink      L"CreateHardLink"
#define S_SetFileTime         L"SetFileTime"
#define S_DeleteFile          L"DeleteFile"

#define READFILE_READSIZE_T DWORD
#define open_rdonly(filename)                                                                \
	CreateFileW(filename, GENERIC_READ,                                                      \
	            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, \
	            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL)
#define open_wasok(fd) ((fd) != NULL && (fd) != INVALID_HANDLE_VALUE)
#define d_name         cFileName
#else /* TARGET_NT */

#ifdef NO_STRUCT_STAT_ST_TIM
#undef HAVE_STRUCT_STAT_ST_TIM
#elif 1
#define HAVE_STRUCT_STAT_ST_TIM
#endif
#ifdef NO_STRUCT_STAT_ST_TIMESPEC
#undef HAVE_STRUCT_STAT_ST_TIMESPEC
#elif 0
#define HAVE_STRUCT_STAT_ST_TIMESPEC
#endif
#ifdef NO_STRUCT_STAT_ST_TIMENSEC
#undef HAVE_STRUCT_STAT_ST_TIMENSEC
#elif 0
#define HAVE_STRUCT_STAT_ST_TIMENSEC
#endif
#ifdef NO_STRUCT_DIRENT_D_TYPE
#undef HAVE_STRUCT_DIRENT_D_TYPE
#elif 1
#define HAVE_STRUCT_DIRENT_D_TYPE
#endif

#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define BYTE                               unsigned char
#define ERROR_FILE_NOT_FOUND               ENOENT
#define GetLastError()                     errno
#define SetCurrentDirectory(x)             (chdir(x) == 0)
#define MoveFile(from, to)                 (rename(from, to) == 0)
#define CreateHardLink(to, from, _)        (link(from, to) == 0)
#define GetFileInformationByHandle(fd, st) (fstat(fd, st) == 0)
#define CloseHandle(fd)                    (close(fd) == 0)
#define DeleteFile(filename)               (unlink(filename) == 0)
#define S_SetCurrentDirectory              "chdir"
#define S_MoveFile                         "rename"
#define S_CreateHardLink                   "link"
#define S_SetFileTime                      "utimensat"
#define S_DeleteFile                       "unlink"
#define BY_HANDLE_FILE_INFORMATION         struct stat
#define ReadFile(fd, buf, bufsize, p_readsize, _) \
	((ssize_t)(*(p_readsize) = (size_t)read(fd, buf, bufsize)) != -1)
#define READFILE_READSIZE_T size_t

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif /* !O_NOFOLLOW */
#define open_rdonly(filename) open(filename, O_RDONLY | O_NOFOLLOW)
#define open_wasok(fd)        ((fd) != -1)
#endif /* !TARGET_NT */

#undef T
#undef TCHAR
#undef Tprintf
#undef fTprintf
#undef putTchar
#undef PRIsT
#undef Tmemcpy
#undef Tmemcmp
#undef Tstrlen
#undef Tstrcmp
#undef Tstrrchr
#undef Tmain
#undef SLASH
#undef PRIm
#undef _ARGm
#ifdef TARGET_NT
#define T(x)     L##x
#define TCHAR    WCHAR
#define Tprintf  wprintf
#define fTprintf fwprintf
#define putTchar putwchar
#define PRIsT    L"ls"
#define Tmemcpy  wmemcpy
#define Tmemcmp  wmemcmp
#define Tstrlen  wcslen
#define Tstrcmp  wcscmp
#define Tstrrchr wcsrchr
#define Tmain    wmain
#define SLASH    L'\\'
#define PRIm     L"ls (%lu)"
#define _ARGm    , nt_strerror(GetLastError()), (unsigned long)GetLastError()
#else /* TARGET_NT */
#define T(x)     x
#define TCHAR    char
#define Tprintf  printf
#define fTprintf fprintf
#define putTchar putchar
#define PRIsT    "s"
#define Tmemcpy  memcpy
#define Tmemcmp  memcmp
#define Tstrlen  strlen
#define Tstrcmp  strcmp
#define Tstrrchr strrchr
#define Tmain    main
#define SLASH    '/'
#define PRIm     "s (%d)"
#define _ARGm    , strerror(errno), errno
#endif /* !TARGET_NT */

#ifdef TARGET_NT
#define STAT_TIME_T FILETIME
#elif (defined(HAVE_STRUCT_STAT_ST_TIMENSEC) || \
       defined(HAVE_STRUCT_STAT_ST_TIM) ||      \
       defined(HAVE_STRUCT_STAT_ST_TIMESPEC))
#define STAT_TIME_T_IS_TIMESPEC
#define STAT_TIME_T struct timespec
#else /* ... */
#define STAT_TIME_T time_t
#endif /* !... */

#ifdef TARGET_NT
#define STAT_TIME_CMP(lhs, op, rhs) (CompareFileTime(lhs, rhs) op 0)
#elif defined(STAT_TIME_T_IS_TIMESPEC)
#define STAT_TIME_CMP(lhs, op, rhs) ((lhs)->tv_sec op (rhs)->tv_sec || ((lhs)->tv_sec == (rhs)->tv_sec && (lhs)->tv_nsec op (rhs)->tv_nsec))
#else /* ... */
#define STAT_TIME_CMP(lhs, op, rhs) (*(lhs) op *(rhs))
#endif /* !... */



#ifndef TARGET_NT
#define HANDLE           int
#define WIN32_FIND_DATAW struct dirent
#endif /* !TARGET_NT */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef __USE_KOS
#define memmoveup   memmove
#define memmovedown memmove
#endif /* !__USE_KOS */

#ifdef TARGET_NT
static WCHAR const *nt_strerror(unsigned long err) {
	static WCHAR *p_oldreturn = NULL;
	WCHAR *result;
	if (p_oldreturn)
		LocalFree(p_oldreturn);
	if (!FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
	                    FORMAT_MESSAGE_FROM_SYSTEM,
	                    NULL, err,
	                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	                    (LPWSTR)&result, 1, NULL))
		return L"unknown error";
	p_oldreturn = result;
	return result;
}
#endif /* TARGET_NT */

static void *xmalloc(size_t num_bytes) {
	void *result = malloc(num_bytes);
	if (!result) {
		if (!num_bytes)
			num_bytes = 1;
		result = malloc(num_bytes);
		if (!result) {
			fTprintf(stderr, T("dupfinder: error: failed to allocate %lu bytes\n"),
			         (unsigned long)num_bytes);
			exit(1);
		}
	}
	return result;
}

static void *xrealloc(void *ptr, size_t num_bytes) {
	void *result;
	if (!num_bytes)
		num_bytes = 1;
	result = realloc(ptr, num_bytes);
	if (!result) {
		fTprintf(stderr, T("dupfinder: error: failed to reallocate %p to %lu bytes\n"),
		         ptr, (unsigned long)num_bytes);
		exit(1);
	}
	return result;
}


#ifdef TARGET_NT
static void dont_update_atime(HANDLE hFile) {
	FILETIME ft;
	ft.dwHighDateTime = 0xffffffff;
	ft.dwLowDateTime = 0xffffffff;
	SetFileTime(hFile, NULL, &ft, NULL);
}
#else /* TARGET_NT */
#define dont_update_atime(hFile) (void)0
#endif /* !TARGET_NT */



/* Mask of attributes we care about. */
#ifdef TARGET_NT
#define INODE_ATTR_MASK \
	(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
#undef S_ISDIR
#undef S_ISLNK
#define S_ISDIR(x) ((x) & FILE_ATTRIBUTE_DIRECTORY)
#define S_ISLNK(x) ((x) & FILE_ATTRIBUTE_REPARSE_POINT)
#endif /* TARGET_NT */

struct fs_dirent;
struct fs_inode {
	union {
		uint64_t      i_ino;    /* [valid_if(!S_ISDIR(i_attr) && !S_ISLNK(i_attr))] INode number (nFileIndex) */
		struct fs_inode *_i_dnext; /* [0..1][valid_if(S_ISDIR(i_attr))] Next not-yet-loaded directory. */
	};
	uint64_t          i_size;   /* File size (in bytes) */
	uint32_t          i_attr;   /* File attributes (DWORD dwFileAttributes) */
	uint32_t          i_nlink;  /* [valid_if(!S_ISDIR(i_attr) && !S_ISLNK(i_attr))] File link count */
	STAT_TIME_T       i_ctime;  /* File creation time [NT] // last-changed [!NT] time */
	STAT_TIME_T       i_atime;  /* Last-accessed time */
	STAT_TIME_T       i_mtime;  /* Last-modified time */
	struct fs_dirent *i_dirent; /* [0..1] First directory entry. */
};

/* Compare file specs between `lhs' and `rhs' */
static int fs_inode_cmpspec(struct fs_inode const *lhs, struct fs_inode const *rhs) {
	if (lhs->i_size != rhs->i_size) {
		if (lhs->i_size < rhs->i_size)
			return -1;
		return 1;
	}
	if (lhs->i_attr < rhs->i_attr)
		return -1;
	if (lhs->i_attr > rhs->i_attr)
		return 1;
	return 0;
}


struct fs_dirent {
	struct fs_inode  *fd_file;   /* [1..1] Associated file */
	struct fs_dirent *fd_next;   /* [0..1] Next directory entry of `fd_file' */
	TCHAR             fd_name[]; /* NUL-terminated filename (relative to $PWD). */
};


struct fs_table {
	size_t             ft_byino_c;  /* Number of elements in `ft_byino_v' */
	size_t             ft_byino_a;  /* Allocated size of `ft_byino_v' */
	struct fs_inode  **ft_byino_v;  /* [1..1][ft_byino_c][owned] Table of files (sorted by `i_ino') */
	size_t             ft_byspec_c; /* Number of elements in `ft_byspec_v' */
	size_t             ft_byspec_a; /* Allocated size of `ft_byspec_v' */
	struct fs_inode  **ft_byspec_v; /* [1..1][ft_byino_c][owned] Table of files (sorted by specs: `i_size + i_attr') */
	size_t             ft_byname_c; /* Number of elements in `ft_byname_v' */
	size_t             ft_byname_a; /* Allocated size of `ft_byname_v' */
	struct fs_dirent **ft_byname_v; /* [1..1][ft_byino_c][owned] Table of files (sorted by name) */
};

static struct fs_table ftab = { 0, 0, NULL, 0, 0, NULL, 0, 0, NULL };

/* [0..1] Chain of directories that have yet to be loaded. */
static struct fs_inode *ftab_pending_dirs = NULL;

static struct fs_inode *ftab_findinode(uint64_t ino) {
	size_t lo, hi;
	lo = 0;
	hi = ftab.ft_byino_c;
	while (lo < hi) {
		size_t i = (lo + hi) / 2;
		struct fs_inode *result = ftab.ft_byino_v[i];
		if (ino < result->i_ino) {
			hi = i;
		} else if (ino > result->i_ino) {
			lo = i + 1;
		} else {
			/* Found it! */
			return result;
		}
	}
	return NULL;
}

/* Add `ino' to the by-ino table. */
static void ftab_add_byinode(struct fs_inode *__restrict ino) {
	size_t lo, hi;
	if (ftab.ft_byino_c >= ftab.ft_byino_a) {
		struct fs_inode **newtab;
		size_t newalloc = (ftab.ft_byino_a << 1) | 1;
		if (newalloc < 0x10)
			newalloc = 0x10;
		newtab = (struct fs_inode **)realloc(ftab.ft_byino_v, newalloc * sizeof(struct fs_inode *));
		if (!newtab) {
			newalloc = ftab.ft_byino_c + 1;
			newtab = (struct fs_inode **)xrealloc(ftab.ft_byino_v, newalloc * sizeof(struct fs_inode *));
		}
		ftab.ft_byino_a = newalloc;
		ftab.ft_byino_v = newtab;
	}
	lo = 0;
	hi = ftab.ft_byino_c;
	while (lo < hi) {
		size_t i = (lo + hi) / 2;
		struct fs_inode *other = ftab.ft_byino_v[i];
		if (ino->i_ino < other->i_ino) {
			hi = i;
		} else {
			assert(ino->i_ino > other->i_ino && "Inode already in use?");
			lo = i + 1;
		}
	}
	assert(lo == hi);
	memmoveup(&ftab.ft_byino_v[lo + 1],
	          &ftab.ft_byino_v[lo],
	          (ftab.ft_byino_c - lo) *
	          sizeof(struct fs_inode *));
	ftab.ft_byino_v[lo] = ino;
	++ftab.ft_byino_c;
}

/* Add `ino' to the by-spec table. */
static void ftab_add_byspec(struct fs_inode *__restrict ino) {
	size_t lo, hi;
	if (ftab.ft_byspec_c >= ftab.ft_byspec_a) {
		struct fs_inode **newtab;
		size_t newalloc = (ftab.ft_byspec_a << 1) | 1;
		if (newalloc < 0x10)
			newalloc = 0x10;
		newtab = (struct fs_inode **)realloc(ftab.ft_byspec_v, newalloc * sizeof(struct fs_inode *));
		if (!newtab) {
			newalloc = ftab.ft_byspec_c + 1;
			newtab = (struct fs_inode **)xrealloc(ftab.ft_byspec_v, newalloc * sizeof(struct fs_inode *));
		}
		ftab.ft_byspec_a = newalloc;
		ftab.ft_byspec_v = newtab;
	}
	lo = 0;
	hi = ftab.ft_byspec_c;
	while (lo < hi) {
		size_t i = (lo + hi) / 2;
		struct fs_inode *other = ftab.ft_byspec_v[i];
		int diff = fs_inode_cmpspec(ino, other);
		if (diff < 0) {
			hi = i;
		} else if (diff > 0) {
			lo = i + 1;
		} else {
			lo = hi = i;
			break;
		}
	}
	assert(lo == hi);
	memmoveup(&ftab.ft_byspec_v[lo + 1],
	          &ftab.ft_byspec_v[lo],
	          (ftab.ft_byspec_c - lo) *
	          sizeof(struct fs_inode *));
	ftab.ft_byspec_v[lo] = ino;
	++ftab.ft_byspec_c;
}

/* Add `ino' to the by-name table. */
static bool ftab_add_byname(struct fs_dirent *__restrict ent,
                            size_t lo, size_t hi,
                            size_t prefix_len) {
	if (ftab.ft_byname_c >= ftab.ft_byname_a) {
		struct fs_dirent **newtab;
		size_t newalloc = (ftab.ft_byname_a << 1) | 1;
		if (newalloc < 0x10)
			newalloc = 0x10;
		newtab = (struct fs_dirent **)realloc(ftab.ft_byname_v, newalloc * sizeof(struct fs_dirent *));
		if (!newtab) {
			newalloc = ftab.ft_byname_c + 1;
			newtab = (struct fs_dirent **)xrealloc(ftab.ft_byname_v, newalloc * sizeof(struct fs_dirent *));
		}
		ftab.ft_byname_a = newalloc;
		ftab.ft_byname_v = newtab;
	}
	while (lo < hi) {
		size_t i = (lo + hi) / 2;
		struct fs_dirent *other = ftab.ft_byname_v[i];
		int diff;
		diff = Tstrcmp(ent->fd_name + prefix_len,
		               other->fd_name + prefix_len);
		if (diff < 0) {
			hi = i;
		} else if (diff > 0) {
			lo = i + 1;
		} else {
			/*lo = hi = i;*/
			return false;
		}
	}
	assert(lo == hi);
	memmoveup(&ftab.ft_byname_v[lo + 1],
	          &ftab.ft_byname_v[lo],
	          (ftab.ft_byname_c - lo) *
	          sizeof(struct fs_dirent *));
	ftab.ft_byname_v[lo] = ent;
	++ftab.ft_byname_c;
	return true;
}

static struct fs_inode *
ftab_getinode_fromfind(struct fs_dirent *__restrict dent,
                       WIN32_FIND_DATAW *__restrict fData) {
#ifdef TARGET_NT
	HANDLE hFile;
#endif /* TARGET_NT */
	struct fs_inode *result;
	BY_HANDLE_FILE_INFORMATION fInfo;
	bool hasIno;
#undef LOCAL_HAVE_DIR_AND_LNK_HANDLING
#if defined(TARGET_NT) || defined(HAVE_STRUCT_DIRENT_D_TYPE)
#define LOCAL_HAVE_DIR_AND_LNK_HANDLING
#ifdef TARGET_NT
	if (fData->dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
#else /* TARGET_NT */
	if (fData->d_type == DT_DIR || fData->d_type == DT_LNK)
#endif /* !TARGET_NT */
	{
		/* Special case: directory / symlink */
		result = (struct fs_inode *)xmalloc(sizeof(struct fs_inode));
		result->i_ino   = (uint64_t)-1;
		result->i_nlink = 1;
#ifdef TARGET_NT
		result->i_size  = ((uint64_t)fData->nFileSizeHigh << 32) | ((uint64_t)fData->nFileSizeLow);
		result->i_attr  = fData->dwFileAttributes & INODE_ATTR_MASK;
		result->i_ctime = fData->ftCreationTime;
		result->i_atime = fData->ftLastAccessTime;
		result->i_mtime = fData->ftLastWriteTime;
#else /* TARGET_NT */
		result->i_size = (uint64_t)-1;
		result->i_attr = DTTOIF(fData->d_type);
		memset(&result->i_ctime, 0, sizeof(result->i_ctime));
		memset(&result->i_atime, 0, sizeof(result->i_atime));
		memset(&result->i_mtime, 0, sizeof(result->i_mtime));
#endif /* !TARGET_NT */
		return result;
	}
#endif /* !... */

#ifdef TARGET_NT
	hFile = open_rdonly(dent->fd_name);
	if (!open_wasok(hFile)) {
		fTprintf(stderr, T("dupfinder: warn: failed to open file '%") PRIsT T("': %") PRIm T("\n"),
		         dent->fd_name _ARGm);
		return NULL;
	}
	dont_update_atime(hFile);
	hasIno = GetFileInformationByHandle(hFile, &fInfo);
#else /* TARGET_NT */
	hasIno = lstat(dent->fd_name, &fInfo) == 0;
#endif /* !TARGET_NT */
	if (!hasIno) {
		fTprintf(stderr, T("dupfinder: warn: failed to stat '%") PRIsT T("': %") PRIm T("\n"),
		         dent->fd_name _ARGm);
#ifdef TARGET_NT
		(void)CloseHandle(hFile);
		fInfo.dwFileAttributes     = fData->dwFileAttributes;
		fInfo.ftCreationTime       = fData->ftCreationTime;
		fInfo.ftLastAccessTime     = fData->ftLastAccessTime;
		fInfo.ftLastWriteTime      = fData->ftLastWriteTime;
		fInfo.dwVolumeSerialNumber = (DWORD)-1;
		fInfo.nFileSizeHigh        = fData->nFileSizeHigh;
		fInfo.nFileSizeLow         = fData->nFileSizeLow;
		fInfo.nNumberOfLinks       = 1;
		fInfo.nFileIndexHigh       = (DWORD)-1;
		fInfo.nFileIndexLow        = (DWORD)-1;
#else /* TARGET_NT */
		memset(&fInfo, 0, sizeof(fInfo));
		fInfo.st_mode  = DTTOIF(fData->d_type);
		fInfo.st_ino   = fData->d_ino;
		fInfo.st_nlink = 1;
#endif /* !TARGET_NT */
	} else {
		uint64_t ino;
#ifdef TARGET_NT
		(void)CloseHandle(hFile);
		ino = ((uint64_t)fInfo.nFileIndexHigh << 32) |
		      ((uint64_t)fInfo.nFileIndexLow);
#else /* TARGET_NT */
		ino = (uint64_t)fInfo.st_ino;
#endif /* !TARGET_NT */

		/* Check if this INode is already known. */
		result = ftab_findinode(ino);
		if (result)
			return result;
	}

	/* Create a new INode */
	result = (struct fs_inode *)xmalloc(sizeof(struct fs_inode));
#ifdef TARGET_NT
	result->i_ino = ((uint64_t)fInfo.nFileIndexHigh << 32) |
	                ((uint64_t)fInfo.nFileIndexLow);
	result->i_size = ((uint64_t)fInfo.nFileSizeHigh << 32) |
	                 ((uint64_t)fInfo.nFileSizeLow);
	result->i_attr  = fInfo.dwFileAttributes & INODE_ATTR_MASK;
	result->i_nlink = fInfo.nNumberOfLinks;
	result->i_ctime = fInfo.ftCreationTime;
	result->i_atime = fInfo.ftLastAccessTime;
	result->i_mtime = fInfo.ftLastWriteTime;
#else /* TARGET_NT */
	result->i_ino   = (uint64_t)fInfo.st_ino;
	result->i_size  = (uint64_t)fInfo.st_size;
	result->i_attr  = fInfo.st_mode;
	result->i_nlink = fInfo.st_nlink;
#ifdef HAVE_STRUCT_STAT_ST_TIMENSEC
	result->i_ctime.tv_sec  = fInfo.st_ctime;
	result->i_atime.tv_sec  = fInfo.st_atime;
	result->i_mtime.tv_sec  = fInfo.st_mtime;
	result->i_ctime.tv_nsec = fInfo.st_ctimensec;
	result->i_atime.tv_nsec = fInfo.st_atimensec;
	result->i_mtime.tv_nsec = fInfo.st_mtimensec;
#elif defined(HAVE_STRUCT_STAT_ST_TIM)
	result->i_ctime.tv_sec  = fInfo.st_ctim.tv_sec;
	result->i_ctime.tv_nsec = fInfo.st_ctim.tv_nsec;
	result->i_atime.tv_sec  = fInfo.st_atim.tv_sec;
	result->i_atime.tv_nsec = fInfo.st_atim.tv_nsec;
	result->i_mtime.tv_sec  = fInfo.st_mtim.tv_sec;
	result->i_mtime.tv_nsec = fInfo.st_mtim.tv_nsec;
#elif defined(HAVE_STRUCT_STAT_ST_TIMESPEC)
	result->i_ctime.tv_sec  = fInfo.st_ctimespec.tv_sec;
	result->i_ctime.tv_nsec = fInfo.st_ctimespec.tv_nsec;
	result->i_atime.tv_sec  = fInfo.st_atimespec.tv_sec;
	result->i_atime.tv_nsec = fInfo.st_atimespec.tv_nsec;
	result->i_mtime.tv_sec  = fInfo.st_mtimespec.tv_sec;
	result->i_mtime.tv_nsec = fInfo.st_mtimespec.tv_nsec;
#else /* ... */
	result->i_ctime = fInfo.st_ctime;
	result->i_atime = fInfo.st_atime;
	result->i_mtime = fInfo.st_mtime;
#endif /* !... */
#endif /* !TARGET_NT */
	result->i_dirent = NULL;
	if (!S_ISDIR(result->i_attr) && !S_ISLNK(result->i_attr)) {
		if (hasIno)
			ftab_add_byinode(result);
		ftab_add_byspec(result);
	}
	return result;
}


static void
ftab_byname_getdirbounds(TCHAR const *relpath, size_t relpath_len,
                         size_t *__restrict p_start,
                         size_t *__restrict p_end) {
	size_t lo, hi;
	lo = 0;
	hi = ftab.ft_byname_c;
	while (lo < hi) {
		size_t i = (lo + hi) / 2;
		struct fs_dirent *ent = ftab.ft_byname_v[i];
		int diff = Tmemcmp(relpath, ent->fd_name, relpath_len);
		if (diff < 0) {
			hi = i;
		} else if (diff > 0) {
			lo = i + 1;
		} else {
			/* Go backwards/forwards until we find the last symbol that matches our starts-with pattern. */
			lo = i;
			while (lo > 0 && Tmemcmp(relpath, ftab.ft_byname_v[lo - 1]->fd_name, relpath_len) == 0)
				--lo;
			hi = i;
			while (hi < ftab.ft_byname_c - 1 &&
			       Tmemcmp(relpath, ftab.ft_byname_v[hi + 1]->fd_name, relpath_len) == 0)
				++hi;
			break;
		}
	}
	assert(lo <= hi);
	*p_start = lo;
	*p_end   = hi;
}


static void scan_directory(TCHAR const *relpath) {
#ifdef TARGET_NT
	WIN32_FIND_DATAW fData;
	HANDLE hFind;
#define fData_ptr (&fData)
	TCHAR *fullpath;
#else /* TARGET_NT */
	struct dirent *fData_ptr;
	DIR *hFind;
#endif /* !TARGET_NT */
	TCHAR *ptr;
	size_t ftab_byname_start, ftab_byname_end;
	size_t relpath_len = Tstrlen(relpath);
	assert(!relpath_len || relpath[relpath_len - 1] == SLASH);
	ftab_byname_getdirbounds(relpath, relpath_len, &ftab_byname_start, &ftab_byname_end);
#ifdef TARGET_NT
	fullpath = (TCHAR *)xmalloc((relpath_len + 2) * sizeof(TCHAR));
	ptr = (TCHAR *)Tmemcpy(fullpath, relpath, relpath_len);
	ptr += relpath_len;
	*ptr++ = T('*');
	*ptr++ = T('\0');
	Tprintf(T("dupfinder: info: scanning: '%") PRIsT T("'...\n"), fullpath);
	hFind = FindFirstFileExW(fullpath, FindExInfoBasic, &fData,
	                         FindExSearchNameMatch, NULL, 0);
	if (hFind == INVALID_HANDLE_VALUE) {
		if (GetLastError() != ERROR_NO_MORE_FILES)
			fTprintf(stderr, T("dupfinder: warn: failed to open directory '%") PRIsT T("': %") PRIm T("\n"),
			         fullpath _ARGm);
	} else
#else /* TARGET_NT */
	if (relpath_len == 0)
		relpath = ".";
	Tprintf(T("dupfinder: info: scanning: '%") PRIsT T("'...\n"), relpath);
	hFind = opendir(relpath);
	if (!hFind) {
		fTprintf(stderr, T("dupfinder: warn: failed to open directory '%") PRIsT T("': %") PRIm T("\n"),
		         relpath _ARGm);
	} else
#endif /* !TARGET_NT */
	{
#ifdef TARGET_NT
		for (;;)
#else /* TARGET_NT */
		while ((fData_ptr = readdir(hFind)) != NULL)
#endif /* !TARGET_NT */
		{
			size_t entlen = Tstrlen(fData_ptr->d_name);
			struct fs_dirent *dent;
			struct fs_inode *ino;
			if (entlen <= 2) {
				if (entlen == 0)
					goto nextfile; /* Shouldn't happen? */
				if (fData_ptr->d_name[0] != T('.'))
					goto do_handle_file;
				if (entlen == 1)
					goto nextfile; /* "." */
				if (fData_ptr->d_name[1] == T('.'))
					goto nextfile; /* ".." */
			}
do_handle_file:
			dent = (struct fs_dirent *)xmalloc(offsetof(struct fs_dirent, fd_name) +
			                                   (relpath_len + entlen + 2) * sizeof(TCHAR));
			ptr = (TCHAR *)Tmemcpy(dent->fd_name, relpath, relpath_len);
			ptr += relpath_len;
			ptr = (TCHAR *)Tmemcpy(ptr, fData_ptr->d_name, entlen);
			ptr += entlen;
			*ptr = T('\0');

			/* Load the Inode associated with the found entry. */
			ino = ftab_getinode_fromfind(dent, fData_ptr);
			if (!ino)
				goto nextfile;

			/* dirents of directories have a trailing '\\' */
			if (S_ISDIR(ino->i_attr)) {
				*ptr++ = SLASH;
				*ptr++ = T('\0');
			}

			/* Link the directory entry to the INode */
			dent->fd_file = ino;
			dent->fd_next = ino->i_dirent;
			ino->i_dirent = dent;

			/* Add the directory entry to the file table. */
			if (!ftab_add_byname(dent, ftab_byname_start, ftab_byname_end, relpath_len)) {
				fTprintf(stderr, T("dupfinder: warn: duplicate file '%") PRIsT T("'?\n"), dent->fd_name);
			} else {
				++ftab_byname_end;
			}

			if (S_ISDIR(ino->i_attr)) {
				/* Must recursively scan this directory in a later pass! */
				ino->_i_dnext = ftab_pending_dirs;
				ftab_pending_dirs = ino;
			}

nextfile:;
#ifdef TARGET_NT
			if (!FindNextFileW(hFind, &fData)) {
				if (GetLastError() != ERROR_NO_MORE_FILES) {
					fTprintf(stderr, T("dupfinder: warn: failed to enumerate directory '%") PRIsT T("': %") PRIm T("\n"),
					         fullpath _ARGm);
				}
				break;
			}
#endif /* TARGET_NT */
		}
#ifdef TARGET_NT
		FindClose(hFind);
#else /* TARGET_NT */
		closedir(hFind);
#endif /* !TARGET_NT */
	}
#ifdef TARGET_NT
	free(fullpath);
#endif /* TARGET_NT */
}


/* Print what is being done at every step. */
static bool verbose = true;

/* Don't actually do any modifying fs-operations */
static bool readonly = false;


/* Identical files are required to have identical timestamps
 * Note that for this purpose, we only require identical last-accessed! */
static bool require_identical_timestamps = false;

#define FCOMP_BUFFER_SIZE (64 * 1024)
static BYTE fcomp_buffer_lhs[FCOMP_BUFFER_SIZE];
static BYTE fcomp_buffer_rhs[FCOMP_BUFFER_SIZE];


static bool
inodes_samedata(struct fs_inode const *__restrict lhs,
                struct fs_inode const *__restrict rhs) {
	int result;
	HANDLE hLhs, hRhs;
	assert(lhs->i_attr == rhs->i_attr);
	assert(lhs->i_size == rhs->i_size);
	if (require_identical_timestamps) {
		if (memcmp(&lhs->i_mtime, &rhs->i_mtime, sizeof(lhs->i_mtime)) != 0)
			return false;
	}
	if (!lhs->i_dirent || !rhs->i_dirent)
		return false; /* Unable to compare :( (dirent fields can be NULL in case of duplicate-file errors) */
	if (S_ISDIR(lhs->i_attr) || S_ISLNK(lhs->i_attr))
		return false; /* Cannot compare these types of files */
	hLhs = open_rdonly(lhs->i_dirent->fd_name);
	if (!open_wasok(hLhs)) {
		fTprintf(stderr, T("dupfinder: warn: failed to open file for compare '%") PRIsT T("': %") PRIm T("\n"),
		         lhs->i_dirent->fd_name _ARGm);
		return false;
	}
	dont_update_atime(hLhs);
	hRhs = open_rdonly(rhs->i_dirent->fd_name);
	if (!open_wasok(hRhs)) {
		fTprintf(stderr, T("dupfinder: warn: failed to open file for compare '%") PRIsT T("': %") PRIm T("\n"),
		         rhs->i_dirent->fd_name _ARGm);
		(void)CloseHandle(hLhs);
		return false;
	}
	dont_update_atime(hRhs);
	result = true;

	/* Compare file data */
	for (;;) {
		READFILE_READSIZE_T dwLhsRead, dwRhsRead;
		if (!ReadFile(hLhs, fcomp_buffer_lhs, sizeof(fcomp_buffer_lhs), &dwLhsRead, NULL)) {
			fTprintf(stderr, T("dupfinder: warn: failed to read from '%") PRIsT T("': %") PRIm T("\n"),
			         lhs->i_dirent->fd_name _ARGm);
			dwLhsRead = 0;
		}
		if (!ReadFile(hRhs, fcomp_buffer_rhs, sizeof(fcomp_buffer_rhs), &dwRhsRead, NULL)) {
			fTprintf(stderr, T("dupfinder: warn: failed to read from '%") PRIsT T("': %") PRIm T("\n"),
			         rhs->i_dirent->fd_name _ARGm);
			dwRhsRead = 0;
		}
		if (dwLhsRead != dwRhsRead || memcmp(fcomp_buffer_lhs, fcomp_buffer_rhs, dwLhsRead) != 0) {
			/* File differ! */
			result = false;
			break;
		}
		if (dwLhsRead < sizeof(fcomp_buffer_lhs))
			break;
	}

	(void)CloseHandle(hRhs);
	(void)CloseHandle(hLhs);
	return result;
}


static void
hardlink_backup_filename(TCHAR *filename,
                         TCHAR **p_actual_filename,
                         TCHAR **p_backup_filename) {
	/* Backup files are named "${DIRNAME}/.dupfinder.${BASENAME}" */
	static TCHAR const backup_prefix[] = T(".dupfinder.");
#define BACKUP_PREFIX_LEN ((sizeof(backup_prefix) / sizeof(TCHAR)) - 1)
	TCHAR *basename = Tstrrchr(filename, SLASH);
	if (basename) {
		++basename;
	} else {
		basename = filename;
	}
	if (Tmemcmp(basename, backup_prefix, BACKUP_PREFIX_LEN) == 0) {
		/* Special case: The caller-given name is already the backup! */
		TCHAR *actual, *ptr;
		size_t temp, backup_len = Tstrlen(filename);
		actual = (TCHAR *)xmalloc((backup_len - BACKUP_PREFIX_LEN + 1) * sizeof(TCHAR));
		temp   = (size_t)(basename - filename);
		ptr = (TCHAR *)Tmemcpy(actual, filename, temp);
		ptr += temp;
		basename += BACKUP_PREFIX_LEN;
		Tmemcpy(ptr, basename, Tstrlen(basename) + 1);
		*p_actual_filename = actual;
		*p_backup_filename = filename;
	} else {
		/* Normal case: The caller-given name is the original */
		TCHAR *backup, *ptr;
		size_t temp, actual_len = Tstrlen(filename);
		backup = (TCHAR *)xmalloc((actual_len + BACKUP_PREFIX_LEN + 1) * sizeof(TCHAR));
		temp   = (size_t)(basename - filename);
		ptr = (TCHAR *)Tmemcpy(backup, filename, temp);
		ptr += temp;
		ptr = (TCHAR *)Tmemcpy(ptr, backup_prefix, BACKUP_PREFIX_LEN);
		ptr += BACKUP_PREFIX_LEN;
		Tmemcpy(ptr, basename, Tstrlen(basename) + 1);
		*p_actual_filename = filename;
		*p_backup_filename = backup;
	}
}


static bool verbose_MoveFile(TCHAR const *from, TCHAR const *to) {
	bool result;
	if (verbose)
		Tprintf(T("dupfinder: verbose: ") S_MoveFile T("(\"%") PRIsT T("\", \"%") PRIsT T("\")\n"), from, to);
	if (readonly)
		return true;
	result = MoveFile(from, to);
	if (!result) {
		fTprintf(stderr, T("dupfinder: error: failed to rename '%") PRIsT T("' -> '%") PRIsT T("': %") PRIm T("\n"),
		         from, to _ARGm);
	}
	return result;
}


static void hardlink_group(struct fs_inode **files_v, size_t files_c) {
	size_t i;
	STAT_TIME_T ftFinalATime, ftFinalMTime;
#ifdef TARGET_NT
	STAT_TIME_T ftFinalCTime;
#endif /* TARGET_NT */
	TCHAR *sFirstFile;
	assert(files_c >= 2);

	/* Figure out what we want the remaining hardlink's timestamps to be. */
	ftFinalATime = files_v[0]->i_atime;
	ftFinalMTime = files_v[0]->i_mtime;
#ifdef TARGET_NT
	ftFinalCTime = files_v[0]->i_ctime;
#endif /* TARGET_NT */
	for (i = 1; i < files_c; ++i) {
		struct fs_inode *other = files_v[i];
		if (STAT_TIME_CMP(&ftFinalATime, <, &other->i_atime))
			ftFinalATime = other->i_atime; /* Use the most-recent access */
#ifdef TARGET_NT
		if (STAT_TIME_CMP(&ftFinalCTime, >, &other->i_ctime))
			ftFinalCTime = other->i_ctime; /* Use the oldest creation-date */
#endif /* TARGET_NT */
		if (STAT_TIME_CMP(&ftFinalMTime, >, &other->i_mtime))
			ftFinalMTime = other->i_mtime; /* Use the oldest last-modified-date */
	}

	/* Fix filename of a backup from a previous iteration. */
	{
		TCHAR *backup;
		hardlink_backup_filename(files_v[0]->i_dirent->fd_name,
		                         &sFirstFile, &backup);
		if (sFirstFile != files_v[0]->i_dirent->fd_name) {
			assert(backup == files_v[0]->i_dirent->fd_name);
			if (!verbose_MoveFile(backup, sFirstFile))
				return;
		}
		if (backup != files_v[0]->i_dirent->fd_name)
			free(backup);
	}

	/* Set our intended file times for the first file of the group. */
	if (memcmp(&ftFinalATime, &files_v[0]->i_atime, sizeof(ftFinalATime)) != 0 ||
	    memcmp(&ftFinalMTime, &files_v[0]->i_mtime, sizeof(ftFinalMTime)) != 0
#ifdef TARGET_NT
	    ||
	    memcmp(&ftFinalCTime, &files_v[0]->i_ctime, sizeof(ftFinalCTime)) != 0
#endif /* TARGET_NT */
		) {
		if (verbose)
			Tprintf(T("dupfinder: verbose: ") S_SetFileTime T("(\"%") PRIsT T("\", ...)\n"), sFirstFile);
		if (!readonly) {
#ifdef TARGET_NT
			HANDLE hFirst;
			hFirst = CreateFileW(sFirstFile, FILE_WRITE_ATTRIBUTES,
			                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
			                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
			if (hFirst == NULL || hFirst == INVALID_HANDLE_VALUE) {
				fTprintf(stderr, T("dupfinder: error: failed to open file '%") PRIsT T("': %") PRIm T("\n"),
				         sFirstFile _ARGm);
				return;
			}
			if (!SetFileTime(hFirst, &ftFinalCTime, &ftFinalATime, &ftFinalMTime)) {
				fTprintf(stderr, T("dupfinder: error: Failed to set timestamps of '%") PRIsT T("': %") PRIm T("\n"),
				         sFirstFile _ARGm);
				(void)CloseHandle(hFirst);
				return;
			}
			(void)CloseHandle(hFirst);
#else /* TARGET_NT */
			struct timespec ts[2];
#ifdef STAT_TIME_T_IS_TIMESPEC
			ts[0].tv_sec  = ftFinalATime.tv_sec;
			ts[0].tv_nsec = ftFinalATime.tv_nsec;
			ts[1].tv_sec  = ftFinalMTime.tv_sec;
			ts[1].tv_nsec = ftFinalMTime.tv_nsec;
#else /* STAT_TIME_T_IS_TIMESPEC */
			ts[0].tv_sec  = ftFinalATime;
			ts[0].tv_nsec = 0;
			ts[1].tv_sec  = ftFinalMTime;
			ts[1].tv_nsec = 0;
#endif /* !STAT_TIME_T_IS_TIMESPEC */
			if (utimensat(AT_FDCWD, sFirstFile, ts, 0) != 0) {
				fTprintf(stderr, T("dupfinder: error: Failed to set timestamps of '%") PRIsT T("': %") PRIm T("\n"),
				         sFirstFile _ARGm);
				return;
			}
#endif /* !TARGET_NT */
		}
	}

	/* Now go through all of the other files and replace them with hardlinks. */
	for (i = 1; i < files_c; ++i) {
		struct fs_inode *other = files_v[i];
		struct fs_dirent *other_dirent = other->i_dirent;
		assert(other_dirent);
		/* Must rename all directory entries under which the other file can be addressed. */
		for (;;) {
			TCHAR *sActual, *sBackup;
			hardlink_backup_filename(other_dirent->fd_name, &sActual, &sBackup);
			if (other_dirent->fd_name != sBackup) {
				/* Rename the file into its backup name */
				if (!verbose_MoveFile(other_dirent->fd_name, sBackup)) {
err_hardlink:
					if (sActual != other_dirent->fd_name)
						free(sActual);
					if (sBackup != other_dirent->fd_name)
						free(sBackup);
					return;
				}
			}
	
			/* Create the hardlink. */
			if (verbose) {
#ifdef TARGET_NT
				Tprintf(T("dupfinder: verbose: ") S_CreateHardLink T("(from: \"%") PRIsT T("\", to: \"%") PRIsT T("\")\n"),
				        sFirstFile, sActual);
#else /* TARGET_NT */
				Tprintf(T("dupfinder: verbose: ") S_CreateHardLink T("(to: \"%") PRIsT T("\", from: \"%") PRIsT T("\")\n"),
				        sActual, sFirstFile);
#endif /* !TARGET_NT */
			}
			if (!readonly) {
				if (!CreateHardLink(sActual, sFirstFile, NULL)) {
					fTprintf(stderr, T("dupfinder: error: failed to create hardlink '%") PRIsT T("' (to: '%") PRIsT T("'): %") PRIm T("\n"),
					         sActual, sFirstFile _ARGm);
					/* Try to restore our backup */
					verbose_MoveFile(sBackup, sActual);
					goto err_hardlink;
				}
			}
	
			/* And finally, delete the previously created backup */
			if (verbose)
				Tprintf(T("dupfinder: verbose: ") S_DeleteFile T("(\"%") PRIsT T("\")\n"), sBackup);
			if (!readonly) {
				if (!DeleteFile(sBackup) && GetLastError() != ERROR_FILE_NOT_FOUND) {
					fTprintf(stderr, T("dupfinder: error: failed to delete hardlink backup '%") PRIsT T("': %") PRIm T("\n"),
					         sBackup _ARGm);
					goto err_hardlink;
				}
			}
			if (sActual != other_dirent->fd_name)
				free(sActual);
			if (sBackup != other_dirent->fd_name)
				free(sBackup);
			other_dirent = other_dirent->fd_next;
			if (!other_dirent)
				break;
		}
	}

	if (sFirstFile != files_v[0]->i_dirent->fd_name)
		free(sFirstFile);
}




static void usage(void) {
	Tprintf(T("usage: dupfinder [OPTIONS...] [PATH=.]\n")
	        T("Options are:\n")
	        T("       --help             Show this help and exit\n")
	        T("  -t,  --with-mtime       Duplicate files need identical last-modified timestamps\n")
	        T("       --without-mtime    Duplicate files don't need identical last-modified timestamps (default)\n")
	        T("       --with-verbose     Print all modifying fs-operations (default)\n")
	        T("       --without-verbose  Silently perform modifying fs-operations\n")
	        T("  -ro, --readonly\n")
	        T("       --with-readonly    Skip modifying fs-operations\n")
	        T("  -rw, --without-readonly Perform modifying fs-operations (default)\n")
	        T("       --action=print     Print groups of duplicate files (default)\n")
	        T("  -P,  --physical\n")
	        T("       --action=hardlink  Merge duplicate files via hardlinks (oldest mtime is used for unify)\n")
	        T("Example:\n")
	        T("   dupfinder .            Print groups of identical files that can be merged via hardlinks\n")
	        T("   dupfinder -P .         Find identical files from current directory and merge via hardlinks\n")
	        T("   dupfinder -ro .        Print system calls needed to merge identical files from current directory\n")
	);
}

static void print_datasize(uint64_t num_bytes) {
	if (num_bytes >= ((uint64_t)1024 * 1024 * 1024)) {
		Tprintf(T("%llu.%.2uGiB"),
		        (unsigned long long)(num_bytes / ((uint64_t)1024 * 1024 * 1024)),
		        (unsigned int)((num_bytes / (((uint64_t)1024 * 1024 * 1024) / 100)) % 100));
	} else if (num_bytes >= ((uint64_t)1024 * 1024)) {
		Tprintf(T("%llu.%.2uMiB"),
		        (unsigned long long)(num_bytes / ((uint64_t)1024 * 1024)),
		        (unsigned int)((num_bytes / (((uint64_t)1024 * 1024) / 100)) % 100));
	} else if (num_bytes >= ((uint64_t)1024)) {
		Tprintf(T("%llu.%.2uKiB"),
		        (unsigned long long)(num_bytes / ((uint64_t)1024)),
		        (unsigned int)((num_bytes / (((uint64_t)1024) / 100)) % 100));
	} else {
		Tprintf(T("%lluB"), (unsigned long long)num_bytes);
	}
}

int Tmain(int argc, TCHAR *argv[]) {
#define DUP_ACTION_PRINT 0
#define DUP_ACTION_HLINK 1
	int dup_action = DUP_ACTION_PRINT;
	if (argc) {
		--argc;
		++argv;
	}
#ifdef TARGET_NT
	setlocale(LC_ALL, ".UTF8");
#endif /* TARGET_NT */
	while (argc && argv[0][0] == '-') {
		TCHAR const *arg = argv[0];
		++argv;
		--argc;
		if (Tstrcmp(arg, T("--with-mtime")) == 0 ||
		    Tstrcmp(arg, T("-t")) == 0) {
			require_identical_timestamps = true;
		} else if (Tstrcmp(arg, T("--without-mtime")) == 0) {
			require_identical_timestamps = false;
		} else if (Tstrcmp(arg, T("--with-verbose")) == 0) {
			verbose = true;
		} else if (Tstrcmp(arg, T("--without-verbose")) == 0) {
			verbose = false;
		} else if (Tstrcmp(arg, T("--with-readonly")) == 0 ||
		           Tstrcmp(arg, T("--readonly")) == 0 ||
		           Tstrcmp(arg, T("-ro")) == 0) {
			readonly = true;
		} else if (Tstrcmp(arg, T("--without-readonly")) == 0 ||
		           Tstrcmp(arg, T("-rw")) == 0) {
			readonly = false;
		} else if (Tstrcmp(arg, T("--action=print")) == 0) {
			dup_action = DUP_ACTION_PRINT;
		} else if (Tstrcmp(arg, T("-P")) == 0 ||
		           Tstrcmp(arg, T("--physical")) == 0 ||
		           Tstrcmp(arg, T("--action=hardlink")) == 0) {
			dup_action = DUP_ACTION_HLINK;
			/* TODO: --action=delete-old  (delete all but the oldest copy) */
			/* TODO: --action=delete-new  (delete all but the newest copy) */
			/* TODO: --action=commands    (print shell commands to do the linking) */
		} else if (Tstrcmp(arg, T("--help")) == 0) {
			usage();
			exit(0);
		} else {
			Tprintf(T("Unrecognized argument: '%") PRIsT T("'\n"), arg);
			usage();
			exit(1);
		}
	}
	if (argc > 1) {
		usage();
		exit(1);
	}
	if (argc) {
		if (!SetCurrentDirectory(argv[0])) {
			fTprintf(stderr, T("dupfinder: error: failed to chdir to '%") PRIsT T("': %") PRIm T("\n"),
			         argv[0] _ARGm);
			exit(1);
		}
	}

	/* Scan the initial (current) directory. */
	scan_directory(T(""));

	/* Scan all recursive directories. */
	while (ftab_pending_dirs != NULL) {
		struct fs_inode *dir;
		struct fs_dirent *dent;
		dir = ftab_pending_dirs;
		ftab_pending_dirs = dir->_i_dnext;
		dent = dir->i_dirent;
		assert(dent->fd_name[0] != T('\0'));
		assert(dent->fd_name[Tstrlen(dent->fd_name) - 1] == SLASH);
		scan_directory(dent->fd_name);
	}

	/* Find files with identical specs. */
	{
		uint64_t saved_disk_inode = 0;
		uint64_t saved_disk_space = 0;
		uint64_t total_disk_space = 0;
		size_t grp_start = 0;
		while (grp_start < ftab.ft_byspec_c) {
			struct fs_inode *lhs, *rhs;
			size_t num_identical = 1;
			size_t num_spec_ident = 1;
			size_t num_data_different = 0;
			lhs = ftab.ft_byspec_v[grp_start];

			/* Determine the # of files with identical specs. */
			while ((grp_start + num_spec_ident) < ftab.ft_byspec_c &&
			       fs_inode_cmpspec(lhs, ftab.ft_byspec_v[grp_start + num_spec_ident]) == 0)
				++num_spec_ident;

			/* Find all files from the same-spec group that are actually identical. */
			while ((num_identical + num_data_different) < num_spec_ident) {
				rhs = ftab.ft_byspec_v[grp_start + num_identical];
				if (inodes_samedata(lhs, rhs)) {
					++num_identical; /* Another identical file! */
				} else {
					struct fs_inode **p_rhs;
					size_t num_untested;
					/* Same specs, but different data --> move to the back of the same-spec-list */
					p_rhs = &ftab.ft_byspec_v[grp_start + num_identical];
					++num_data_different;
					num_untested = num_spec_ident - (num_identical + num_data_different);
					memmovedown(p_rhs, p_rhs + 1, num_untested * sizeof(struct fs_inode *));
					p_rhs[num_untested] = rhs;
				}
			}
			if (num_identical > 1) {
				size_t grp_end = grp_start + num_identical;
				if (dup_action == DUP_ACTION_PRINT) {
					size_t j;
					/* Handle identical groups of files. */
					Tprintf(T("group:["));
					for (j = grp_start; j < grp_end; ++j) {
						struct fs_dirent *iter;
						if (j > grp_start)
							putTchar(T(','));
						iter = ftab.ft_byspec_v[j]->i_dirent;
						assert(iter);
						for (;;) {
							Tprintf(T("\"%s\""), iter->fd_name);
							iter = iter->fd_next;
							if (!iter)
								break;
							putTchar(T(','));
						}
					}
					Tprintf(T("]\n"));
				} else if (dup_action == DUP_ACTION_HLINK) {
					hardlink_group(&ftab.ft_byspec_v[grp_start], num_identical);
				}
				saved_disk_space += lhs->i_size * (num_identical - 1);
				saved_disk_inode += num_identical - 1;
			}
			total_disk_space += lhs->i_size * (num_identical);
			grp_start += num_identical;
		}
		Tprintf(T("\n")
		        T("saved_disk_inode: %llu\n")
		        T("total_disk_inode: %llu\n")
		        T("saved_disk_space: "),
		        (unsigned long long)(saved_disk_inode),
		        (unsigned long long)(ftab.ft_byspec_c));
		print_datasize(saved_disk_space);
		Tprintf(T("\ntotal_disk_space: "));
		print_datasize(total_disk_space);
		putTchar(T('\n'));
	}

	return 0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* !GUARD_DUPFINDER_MAIN_C */
