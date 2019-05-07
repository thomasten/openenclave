// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_MALLOC_H
#define _OE_BITS_MALLOC_H
#if defined(_MSC_VER)
#define CDECL __cdecl
#else
#define CDECL
#endif

OE_INLINE
void* CDECL malloc(size_t size)
{
    return oe_malloc(size);
}

OE_INLINE
void CDECL free(void* ptr)
{
    oe_free(ptr);
}

OE_INLINE
void* CDECL calloc(size_t nmemb, size_t size)
{
    return oe_calloc(nmemb, size);
}

OE_INLINE
void* CDECL realloc(void* ptr, size_t size)
{
    return oe_realloc(ptr, size);
}

OE_INLINE
void* memalign(size_t alignment, size_t size)
{
    return oe_memalign(alignment, size);
}

OE_INLINE
int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return oe_posix_memalign(memptr, alignment, size);
}

#endif /* _OE_BITS_MALLOC_H */
