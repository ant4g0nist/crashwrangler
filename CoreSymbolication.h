/*
 * CoreSymbolication.h — Private framework declarations
 *
 * These are well-known private APIs from the CoreSymbolication framework,
 * stable since OS X 10.6. We declare them here so CrashReport.m can
 * symbolicate addresses and enumerate loaded images without relying on
 * precompiled x86_64-only object files.
 */

#ifndef CORESYMBOLICATION_H
#define CORESYMBOLICATION_H

#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>

/* Opaque reference types — each is a struct containing a pointer + data. */
typedef struct {
    void *csCppData;
    void *csCppObj;
} CSTypeRef;

typedef CSTypeRef CSSymbolicatorRef;
typedef CSTypeRef CSSymbolRef;
typedef CSTypeRef CSSymbolOwnerRef;
typedef CSTypeRef CSSourceInfoRef;

/* Address range returned by CSSymbolGetRange / CSSymbolOwnerGetRange. */
typedef struct {
    unsigned long long location;
    unsigned long long length;
} CSRange;

/* UUID bytes (matches CFUUIDBytes layout). */
typedef struct {
    uint8_t byte0;
    uint8_t byte1;
    uint8_t byte2;
    uint8_t byte3;
    uint8_t byte4;
    uint8_t byte5;
    uint8_t byte6;
    uint8_t byte7;
    uint8_t byte8;
    uint8_t byte9;
    uint8_t byte10;
    uint8_t byte11;
    uint8_t byte12;
    uint8_t byte13;
    uint8_t byte14;
    uint8_t byte15;
} CSUUIDBytes;

/* Time constant used by several APIs. */
#define kCSNow 0x80000000u

/* Check whether a CSTypeRef is null. */
Boolean CSIsNull(CSTypeRef ref);

/* Release a symbolicator. */
void CSRelease(CSTypeRef ref);

/* Create a symbolicator for the given task. */
CSSymbolicatorRef CSSymbolicatorCreateWithTask(task_t task);

/* Resolve an address to a symbol. */
CSSymbolRef CSSymbolicatorGetSymbolWithAddressAtTime(
    CSSymbolicatorRef symbolicator,
    unsigned long long address,
    unsigned int time);

/* Symbol accessors. */
const char *CSSymbolGetName(CSSymbolRef symbol);
CSRange CSSymbolGetRange(CSSymbolRef symbol);
CSSymbolOwnerRef CSSymbolGetSymbolOwner(CSSymbolRef symbol);

/* Symbol owner (image) accessors. */
const char *CSSymbolOwnerGetName(CSSymbolOwnerRef owner);
const char *CSSymbolOwnerGetPath(CSSymbolOwnerRef owner);
unsigned long long CSSymbolOwnerGetBaseAddress(CSSymbolOwnerRef owner);
CSUUIDBytes CSSymbolOwnerGetCFUUIDBytes(CSSymbolOwnerRef owner);
long CSSymbolOwnerGetArchitecture(CSSymbolOwnerRef owner);

/* Enumerate all loaded images (symbol owners) in a symbolicator. */
typedef int (^CSSymbolOwnerIterator)(CSSymbolOwnerRef owner);
int CSSymbolicatorForeachSymbolOwnerAtTime(
    CSSymbolicatorRef symbolicator,
    unsigned int time,
    CSSymbolOwnerIterator iterator);

#endif /* CORESYMBOLICATION_H */
